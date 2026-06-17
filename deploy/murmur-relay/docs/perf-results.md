# murmur-relay — performance & volume results

Real numbers from the `loadtest` harness + the durability suite. Re-run anytime (below);
these are the evidence behind the PRD's targets (`PRD-durable-relay.md` §11).

## JSON → binary wire/at-rest (the encoding migration)

The envelope was JSON (`ciphertext` as a number array ≈ 3–4 chars/byte); it is now a compact
binary frame on the wire and raw ciphertext at rest. Same harness, same host, Redis backend:

| Scenario | JSON (before) | Binary (after) | Δ |
|---|---|---|---|
| roundtrip 256 B — throughput | 34,356/s | **40,821/s** | +19% |
| roundtrip 256 B — p99 | 1.70 ms | **1.48 ms** | −13% |
| **roundtrip 16 KiB — throughput** | 5,287/s | **10,867/s** | **≈2×** |
| **roundtrip 16 KiB — p99** | 7.01 ms | **2.00 ms** | **≈3.5× better** |
| deposit-volume 256 B — throughput | 71,377/s | **77,749/s** | +9% |
| **bytes / queued 256 B message** | **792 B** | **462 B** | **−42%** |

0 errors throughout. The dramatic win is **large payloads**: a 16 KiB ciphertext was ~64 KB
of JSON number-array, so binary roughly doubles 16 KiB throughput and cuts its p99 ~3.5×.

**Where the residual 462 B/msg went:** the 256 B ciphertext is now stored raw (was ~770 B of
JSON), so the per-message *queue element* shrank ~514 B. The remaining overhead was dominated
by the **per-message dedup key** (`mr:{mbx}:s:<sha256-hex>` — a ~110-char key + TTL + Redis
per-key overhead, ~185 B per *message*). That has now been fixed (next section). The inner
envelope is binary too, so *real* messages (whose 64-byte signature was a ~200-char JSON
array) also shrink.

## Dedup: per-message keys → bounded per-mailbox sorted-set

The byte-replay dedup was one TTL'd Redis key per message; it is now **one bounded sorted-set
per mailbox** (ZADD a raw 128-bit fingerprint scored by arrival, keep the newest N=128,
`ZREMRANGEBYRANK`). This restores the in-memory backend's bounded sliding window, and the
**authoritative** dedup moved app-side (by `message_id`) — the relay's window is just a cheap
network-replay guard. Same volume test (256 B, deposit-only, ~614k-message backlog):

| | per-message keys | bounded sorted-set |
|---|---:|---:|
| bytes / queued msg | 462 B | **309 B** |
| Redis keys | ~1.86 M | **29,100** (≈64× fewer) |
| deposit throughput | 77,749/s | 76,722/s (unchanged) |

**Net across both changes:** JSON 792 B/msg → binary 462 → **309 B/msg (−61%)**, now ~36 B
over the floor *for this synthetic 256 B ciphertext* (256 + minimal queue overhead). Durability
suite 6/6 still green with the sorted-set dedup (idempotent replay, drain-once, post-drain
replay all hold).

> The 256 B here is a fixed random payload — it does not shrink with the envelope. A **real**
> message's ciphertext got smaller too: the sealed *inner* frame was slimmed (recipient AID not
> stored — reconstructed as the opener; sender AID stored as its 32-byte digest, not the
> `did:keri:<64-hex>` string; default content_type/flags omitted; id shrunk to a variable
> sequence). Measured in murmur-core: a 12-byte message's ciphertext is **150 B** (was ~282 B,
> −47%), so it sits at ~150 + ~36 ≈ **~186 B at rest**. See
> `murmur/docs/messages/message_format.md` §4.

## Environment

- Host: Apple Silicon (dev laptop), local Redis **8.0.3** on loopback (`--maxmemory 512mb
  --maxmemory-policy noeviction`), relay release build, all on one machine.
- This is a **single relay process + single local Redis** — a floor, not a ceiling.
  Production scales out (stateless relay tier + managed Redis); loopback also understates
  latency a real network would add and overstates contention vs a dedicated Redis box.

## Throughput & latency (the `loadtest` example)

`roundtrip` = deposit **and** drain each op (so Redis sees ~2× these ops/s); `deposit` =
deposit only (builds a backlog). 64 concurrent HTTP clients unless noted. **0 errors** in
every run.

| Scenario | Backend | Payload | Throughput (deposits/s) | p50 | p99 | p999 | max |
|---|---|---|---:|---:|---:|---:|---:|
| A roundtrip | **Redis** | 256 B | **34,356** | 0.90 ms | 1.70 ms | 2.86 ms | 13.2 ms |
| B roundtrip | in-memory | 256 B | 53,172 | 0.57 ms | 1.44 ms | 3.00 ms | 11.8 ms |
| C roundtrip | **Redis** | 16 KiB | 5,287 | 2.99 ms | 7.01 ms | 13.6 ms | 30.6 ms |
| D deposit-only | **Redis** | 256 B | **71,377** | 0.85 ms | 1.62 ms | 2.31 ms | 6.2 ms |

**Reading it:**
- **Durability is cheap.** Redis round-trips at ~65% of the in-memory backend's
  throughput (34k vs 53k/s) at sub-2 ms p99. Persisting every message costs ~35% of peak
  throughput and ~0.3 ms of p99 — a good trade for "a restart loses nothing."
- **Targets blown past.** PRD target was ≥5,000 round-trips/s at p99 < 15 ms; actual is
  **34k/s at p99 1.7 ms** (256 B), and even 16 KiB messages sustain 5.3k/s at p99 7 ms
  (~170 MB/s of ciphertext through Redis + HTTP).
- **Deposit-only is faster** (71k/s) — pure `RPUSH`+counter+dedup, no drain `LRANGE`/`DEL`.

## Volume / memory (scenario D backlog)

A deposit-only run built and held a large undrained backlog:

- **571,127** messages queued across **20,000** mailboxes (no drains).
- **589,165** Redis keys (per active mailbox: a queue list + a byte counter; plus per-
  message dedup keys).
- **431.2 MiB** `used_memory` → **~792 B per queued 256 B message**.

**Memory note (a real optimization, not yet done):** ~792 B to hold a 256 B ciphertext is
~3×. The cause is the storage encoding: the `OuterEnvelope` is stored as **JSON**, and
`ciphertext` serializes as a JSON *number array* (`[255,12,...]` ≈ 3–4 chars/byte), so
256 B becomes ~770 B of JSON before Redis/list overhead. Storing the ciphertext **base64**
(~1.37×) or as a compact **binary** blob (bincode/raw) would cut backlog memory roughly
2–3×. The HTTP wire stays JSON; only the at-rest encoding changes. Tracked as a follow-up
(PRD §12). Until then, size Redis for ~800 B per expected undrained 256 B message (more for
larger payloads — dominated by the ciphertext itself at that point).

**Global bound:** with `maxmemory`/`noeviction` set, a backlog that would exceed it makes
`RPUSH` return OOM and the relay answers `507` (fail-closed) — verified by design; the
deposit Lua mutates the queue first so an OOM leaves no partial state.

## Correctness / reliability (the durability suite — all green)

`cargo test -p murmur-relay --test redis_durability` (6/6 passing on live Redis):

1. **`durability_survives_a_relay_restart`** — deposit 25 → **kill the relay process** →
   start a fresh relay on the same Redis → drain returns all 25 in order. *A restart loses
   nothing.*
2. `idempotent_replay_and_drain_once` — byte-identical re-deposit → `deduped_replay`; a
   replay after a drain is still dropped.
3. `quota_per_mailbox_message_cap` — over-cap deposit → `429 quota_exceeded`, records nothing.
4. `prekey_round_trip_and_404` — publish/fetch opaque bytes; unknown AID → 404.
5. `ttl_expires_an_undrained_message` — a 1 s TTL reclaims an undrained message.
6. `fails_fast_when_redis_is_unreachable` — a dead Redis is a startup error (crash-loop),
   not a relay serving 503s forever.

## How to re-run

```bash
# 1. a throwaway Redis
redis-server --port 6390 --save '' --appendonly no \
  --maxmemory 512mb --maxmemory-policy noeviction &

# 2. correctness + durability
MURMUR_RELAY_TEST_REDIS_URL=redis://127.0.0.1:6390 \
  cargo test -p murmur-relay --test redis_durability -- --test-threads=1 --nocapture

# 3. a relay against that Redis
cargo build --release -p murmur-relay --bin murmur-relay --example loadtest
MURMUR_RELAY_REDIS_URL=redis://127.0.0.1:6390 \
  target/release/murmur-relay serve-http 127.0.0.1:8788 &

# 4. throughput + volume
target/release/examples/loadtest --url http://127.0.0.1:8788 \
  --concurrency 64 --seconds 12 --payload 256 --mode roundtrip
target/release/examples/loadtest --url http://127.0.0.1:8788 \
  --concurrency 64 --seconds 8 --payload 256 --mailboxes 20000 --mode deposit
redis-cli -p 6390 info memory | grep used_memory_human
```
