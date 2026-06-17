# murmur-relay — performance & volume results

Real numbers from the `loadtest` harness + the durability suite. Re-run anytime (below);
these are the evidence behind the PRD's targets (`PRD-durable-relay.md` §11).

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
