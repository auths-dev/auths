# murmur-relay — performance & volume results

Real numbers from the `loadtest` harness + the durability suite, on the **current** build
(binary wire + raw-ciphertext at-rest + bounded sorted-set dedup + the v2 sealed inner
frame). Re-run anytime (last section); these are the evidence behind the PRD's targets
(`PRD-durable-relay.md` §11).

Last re-run: all four scenarios + the volume/memory measurement below were re-measured after
the inner-frame v2 change. Throughput is run-to-run ±5%.

## Current results

### Throughput & latency (the `loadtest` example)

`roundtrip` = deposit **and** drain each op (Redis sees ~2× these ops/s); `deposit` = deposit
only (builds a backlog). 64 concurrent HTTP clients. **0 errors** in every run.

| Scenario | Backend | Payload | Throughput (deposits/s) | p50 | p99 | p999 | max |
|---|---|---|---:|---:|---:|---:|---:|
| A roundtrip | **Redis** | 256 B | **39,816** | 0.76 ms | 1.54 ms | 2.29 ms | 11.1 ms |
| B roundtrip | in-memory | 256 B | 57,561 | 0.53 ms | 1.25 ms | 2.23 ms | 30.6 ms |
| C roundtrip | **Redis** | 16 KiB | **10,781** | 2.93 ms | 4.21 ms | 13.4 ms | 22.4 ms |
| D deposit-only | **Redis** | 256 B | **77,242** | 0.77 ms | 1.60 ms | 2.13 ms | 11.1 ms |

**Reading it:**
- **Durability is cheap.** Redis round-trips at ~69% of the in-memory backend (39.8k vs
  57.6k/s) at p99 1.54 ms. Persisting every message costs ~30% of peak throughput and
  ~0.3 ms of p99 — a good trade for "a restart loses nothing."
- **Targets blown past.** PRD target was ≥5,000 round-trips/s at p99 < 15 ms; actual is
  **39.8k/s at p99 1.5 ms** (256 B), and even 16 KiB messages sustain **10.8k/s at p99
  4.2 ms** (~170 MB/s of ciphertext through Redis + HTTP).
- **Deposit-only is faster** (77k/s) — `RPUSH` + counter + one `ZADD`/`ZSCORE`, no drain.

### Volume / memory (scenario D backlog)

A deposit-only run built and held a large undrained backlog:

- **618,042** messages queued across **20,000** mailboxes (no drains).
- **29,229** Redis keys total — ~1.5 per mailbox (a queue list + a byte counter + one dedup
  sorted-set; many mailboxes share the small key set). **Not** per-message keys.
- **182.3 MiB** `used_memory` → **~309 B per queued 256 B message**.

That 309 B is a fixed **random 256 B** payload (the synthetic worst case for the overhead
*ratio*) — so ~256 B ciphertext + ~53 B of Redis structure (quicklist node + the amortized
dedup-zset entry + counter). A **real** message is smaller: its sealed ciphertext is ~150 B
for a short text (§"inner frame", measured in murmur-core), so it sits at ~150 + ~53 ≈
**~200 B at rest**.

**Global bound:** with `maxmemory`/`noeviction` set, a backlog that would exceed it makes
`RPUSH` return OOM and the relay answers `507` (fail-closed) — the deposit Lua mutates the
queue first so an OOM leaves no partial state.

## How we got here (the three optimizations)

Each row is a real before/after on the same harness + host.

### 1. JSON → binary (wire + at-rest encoding)

`ciphertext` used to serialize as a JSON number array (`[255,12,…]`, ~3–4 chars/byte); now a
compact binary frame on the wire and raw ciphertext at rest.

| Scenario | JSON (before) | Binary (after) | Δ |
|---|---|---|---|
| roundtrip 256 B — throughput | 34,356/s | 40,821/s | +19% |
| **roundtrip 16 KiB — throughput** | 5,287/s | 10,867/s | **≈2×** |
| **roundtrip 16 KiB — p99** | 7.01 ms | ~2–4 ms | **≈2–3× better** |
| bytes / queued 256 B message | 792 B | 462 B | −42% |

The dramatic win is **large payloads**: a 16 KiB ciphertext was ~64 KB of JSON number-array.

### 2. Per-message dedup keys → bounded per-mailbox sorted-set

The byte-replay dedup was one TTL'd Redis key per message (`mr:{mbx}:s:<sha256-hex>`,
~185 B/message of key + overhead); now **one bounded sorted-set per mailbox** (ZADD a raw
128-bit fingerprint scored by arrival, keep the newest N=128 via `ZREMRANGEBYRANK`). The
**authoritative** dedup moved app-side (by `message_id`); the relay window is a cheap
network-replay guard.

| | per-message keys | bounded sorted-set |
|---|---:|---:|
| bytes / queued 256 B msg | 462 B | **309 B** |
| Redis keys (≈614k backlog) | ~1.86 M | **~29 k** (≈64× fewer) |
| deposit throughput | 77,749/s | 77,242/s (unchanged) |

### 3. Slimmer sealed inner frame (v2) — smaller *real* messages

The synthetic 256 B payload above doesn't shrink with the envelope, but a real message's
**ciphertext** did: the sealed inner frame stopped re-stating per-conversation-constant data —
recipient AID not stored (reconstructed as the opener), sender AID stored as its 32-byte
digest (not `did:keri:<64-hex>`), default content_type/flags omitted, id shrunk to a variable
sequence (default 8 B).

| | inner frame v1 | inner frame v2 |
|---|---:|---:|
| ciphertext of a 12-byte message | ~282 B | **150 B** (−47%) |
| → at rest (~+53 B Redis) | ~335 B | **~200 B** |

(Measured by a murmur-core test that seals a real message and asserts the compact size.)

**Net for at-rest memory:** JSON 792 B/msg → 462 → **309 B/msg** for the synthetic 256 B
payload (−61%); a real short message is **~200 B at rest** (ciphertext ~150 B).

## Environment

- Host: Apple Silicon (dev laptop), local Redis **8.0.3** on loopback (`--maxmemory 512mb
  --maxmemory-policy noeviction`), relay release build, all on one machine.
- This is a **single relay process + single local Redis** — a floor, not a ceiling.
  Production scales out (stateless relay tier + managed Redis); loopback also understates
  latency a real network would add and overstates contention vs a dedicated Redis box.

## Correctness / reliability (the durability suite — all green)

`cargo test -p murmur-relay --test redis_durability` (6/6 passing on live Redis):

1. **`durability_survives_a_relay_restart`** — deposit 25 → **kill the relay process** →
   start a fresh relay on the same Redis → drain returns all 25 in order. *A restart loses
   nothing.*
2. `idempotent_replay_and_drain_once` — byte-identical re-deposit → `deduped_replay` (now via
   the per-mailbox sorted-set window); a replay after a drain is still dropped.
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

# 4. throughput + volume (A/C/D; drop the env var + use a 2nd port for the in-memory B)
target/release/examples/loadtest --url http://127.0.0.1:8788 \
  --concurrency 64 --seconds 12 --payload 256 --mode roundtrip          # A
target/release/examples/loadtest --url http://127.0.0.1:8788 \
  --concurrency 64 --seconds 8  --payload 16384 --mode roundtrip        # C
target/release/examples/loadtest --url http://127.0.0.1:8788 \
  --concurrency 64 --seconds 8  --payload 256 --mailboxes 20000 --mode deposit   # D
redis-cli -p 6390 info memory | grep used_memory_human
redis-cli -p 6390 dbsize

# 5. the real-message ciphertext size (not synthetic)
cargo test -p murmur-core a_short_real_message_seals_to_a_compact_ciphertext -- --nocapture
```
