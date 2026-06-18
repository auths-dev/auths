# PRD — Durable, scalable Murmur relay (Redis-backed backlog + endpoint delivery-acks)

> **Durable plan.** Self-contained so it survives a fresh session / context loss.
> Cold start: read §1 (Problem), §2 (Hybrid model), §3 (Architecture), §4 (Redis data
> model), then §10 (Implementation) and §11 (Test/perf plan). Ground truth is the test
> suite + the load harness, not prose.

- **Engine/relay source:** `crates/murmur-relay` (binary), `crates/murmur-core` (the
  in-memory `MailboxStore` + wire types it reuses).
- **Deploy kit:** `deploy/murmur-relay/` (Dockerfile, fly.toml, README runbook).
- **Status:** design + this PRD complete; implementation tracked in §10. The in-memory
  relay (today) is the dev/hermetic default and stays; Redis is the production backend.

---

## 1. Problem

The relay is the store-and-forward mailbox: a sender deposits a sealed envelope, an
offline recipient drains it later. **Today the backlog lives only in process RAM**
(`MailboxStore` behind a `Mutex`), so any relay restart — every `fly deploy`, host
migration, OOM, or crash — **silently loses every undelivered message.** The app's
outbox does *not* cover this: once the relay answers `queued`, the sender marks the
message sent and drops its copy. Result: *"I sent it, you never got it, nobody has it."*

That is fine for a same-room demo (the recipient drains within ~3 s) and unacceptable
for a real messenger where the recipient reads it tomorrow. **The backlog must be
durable and the delivery guarantee must survive infrastructure churn — at scale.**

## 2. The hybrid model (two layers of guarantee)

Reliability is split so neither layer has to be heroic:

1. **Durable relay (this PRD's primary build).** The relay persists its queues, dedup
   horizon, and prekey directory in **Redis** — a fast, shared, durable store. A relay
   process restart no longer loses the backlog; many stateless relay processes share one
   Redis, so the relay tier scales horizontally. Undelivered messages expire on a **TTL**
   (default 30 days) so the relay is a transient buffer, never a permanent archive.

2. **Endpoint delivery-acks (the complementary guarantee, §8).** The recipient returns a
   **sealed delivery-ack** when it drains+opens a message; the sender keeps its copy and
   re-sends until acked. This makes delivery *end-to-end* correct even if the relay (or
   Redis) genuinely loses something, and it keeps the relay honestly "best-effort
   durable" rather than a system of record. Acks ride the same envelopes — **no relay
   change** beyond durability is needed for them.

The relay stays **dumb and untrusted**: it persists *opaque ciphertext keyed by
AID-unlinkable mailbox ids* — it still cannot read a byte, and Redis at rest holds no
plaintext, no sender AID, no phone number.

## 3. Architecture

```
        ┌────────────┐   POST /deposit / GET /drain / prekey   ┌────────────┐
 iPhone │  Murmur    │ ───────────────────────────────────────▶│  relay     │  (stateless,
        │  app       │◀─────────────────────────────────────── │  tier      │   N machines)
        └────────────┘                                          └─────┬──────┘
            ▲  delivery-ack (sealed, rides /deposit)                  │ redis protocol
            └──────────────────────────────────────────────┐         ▼
                                                            │   ┌──────────┐
                                                            └───│  Redis   │  durable backlog,
                                                                │ (managed │  dedup, prekeys
                                                                │  + HA)   │  (opaque bytes only)
                                                                └──────────┘
```

- **Relay tier:** the same `murmur-relay serve-http` binary, now stateless. Any machine
  can serve any request because all state is in Redis. Scale = add machines behind Fly's
  proxy. Health = the machine + its Redis connection are up.
- **Redis:** one logical store (managed, replicated for HA — Upstash on Fly, or Fly's
  managed Redis). Holds queues, the dedup horizon, prekeys — all opaque.
- **Backend is pluggable:** `RelayStore::{Memory, Redis}`. No `MURMUR_RELAY_REDIS_URL`
  → in-memory (dev, the hermetic 13-leg self-test, the `NET-1` probe). URL set →
  Redis. This keeps the gate fast/hermetic and production durable from one binary.

## 4. Redis data model (Cluster-ready from day one)

All keys for a given mailbox share a **hash tag** `{<mbx>}` so a single multi-key Lua
script touches one Cluster slot — the relay can move to Redis Cluster (sharded by
mailbox) with no key-design change.

| Purpose | Key | Type | Notes |
|---|---|---|---|
| Mailbox queue | `mr:{<mbx>}:q` | LIST | JSON `OuterEnvelope` per element; FIFO (`RPUSH`/drain) |
| Per-mailbox bytes | `mr:{<mbx>}:b` | STRING (int) | running undrained-byte count, for the per-mailbox byte cap |
| Dedup horizon | `mr:{<mbx>}:s:<fp>` | STRING | `fp = hex(SHA256(ciphertext))`; `SET NX EX dedup_ttl`; presence = replay |
| Prekey bundle | `mr:{<aid>}:pk` | STRING | opaque bundle bytes; `SET EX prekey_ttl` |

**Atomicity via Lua** (Redis runs a script atomically, so concurrent deposits to the
same mailbox can't race the quota or double-count):

- **`DEPOSIT(mbx, payload, fp, size)`** — in order, fail-closed:
  1. `EXISTS mr:{<mbx>}:s:<fp>` → return `"deduped"` (a byte-identical replay; idempotent
     success to the client).
  2. Quota: `LLEN mr:{<mbx>}:q ≥ max_msgs` **or** `GET mr:{<mbx>}:b + size > max_bytes`
     → return `"quota"` (records nothing — a retry after space frees still works).
  3. `RPUSH` payload (first mutation — if Redis is at `maxmemory`/`noeviction` this errors
     here, before any counter/dedup write, so no partial state); `INCRBY mr:{<mbx>}:b
     size`; `PEXPIRE` the queue + byte keys (sliding mailbox TTL); `SET
     mr:{<mbx>}:s:<fp> 1 EX dedup_ttl`; return `"queued"`.
- **`DRAIN(mbx)`** — `LRANGE 0 -1`; if empty return `[]`; else `DEL` the queue + the byte
  key; return the items. (Dedup keys are **not** cleared — a replay after a drain is still
  dropped within the dedup horizon, matching the in-memory store's "delivery horizon
  outlives the queue".)

**Global memory bound = Redis `maxmemory` + `noeviction`** (set on the instance). This is
the true, drift-free global cap (an app-maintained global counter would drift when TTL
expires undrained mailboxes). The per-mailbox caps (exact, in Lua) stop any single
mailbox from dominating; Redis's own memory ceiling stops the whole store from growing
unbounded, returning OOM → the relay answers `507 Insufficient Storage` (fail-closed).

**TTL semantics:** the queue + byte keys get a **sliding** `PEXPIRE = msg_ttl` on every
deposit, so an *active* conversation's backlog never expires mid-flight, and a truly
abandoned mailbox is reclaimed `msg_ttl` after its last deposit. Dedup keys carry their
own `dedup_ttl`. Per-message TTL (a sorted-set + sweeper, so each message expires exactly
`msg_ttl` after *it* arrived) is a documented future refinement (§12).

## 5. Reliability

- **Fail-closed everywhere.** A Redis error (connection lost, OOM, timeout) maps to a
  `5xx` (`503` connectivity, `507` OOM) — **never** a fake `queued`. The sender's outbox
  keeps the message and retries. We never acknowledge what we didn't store.
- **Auto-reconnect.** The relay holds a `redis::aio::ConnectionManager` — a multiplexed
  connection that transparently reconnects with backoff; in-flight commands during a blip
  fail (→ fail-closed) and the next succeeds.
- **Idempotent deposit.** `DedupedReplay` is a **200 success** — a client retry after a
  lost response is safe. Combined with stable per-message ids at the app layer, delivery
  is at-least-once with endpoint dedup, never lost, never duplicated to the user.
- **Atomic operations.** All multi-step mailbox mutations are single Lua scripts → no
  torn state under concurrency or partial failure.
- **Health vs readiness.** `GET /` pings Redis (`PING`) when Redis-backed, so an unhealthy
  Redis marks the machine unhealthy (Fly stops routing / restarts). Cheap (one PING).
- **Startup fail-fast.** If `MURMUR_RELAY_REDIS_URL` is set but the first connection
  fails, the process exits non-zero so the platform restarts it rather than serving a
  silently-broken relay.
- **No data race on restart.** Because all state is in Redis, a rolling deploy (drain old
  machine, start new) preserves the backlog perfectly — proven by the durability test
  (§11): deposit → kill+restart the relay process → drain still returns the backlog.

## 6. Scalability

- **Stateless relay tier → horizontal scale.** `fly scale count N` (or autoscale) adds
  machines; all share Redis. Redis is single-threaded but each op here is O(1)/O(small),
  so one modest Redis serves very high deposit/drain rates (see §11 targets).
- **Cluster-ready keys.** Hash-tagged keys mean moving to **Redis Cluster** (shard by
  mailbox) needs no redesign when one Redis node is no longer enough.
- **HA.** Use a managed Redis with a replica (Upstash / Fly Redis) so a node failure fails
  over without losing the (replicated) backlog.
- **Connection efficiency.** One multiplexed `ConnectionManager` per relay process
  pipelines concurrent requests over a single socket — minimal connections to Redis even
  at high concurrency.
- **Right-sizing.** Backlog memory ≈ Σ undelivered ciphertext (+ ~small Redis overhead
  per key). 256 MiB of ciphertext ≈ a 512 MiB–1 GiB Redis. Scale Redis memory with
  expected offline-backlog, not with throughput.

## 7. Configuration (env; in-memory default preserved)

| Env var | Default | Meaning |
|---|---|---|
| `MURMUR_RELAY_REDIS_URL` | *(unset → in-memory)* | `redis://[:pass@]host:port[/db]` (or `rediss://` for TLS). Set → Redis backend. |
| `MURMUR_RELAY_MSG_TTL_SECS` | `2592000` (30 d) | sliding TTL on a mailbox's queue/bytes |
| `MURMUR_RELAY_DEDUP_TTL_SECS` | `86400` (1 d) | how long a replay is recognized after first sight |
| `MURMUR_RELAY_PREKEY_TTL_SECS` | `2592000` (30 d) | published-bundle TTL (republished on app launch) |
| `MURMUR_RELAY_MAX_MSGS_PER_MAILBOX` | `1024` | per-mailbox message cap (matches in-memory) |
| `MURMUR_RELAY_MAX_BYTES_PER_MAILBOX` | `16777216` (16 MiB) | per-mailbox byte cap |
| `MURMUR_RELAY_KEY_PREFIX` | `mr` | key namespace (test isolation / multi-tenant) |

Bind address stays a CLI arg (`serve-http 0.0.0.0:8080`) — the container sets it; Redis
config is env so it's a Fly secret. The global byte cap is **Redis `maxmemory`**, set on
the instance, not an app env.

## 8. Endpoint delivery-acks (the hybrid's second half)

*App-side (`murmur` repo, `MessagingService`); specified here because it completes the
guarantee. Not built by the relay work — the relay only durably forwards the ack envelope.*

- On successful `open`, the recipient seals a tiny **delivery-ack** control message
  (`{type:"ack", msg_id}`) and deposits it to the **sender's** drain mailbox.
- The sender keeps each sent message in a **durable outbox** (persisted, not the current
  in-memory one) marked `sent`; on receiving the matching ack it marks `delivered` and
  drops the retained copy.
- Unacked after a backoff → re-send (covers a relay/Redis loss, or a recipient who never
  drained). Re-sends are byte-identical → relay dedup drops accidental doubles; the app
  dedups received messages by `msg_id` (Epic I3 in the messaging PRD).
- Result: **the sender is the source of truth until delivery is confirmed.** Relay
  durability makes this rare; the ack makes it correct when it isn't.

## 9. Security & metadata posture

- **Content:** unchanged — sealed end-to-end; Redis stores only `OuterEnvelope`
  ciphertext. A dump of Redis reveals no plaintext, no AID, no number.
- **Mailbox ids** are a PRF of the pairwise session secret (already implemented), so the
  persisted keys are **unlinkable to identities** — a Redis dump is opaque bytes keyed by
  opaque handles.
- **Retention** is bounded by the TTL (default 30 d) — the relay is a buffer, not an
  archive; this caps the seizure/retention surface.
- **In transit to Redis:** use `rediss://` (TLS) + Redis `AUTH` for any non-loopback
  Redis. Managed providers (Upstash) give TLS + auth by default.
- **Residual metadata** (deposit/drain timing, source IP, prekey-fetch graph) is the same
  as today and tracked separately (sealed-sender-style work) — Redis doesn't add to it.

## 10. Implementation plan (epics → files)

**E1 — Storage abstraction.** `crates/murmur-relay/src/store.rs`:
- `enum RelayStore { Memory(MemoryStore), Redis(RedisStore) }` with async
  `deposit/drain/put_prekey/get_prekey/health` and a `StoreError` (→ HTTP status).
- `MemoryStore` wraps today's `Arc<Mutex<MailboxStore>>` + prekey map (behavior unchanged).
- `RelayConfig` parsed from env (defaults = today's).

**E2 — Redis backend.** `crates/murmur-relay/src/redis_store.rs`:
- `RedisStore { conn: ConnectionManager, cfg }` + two `redis::Script`s (deposit, drain)
  loaded once. Hash-tagged keys (§4). `fingerprint = SHA256(ciphertext)` (reuse the same
  rule as `murmur-core`). Prekey = `SET EX` / `GET`. `health = PING`.
- Add deps: `redis` (`tokio-comp`, `connection-manager`, `script`), `sha2` (already via
  workspace), keep `serde_json` for payloads.

**E3 — HTTP + entrypoint.** `crates/murmur-relay/src/http.rs` + `src/main.rs`:
- `RelayState` holds a `RelayStore`; handlers `await` it; map `StoreError` →
  `503`/`507`. `GET /` returns version and (Redis) pings. `serve-http` builds the backend
  from env, fail-fast on a bad Redis URL at startup.
- **Invariant:** no env → Memory → the 13-leg `serve` self-test and `NET-1` stay green
  unchanged.

**E4 — Tests** (§11). `tests/redis_durability.rs` (black-box over HTTP, gated by
`MURMUR_RELAY_TEST_REDIS_URL`). Keep `http.rs`'s in-memory round-trip test.

**E5 — Load/volume harness.** `crates/murmur-relay/examples/loadtest.rs` (§11).

**E6 — Deploy kit + docs.** Update `deploy/murmur-relay/fly.toml` (Redis secret, an
always-on machine, `maxmemory` guidance) + `README.md` (provision Upstash/Fly Redis, set
the secret, env table) referencing this PRD.

## 11. Test & performance plan (you must be able to re-run this)

### Correctness / reliability (Rust tests, gated on a live Redis)
1. **Durability (the headline):** start Redis → `serve-http` (Redis) on an ephemeral port
   → deposit N → **kill the relay process** → start a fresh relay on the same Redis →
   `GET /drain` returns all N, in order. *Proves a restart loses nothing.*
2. **Idempotent replay:** re-deposit a byte-identical envelope → `deduped_replay`/200; it
   does not double-deliver.
3. **Drain-once:** two drains → second is `[]`; a replay *after* drain is still deduped.
4. **Quota:** per-mailbox message + byte caps return `quota_exceeded` and record nothing.
5. **TTL:** with a 1 s `MSG_TTL`, an undrained message is gone after expiry; an active
   mailbox (kept depositing) is not.
6. **Prekey:** publish → fetch identical bytes; unknown AID → 404; TTL expiry → 404.
7. **Concurrency:** K concurrent depositors to one mailbox → exactly K queued (no lost/dup
   under the atomic Lua), drain returns K.
8. **Fail-closed:** point at a dead Redis → deposit returns `503`, never `queued`.

### Performance / volume (the `loadtest` example, against local Redis)
Metrics: **throughput** (deposits/s, drains/s), **latency** p50/p99/p999, **error rate**,
**Redis memory** (`INFO memory`) at the backlog depth.
Scenarios:
- **Throughput:** C concurrent clients, small (256 B) and large (16 KiB) ciphertext,
  60 s sustained — record ops/s + latency percentiles.
- **Backlog volume:** deposit a large undrained backlog (e.g. 200k messages across 10k
  mailboxes), record Redis memory + a cold-drain latency, confirm per-mailbox + global
  (`maxmemory`) caps hold and quota kicks in cleanly.
- **Restart-under-load:** mid-load, kill+restart the relay; confirm zero message loss and
  a fast recovery (clients see brief 5xx, then success).
- **Soak:** 10 min steady deposit/drain; memory returns to baseline after drains (no
  leak); dedup/TTL keys don't accumulate unbounded.

### Targets (single small Redis + one relay machine; revise with real numbers)
- ≥ **5,000** deposit+drain round-trips/s at p99 < **15 ms** for 256 B payloads, local.
- Linear-ish throughput scaling as relay machines are added (Redis-bound, not relay-CPU).
- **Zero** message loss across a kill+restart with a non-empty backlog.
- Memory ≈ ciphertext bytes + small constant per key; no unbounded growth under soak.

> Real measured numbers from the harness are appended to `docs/perf-results.md` when the
> suite is run, so the targets become evidence.

## 12. Out of scope / future
- Per-message TTL precision (sorted-set + sweeper) vs the sliding mailbox TTL here.
- Redis Cluster sharding (keys are already tagged for it) and multi-region relay.
- The durable app-side outbox + delivery-ack wiring (§8) — app repo, separate task.
- Sealed-sender / fetch-privacy metadata work — separate track.
- A pull/stream (WebSocket/SSE) drain to replace polling — separate task.

## 13. Acceptance — done when
- `MURMUR_RELAY_REDIS_URL` set → durable Redis backend; unset → in-memory (gate + `NET-1`
  unchanged and green).
- The durability test passes: **a relay restart with a non-empty backlog loses nothing.**
- All §11 correctness tests green on a live Redis; fail-closed verified.
- The `loadtest` harness runs and `docs/perf-results.md` records real throughput/latency/
  memory numbers meeting (or honestly revising) §11 targets.
- Deploy kit updated so a Fly deploy with a managed Redis is a documented, repeatable
  runbook (owner runs it).
