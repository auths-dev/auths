# High-Performance Storage Tiering Design

## Overview

Replace the single-tier Git-native storage with a two-tier architecture:
- **Tier 0 (Hot):** Redis — async reads/writes, sub-millisecond latency
- **Tier 1 (Cold):** Git — persistent cryptographic ledger, sequential writes via background worker

Target: `auths-registry-server`. New code lives in a dedicated `auths-cache` crate.

## Architecture

```
                         ┌─────────────────────┐
                         │  HTTP Request        │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │  auths-registry-     │
                         │  server (Axum)       │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │      TieredResolver            │
                    │      (auths-cache crate)       │
                    └───┬───────────────────────┬───┘
                        │                       │
              ┌─────────▼─────────┐   ┌────────▼──────────┐
              │  Tier 0: Redis    │   │  Tier 1: Git      │
              │  (RedisCache)     │   │  (GitArchive)     │
              │  async, <1ms      │   │  spawn_blocking   │
              └───────────────────┘   └───────────────────┘
                        │
              ┌─────────▼─────────┐
              │  Write-Through    │
              │  mpsc channel     │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │  ArchivalWorker   │
              │  (background)     │
              │  Sequential Git   │
              │  commits          │
              └─────────┬─────────┘
                        │ on failure
              ┌─────────▼─────────┐
              │  DLQ: Redis       │
              │  Stream           │
              │  auths:dlq:       │
              │  archival         │
              └───────────────────┘
```

## Read Path (Cache-Aside)

1. HTTP request arrives at `auths-registry-server`
2. `TieredResolver::resolve(did)` checks Redis via `TierZeroCache::get_state(did)`
3. **Cache hit** → return `KeyState` immediately (sub-1ms)
4. **Cache miss** → `TierOneArchive::read_ledger(did)` calls `PackedRegistryBackend` via `spawn_blocking`
5. Hydrate Redis: `TierZeroCache::set_state(did, state)` with configurable TTL
6. Return `KeyState`

**Cache miss on Redis failure:** If Redis is unreachable, log warning and fall through to Git directly. The system degrades gracefully — higher latency but no downtime.

## Write Path (Write-Through)

1. HTTP request writes an identity update
2. Write to Redis immediately via `TierZeroCache::set_state(did, state)`
3. Dispatch `ArchivalMessage::Update { did, state }` to `mpsc::Sender`
4. Return success to client (Git write is async)
5. `ArchivalWorker` receives message and commits to Git

**No `spawn_blocking` on the HTTP request path for writes.** Git commits happen exclusively in the background worker.

## Concurrency Guarantees

- **Redis reads:** Fully async via `bb8` connection pool. No thread pool contention.
- **Redis writes:** Async. Write-through ensures Redis is always ahead of Git.
- **Git writes:** Sequential via single `mpsc` consumer. No concurrent Git ref mutations. Advisory file lock (`registry.lock`) still held during writes for external safety.
- **HTTP handler threads:** Never blocked by Git I/O on the write path. Read-path cache misses still use `spawn_blocking` but only on cold starts / TTL expiry.

## Cache Invalidation

- **TTL-based:** Default 1 hour, configurable via `AUTHS_CACHE_TTL_SECS`
- **Write-through:** On identity update, Redis is written before Git, so cache is always fresh
- **Explicit invalidation:** `TierZeroCache::delete_state(did)` for manual cache busting
- **Key format:** `auths:state:{did}` (e.g., `auths:state:did:keri:abc123`)
- **Serialization:** JSON via `serde_json` (consistent with existing Git blob format)

## Failure Handling and DLQ

KERI identity sequences are strictly append-only cryptographic hash chains. Dropping a failed event would permanently corrupt the chain once Redis TTL evicts.

### Retry Strategy

1. Attempt Git write
2. On failure: retry up to 3 times with exponential backoff + jitter
   - Attempt 1: 100ms + random(0..50ms)
   - Attempt 2: 400ms + random(0..50ms)
   - Attempt 3: 1600ms + random(0..50ms)
3. On exhaustion: route to Dead Letter Queue

### Dead Letter Queue (DLQ)

- **Implementation:** Redis Stream at key `auths:dlq:archival`
- **Format:** `XADD auths:dlq:archival * payload <json>`
- **Payload:** Serialized `ArchivalMessage` (did + KeyState)
- **Logging:** `error!` level with stream entry ID for traceability

### DLQ Recovery Procedures

1. **Inspect:** `XRANGE auths:dlq:archival - +` to list pending messages
2. **Replay:** Process messages in order (they are sequenced by Redis Stream ID)
3. **Verify:** After replay, run `verify_chain(did)` to confirm hash chain integrity
4. **Acknowledge:** `XDEL auths:dlq:archival <id>` after successful replay
5. **Monitor:** Alert on `XLEN auths:dlq:archival > 0` in production monitoring

## Failover Strategies

| Scenario | Behavior |
|----------|----------|
| Redis down (reads) | Fall through to Git via `spawn_blocking`. Log warning. Higher latency. |
| Redis down (writes) | Write directly to Git synchronously. Log warning. |
| Redis down (DLQ) | Log `critical!` — manual intervention required. |
| Git lock contention | Retry with backoff → DLQ on exhaustion |
| Git disk failure | DLQ preserves messages for replay after recovery |
| mpsc channel full | Back-pressure on HTTP write handlers (bounded channel) |

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `AUTHS_REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection URL |
| `AUTHS_REDIS_POOL_SIZE` | `16` | Max connections in bb8 pool |
| `AUTHS_CACHE_TTL_SECS` | `3600` | Cache entry TTL in seconds |
| `AUTHS_ARCHIVAL_CHANNEL_SIZE` | `1024` | mpsc channel buffer size |

## Crate Structure

```
crates/auths-cache/
  Cargo.toml
  src/
    lib.rs           # Re-exports
    traits.rs        # TierZeroCache, TierOneArchive traits
    error.rs         # CacheError, ArchiveError, ResolutionError, DLQError
    redis_cache.rs   # RedisCache impl of TierZeroCache
    git_archive.rs   # GitArchive impl of TierOneArchive
    resolver.rs      # TieredResolver (cache-aside orchestrator)
    worker.rs        # ArchivalWorker, DLQ routing
    config.rs        # CacheConfig from env vars
```

## Changes to Existing Crates

### `auths-id`
- Remove `redb` dependency from `Cargo.toml`
- Remove `crates/auths-id/src/storage/registry/cache.rs` (`RegistryCache`)
- Remove cache-related fields from `PackedRegistryBackend`
- `PackedRegistryBackend` becomes a pure Git-only backend

### `auths-registry-server`
- Add `auths-cache` dependency
- `ServerState` gains: `redis_pool`, `tiered_resolver`, `archival_tx`
- Identity read endpoints use `tiered_resolver.resolve()` instead of direct backend calls
- Identity write endpoints use write-through pattern
- `run_server()` spawns `ArchivalWorker` and holds `JoinHandle` for graceful shutdown

### Workspace `Cargo.toml`
- Add `auths-cache` to workspace members
