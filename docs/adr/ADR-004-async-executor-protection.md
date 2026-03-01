---
title: "ADR-004: Async Executor Protection & Distributed Singleton Enforcement"
date: 2026-02-27
status: Accepted
authors:
  - Engineering Team, Principal Architect
deciders:
  - Engineering Team, CTO
tags: [infrastructure, performance, security, async, postgres, concurrency]
---

# ADR-004: Async Executor Protection & Distributed Singleton Enforcement

## 1. Context and Problem Statement

Auths runs on Tokio's M:N async runtime, which multiplexes async tasks across a fixed-size worker-thread pool (default: number of logical CPUs). When a worker thread executes a long-running blocking operation — CPU-bound computation or synchronous I/O — it is unavailable for async task scheduling for the entire duration. When all worker threads are simultaneously blocked, no async task in the process can make progress. This is **reactor starvation**.

The system contains three categories of operations with unbounded or unpredictable latency relative to network I/O:

1. **Argon2id password hashing** — intentionally CPU-bound; the default `Argon2::default()` parameters target ~64ms on modern hardware.
2. **Ed25519 sign/verify via `ring`** — a synchronous C-FFI library with no async interface.
3. **`git2` filesystem I/O** — synchronous C library that holds OS file locks during operations.

Additionally, in multi-node deployments, background tasks that must run on exactly one node at a time (e.g., expired-session cleanup) require a distributed singleton mechanism. Using `pg_advisory_lock` (blocking) would hold a database connection open for the entire cleanup duration, potentially exhausting the connection pool under concurrent cleanup attempts from multiple nodes.

**Key Constraints & Forces:**
* Async worker threads must never be blocked on CPU-bound or synchronous I/O operations.
* The Ed25519 keypair (`ring::Ed25519KeyPair`) is not `Send` and cannot be stored in a `Mutex` or `Arc` without `unsafe`; key material lifecycle must be bounded to individual signing operations.
* Distributed cleanup must not block database connections while waiting for a lock.
* Advisory lock scope must be the transaction — automatically released on node crash, with no stale lock accumulation.
* The lock ID for the cleanup singleton must be a compile-time constant, not a runtime configuration value, to prevent collision between unrelated deployments sharing a Postgres instance.

---

## 2. Considered Options

* **Option A:** Direct blocking calls on async tasks — Argon2, ring, and git2 called inline within Tokio async contexts.
* **Option B:** `spawn_blocking` for all CPU-bound / synchronous-I/O operations (selected).
* **Option C (cleanup):** `pg_advisory_lock` (blocking) — waits indefinitely until the lock is available.
* **Option D (cleanup):** `pg_try_advisory_xact_lock` (non-blocking, transaction-scoped) — returns immediately if lock is held (selected).

---

## 3. Decision

We have decided to proceed with **Option B** (`spawn_blocking`) for all CPU-bound and synchronous-I/O operations, and **Option D** (`pg_try_advisory_xact_lock`) for the distributed cleanup singleton.

### Rationale

**Option A** causes reactor starvation: at modest concurrency (16 simultaneous registration requests × 64ms Argon2 = 1,024ms total blocking time), a 4-core machine exhausts its worker pool entirely. HTTP request processing halts for all concurrent users.

**Option B** dispatches blocking work to Tokio's dedicated blocking pool, which is separate from the async worker pool and has a higher ceiling (default: 512 threads). Async task scheduling continues uninterrupted.

**Option C** (`pg_advisory_lock`) holds a database connection open for the lock-wait duration. Under concurrent cleanup attempts from N nodes, N connections block simultaneously — a pool-exhaustion scenario that degrades the entire application, not just the cleanup path.

**Option D** (`pg_try_advisory_xact_lock`) returns immediately: `true` if acquired, `false` if another node holds it. The connection is released immediately on `false`. The lock scope is the transaction — automatically released on commit, rollback, or node crash. There is no stale-lock scenario.

---

## 4. Implementation Specifications

### Data Flow / Architecture

```mermaid
graph TD
    subgraph AsyncPool ["Tokio Worker Threads — async pool (default: CPU count)"]
        H[HTTP Handlers\nAxum routes]
        TR[TieredResolver\nCache-Aside reads]
        AW[ArchivalWorker\nmpsc recv loop]
        CT[Cleanup Task\ninterval tick every 60s]
    end

    subgraph BlockingPool ["Tokio Blocking Pool — spawn_blocking (default ceiling: 512)"]
        A2[Argon2id\nhash_secret_blocking\nroutes/register.rs:171]
        ED[Ed25519 sign/verify\nRingCryptoProvider\nauths-crypto/ring_provider.rs]
        GI[git2 I/O\nLocalGitResolver / ArchivalWorker\nlocal_git_resolver.rs:56]
        RI[Registry init\nPackedRegistryBackend::init_if_needed\nroutes/tenant.rs:178]
    end

    subgraph PG ["Postgres"]
        LOCK["pg_try_advisory_xact_lock\nCLEANUP_LOCK_ID = 0x6175_7468_7365_7373\n('authsess' in ASCII hex)"]
        SESS["sessions table\nDELETE WHERE expires_at < now()"]
    end

    H -->|spawn_blocking| A2
    H -->|spawn_blocking| ED
    H -->|spawn_blocking| GI
    H -->|spawn_blocking| RI
    TR -->|spawn_blocking| GI
    AW -->|spawn_blocking via TierOneArchive| GI
    CT -->|sqlx async query| LOCK
    LOCK -->|locked = true| SESS
    LOCK -->|locked = false → Ok(None)| Skip["Return None — skip this cycle"]

    style AsyncPool fill:#e8f5e9,stroke:#2e7d32
    style BlockingPool fill:#fff3e0,stroke:#e65100
    style PG fill:#e3f2fd,stroke:#1565c0
```

**Argon2id dispatch** — `crates/auths-auth-server/src/routes/register.rs:167`

```rust
async fn hash_secret_blocking(secret: &str) -> Result<String, AuthApiError> {
    tokio::task::spawn_blocking(move || {
        let argon2 = Argon2::default();
        // ~64ms CPU-bound operation
    })
    .await?
}
```

Called at lines 108 and 114 in the registration handler.

**Ed25519 dispatch** — `crates/auths-crypto/src/ring_provider.rs`

```rust
async fn verify_ed25519(&self, pubkey: &[u8], message: &[u8], signature: &[u8])
    -> Result<(), CryptoError>
{
    tokio::task::spawn_blocking(move || {
        let peer_public_key = UnparsedPublicKey::new(&ED25519, &pubkey);
        peer_public_key.verify(&message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    })
    .await?
}

async fn sign_ed25519(&self, seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    tokio::task::spawn_blocking(move || {
        // Keypair re-materialized from raw seed on each call.
        // ring::Ed25519KeyPair is !Send; cannot be stored in Arc<Mutex<>>.
        let keypair = Ed25519KeyPair::from_seed_unchecked(&seed_bytes)?;
        Ok(keypair.sign(&message).as_ref().to_vec())
    })
    .await?
}
```

**Distributed cleanup singleton** — `crates/auths-auth-server/src/adapters/postgres_session_store.rs:291`

```rust
// Lock ID derived from "authsess" in ASCII hex — compile-time constant.
const CLEANUP_LOCK_ID: i64 = 0x6175_7468_7365_7373_u64 as i64;

async fn attempt_cleanup_cycle(pool: &PgPool) -> Result<Option<usize>, StoreError> {
    let mut tx = pool.begin().await?;
    let locked: bool = sqlx::query_scalar!(
        "SELECT pg_try_advisory_xact_lock($1) AS \"locked!\"",
        CLEANUP_LOCK_ID,
    )
    .fetch_one(&mut *tx)
    .await?;

    if !locked {
        return Ok(None); // Another node holds the lock; skip without blocking
    }
    // Run cleanup — lock auto-released on tx commit/rollback
}
```

Cleanup runs on a 60-second `tokio::time::interval` with `MissedTickBehavior::Delay`.

### Dependencies

| Dependency | Crate | Purpose |
| :--- | :--- | :--- |
| `tokio::task::spawn_blocking` | all server crates | Dispatch CPU/IO-bound work off async executor |
| `argon2` | `auths-auth-server` | Password hashing (Argon2id) |
| `ring` | `auths-crypto` | Ed25519 sign/verify |
| `git2` | `auths-id`, `auths-auth-server` | Synchronous Git operations |
| `sqlx` | `auths-auth-server` | `pg_try_advisory_xact_lock` query |

### Security Boundaries

`SecureSeed` is a newtype wrapping `[u8; 32]` with no `Debug`, `Display`, or `Clone` impl — preventing accidental log leakage of raw key material. The `ring::Ed25519KeyPair` object (which holds key material in C heap memory) exists only for the duration of a single `spawn_blocking` closure; it is dropped immediately after signing. Long-lived key material in process memory is eliminated by design.

The advisory lock ID (`0x6175_7468_7365_7373`) is a compile-time constant. Configurable lock IDs create a risk of two independent deployments sharing a Postgres instance and silently stealing each other's cleanup singleton.

### Failure Modes

| Failure | Behaviour |
| :--- | :--- |
| `spawn_blocking` task panics | `JoinError` is returned; caller maps to `CryptoError::OperationFailed` or `AuthApiError` |
| Blocking pool saturation (512 threads) | New `spawn_blocking` calls queue; eventually timeout at the HTTP layer |
| `pg_try_advisory_xact_lock` returns `false` | `attempt_cleanup_cycle` returns `Ok(None)`; next tick retries in 60s |
| Node crashes mid-cleanup | Postgres releases transaction-scoped advisory lock on connection close; next node to tick acquires lock cleanly |

---

## 5. Consequences & Mitigations

### Positive Impacts
* Async worker threads are never blocked — HTTP request latency is fully decoupled from Argon2, ring, and git2 operation duration.
* `pg_try_advisory_xact_lock` guarantees at-most-one cleanup runner across any number of nodes with zero additional infrastructure.
* Advisory lock auto-release on crash eliminates the stale-lock failure mode entirely.
* `SecureSeed` encapsulation prevents raw key material from ever appearing in a `Mutex`, `Arc`, or log output.

### Trade-offs and Mitigations

| Negative Impact / Trade-off | Remediation / Mitigation Strategy |
| :--- | :--- |
| `spawn_blocking` closures require owned data (`move`); input slices must be cloned before dispatch | Clones are small (32-byte seeds, signature bytes); heap allocation cost is negligible relative to Ed25519 and Argon2 computation time |
| Keypair re-materialization on every `sign_ed25519` call adds ~2µs overhead | Acceptable for commit-signing workloads; re-materialization cost is orders of magnitude below the Argon2 or network I/O budget |
| 60-second cleanup interval means expired sessions persist up to 60s post-expiry | Acceptable given session expiry windows of hours to days; reduce interval if compliance requires tighter TTL enforcement |
| Blocking pool saturation under extreme concurrency (>512 `spawn_blocking` tasks) | Rate-limit CPU-bound endpoints (registration, verification) at the Axum layer; alert on `tokio_blocking_threads` gauge approaching ceiling |

---

## 6. Validation & Telemetry

* **Health Checks:** `spawn_blocking` task panic rate — liveness probe should fail if `CryptoError::OperationFailed("… task panicked")` errors exceed threshold; indicates blocking pool exhaustion.
* **Metrics (Prometheus):**
  * `tokio_blocking_threads` — gauge; alert if sustained > 400 (80% of default 512 ceiling)
  * `auths_argon2_duration_seconds` — histogram; P99 > 500ms indicates hardware regression or config change
  * `auths_ed25519_verify_duration_seconds` — histogram; P99 > 10ms indicates blocking pool pressure
  * `auths_session_cleanup_skipped_total` — counter; high rate indicates multi-node lock contention (normal at low rates)
  * `auths_session_cleanup_deleted_total` — counter; zero for extended periods indicates cleanup task is not running
* **Log Signatures:**
  * `WARN Cleanup lock held by another node, skipping` — informational; expected in multi-node deployments
  * `WARN Session cleanup error: …` — investigate; Postgres connectivity or schema issue
  * `ERROR … Verification task panicked` — P1; blocking pool or ring library issue

---

## 7. References
* ADR-003: Tiered Cache & Write-Contention Mitigation — establishes `spawn_blocking` dispatch pattern for `git2`
* [Tokio docs: CPU-bound tasks and blocking code](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)
* [Postgres docs: Advisory Locks](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS)
* `crates/auths-crypto/src/ring_provider.rs` — `RingCryptoProvider` with `spawn_blocking` dispatch
* `crates/auths-auth-server/src/routes/register.rs:167` — `hash_secret_blocking`
* `crates/auths-auth-server/src/adapters/postgres_session_store.rs:291` — `CLEANUP_LOCK_ID` and `pg_try_advisory_xact_lock`
* `crates/auths-auth-server/src/adapters/local_git_resolver.rs:56` — `spawn_blocking` for `git2`
