# Distributed Session Cleanup Locking

## Problem

`spawn_cleanup_task` runs a periodic loop that deletes expired sessions. In a multi-node deployment, every instance runs this loop independently, causing redundant DELETE queries and database contention.

## Solution: Transaction-Level Advisory Locks

We use PostgreSQL's `pg_try_advisory_xact_lock` to coordinate cleanup across nodes. On each tick, a node attempts to acquire the lock inside a transaction:

- **Lock acquired**: the node runs the batched DELETE, then commits (releasing the lock).
- **Lock not acquired**: the node commits the empty transaction and skips cleanup.

### Why Transaction-Level (Not Session-Level)

Session-level advisory locks (`pg_advisory_lock`) persist until explicitly released or the connection closes. With connection pooling (`sqlx::PgPool`), a connection holding a session-level lock may be returned to the pool without releasing it, permanently blocking other nodes.

Transaction-level locks (`pg_try_advisory_xact_lock`) are automatically released when the transaction commits or rolls back — even if the Rust code panics. This makes them safe with connection pools.

### Lock ID

All nodes contend on the same lock ID:

```
CLEANUP_LOCK_ID = 0x6175_7468_7365_7373  ("authsess" in hex)
```

This is a constant defined in `postgres_session_store.rs`.

## Architecture

The implementation is decomposed into three functions:

1. **`spawn_cleanup_task(pool, interval_duration)`** — the temporal loop. On each tick, delegates to `attempt_cleanup_cycle`. Logs errors but never panics.

2. **`attempt_cleanup_cycle(pool)`** — acquires a transaction, attempts the advisory lock. If acquired, calls `execute_garbage_collection`. Commits the transaction (auto-releasing the lock).

3. **`execute_garbage_collection(tx)`** — runs the batched DELETE within the provided transaction.

## Failure Modes

| Scenario | Behavior |
|----------|----------|
| Node crashes mid-cleanup | Transaction rolls back, lock is released, next tick another node picks up |
| Lock held by another node | `pg_try_advisory_xact_lock` returns false (non-blocking), node skips cleanup |
| Database unreachable | Error is logged, node retries on next tick |
| All nodes stop | No cleanup runs; expired sessions accumulate until a node restarts |
