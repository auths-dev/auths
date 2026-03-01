# Performance

Read and write throughput characteristics of the Auths registry.

## Storage Tiers

The registry uses a two-tier storage architecture:

- **Tier 0 (Redis):** Sub-millisecond cached reads and writes via an async connection pool.
- **Tier 1 (Git):** Persistent cryptographic ledger storing identity data as Git objects under `refs/auths/registry/v1`.

See [Storage Architecture](storage-architecture.md) for full details.

## Read Path

| Operation | Cache Hit (Redis) | Cache Miss (Git) |
|-----------|-------------------|-------------------|
| Key state lookup | Sub-millisecond | O(N) KEL replay on first access |
| Event retrieval | Sub-millisecond | Git tree traversal |
| Tip lookup | Sub-millisecond | Git tree traversal |

On a cache miss, the system reads from Git, populates Redis with a configurable TTL (default: 1 hour), and returns the result. Subsequent reads for the same identity are served from Redis until the TTL expires or a write refreshes the entry.

If Redis is unreachable, reads fall through to Git transparently. Latency increases but the service remains available.

## Write Path

Each identity update performs:

1. **Structural validation** (O(1)): prefix match, sequence check, chain linkage, SAID verification
2. **Cryptographic verification** (O(1)): validates the new event's Ed25519 signature and pre-rotation commitment against the current `KeyState` — no full KEL replay
3. **Redis write** (sub-millisecond): updates the cache immediately so subsequent reads see the new state
4. **Background Git commit** (1-10ms on SSD): a background worker writes the blob, updates the tree, creates the commit, and performs a CAS ref update

The HTTP handler returns as soon as the Redis write completes. Git commits happen asynchronously in a sequential background worker, keeping the write path fast and non-blocking.

### Why O(1) Append

The write path validates only the incoming event against the current key state. It does NOT replay the entire Key Event Log (KEL). This means append time is constant regardless of how many events an identity has.

The alternative — full KEL replay on every write — would make append time O(N) where N is the KEL length, creating a denial-of-service vector.

The current `KeyState` is trustworthy because it was computed from a full KEL validation on first read and updated incrementally on each subsequent write.

## Write Throughput

**Single-writer throughput**: ~100-1,000 events/second, bounded by Git commit latency.

Each Git write requires tree object creation, a commit object, and a ref update. On an SSD this takes 1-10ms per commit. The background worker serializes all Git writes, so throughput is:

```
throughput = 1 / commit_latency
           ≈ 100-1,000 events/sec (SSD)
           ≈ 10-100 events/sec (HDD)
```

This is sufficient for identity management workloads where events are key rotations, device attestations, and interaction anchors — not high-frequency transactions.

### Why Git?

Git provides integrity guarantees that would otherwise require a database WAL:

- **Content-addressed storage**: every object is verified by its hash
- **Atomic ref updates**: CAS on ref OID prevents split-brain
- **Built-in audit trail**: commit history is the audit log
- **Portability**: `git clone` replicates the entire registry

### Scaling Paths

| Strategy | Read | Write | Status |
|----------|------|-------|--------|
| Redis cache | Scales horizontally (read replicas) | N/A | Implemented |
| Identity sharding | N/A | Parallel writes to different shards | Future |
| Witness receipts | Distributed verification | N/A | Partial (infrastructure exists) |

**Identity sharding**: partition identities across multiple Git repos by prefix hash. Each shard has its own advisory lock, enabling parallel writes. Not implemented — current throughput is sufficient for target workloads.

## Benchmarking

Run the registry benchmarks:

```bash
cargo bench --package auths-id --bench registry
```

Available benchmarks:

- `key_state_lookup`: cached key state reads at various identity counts
- `cache_cold_start`: first-read cache rebuild time
- `event_append`: single interaction append including crypto verification + Git commit
- `append_scaling`: confirms O(1) append time at KEL depths of 10, 100, 500
