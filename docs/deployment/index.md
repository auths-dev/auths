# Deployment

Operational guides for running Auths infrastructure.

## Sections

- **[Witness Servers](witness-servers.md)** -- Deploy and configure witness servers for multi-party verification of KERI events. Covers initialization, TLS, health checks, and witness policies.

- **[Performance & Tuning](performance.md)** -- Read/write throughput characteristics, the two-tier Redis/Git storage architecture, scaling paths, and benchmarking.

- **[Storage Architecture](storage-architecture.md)** -- Deep dive into the tiered storage model: Redis hot cache, Git persistent ledger, background writers, dead letter queues, and failure handling.
