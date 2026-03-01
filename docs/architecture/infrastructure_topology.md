# Infrastructure Topology & Deployment Boundaries

This document defines the strict 3-layer architecture of the `auths` Public Registry ecosystem. To ensure cryptographic integrity, high availability, and global scalability, the system strictly separates the stateless presentation layer from the stateful cryptographic engine.

## Architectural Overview

```mermaid
flowchart TD
    Client((Client Browser / CLI))

    subgraph Layer 1: Vercel / Edge (auths-site)
        UI[Next.js 15 App Router]
        Cache[Edge Cache]
    end

    subgraph Layer 2: API & Crypto Engine (VPS / Container)
        Axum[Rust Axum Server]
        Middleware[Tower Rate Limiting & Auth]
        Tokio[Tokio Async Runtime]
    end

    subgraph Layer 3: The State (Postgres & Git)
        DB[(Managed Postgres)]
        Git[(Persistent NVMe / Git Ledger)]
    end

    Client -->|HTTPS / UI Interactions| UI
    Client -->|CLI Commands| Axum
    UI -->|API Proxying & Data Fetching| Axum
    Axum -->|Relational Queries| DB
    Axum -->|File System / Immutable Logs| Git
```

---

## Layer 1: The Presentation Layer (Vercel / Edge)

**Repository:** `auths-site`

**Tech Stack:** Next.js 15 (App Router), React Server Components (RSC)

The presentation layer serves as the user-facing discovery portal (`/registry`). It is deployed to Vercel's Edge/Serverless infrastructure.

### Constraints & Responsibilities

* **Strictly Stateless:** Vercel's serverless functions are ephemeral. They spin down to zero and lack persistent local file systems.
* **No Cryptographic State:** This layer **cannot** hold private keys, manage Key Event Logs (KELs), or write to the KERI ledger.
* **API Proxying:** It acts purely as a consumer of the `auths-registry-server`. All data displayed on the dashboard (recent artifacts, identity trust graphs) is fetched via HTTP requests to Layer 2.
* **Edge Caching:** Leverages Next.js 15 caching directives (`use cache`, `stale-while-revalidate`) to serve high-traffic public key lookups instantly via Vercel's global CDN, protecting the Rust backend from traffic spikes.

---

## Layer 2: The API & Crypto Engine (VPS / Containerized)

**Repository:** `auths-registry-server`

**Tech Stack:** Rust, Axum, Tokio, Tower

This is the core engine of the Web of Trust. Because resolving Decentralized Identifiers (DIDs) requires replaying cryptographically linked lists and verifying Ed25519 signatures, this layer manages heavy CPU-bound tasks.

### Constraints & Responsibilities

* **Always-On Persistence:** Unlike Layer 1, this layer **cannot** be deployed to serverless environments (like AWS Lambda or Vercel). It requires an always-on, persistent process deployed via Docker to services like AWS ECS, Fly.io, or a standard VPS.
* **Stateful Cryptography:** Executes KERI state resolution. CPU-heavy signature verifications are offloaded from the main async reactor using `tokio::task::spawn_blocking` to prevent starving concurrent network requests.
* **Rate Limiting:** Implements `tower_governor` and GDPR-compliant HMAC-SHA256 time-salted IP hashing to enforce monthly API quotas without storing Personally Identifiable Information (PII).
* **Connection Pooling:** Maintains persistent TCP connections to Layer 3 via `sqlx::PgPool` to ensure high-throughput reads for CI/CD systems fetching maintainer keys.

---

## Layer 3: The State (Postgres & Git)

The state layer is bifurcated into two distinct storage mediums to balance fast relational querying with immutable cryptographic auditing.

### 1. Fast Indexing (Managed Postgres)

* **Role:** Serves as the high-speed search index.
* **Infrastructure:** Should be hosted on a managed database provider (e.g., Supabase, Neon, AWS RDS) for automated backups and connection pooling.
* **Data Stored:** * `platform_claims`: Maps human-readable namespaces (e.g., `@torvalds` or `did:key:z6Mk...`) to specific DIDs.
* `artifact_attestations`: Partitioned table mapping compiled software packages (`npm:react`) to the device keys that signed them.
* `public_registrations`: Stores the anonymized HMAC hashes for quota enforcement.

### 2. The Immutable Ledger (Git / NVMe Disk)

* **Role:** The canonical, cryptographically verifiable source of truth.
* **Infrastructure:** Requires a **Persistent NVMe/EBS Volume** mounted directly to the Layer 2 container.
* **Data Stored:** The `PackedRegistryBackend` uses Git as its underlying storage mechanism to append KERI Key Event Logs (KELs) and attestation JSON files.
* **Constraint:** If the Rust container restarts or is redeployed, this volume *must* persist. Losing this disk means losing the immutable history required to mathematically prove the state of an identity, which cannot be reconstructed solely from the Postgres indices.
