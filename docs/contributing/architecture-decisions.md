# Architecture Decisions

This page summarizes the key architectural decisions in Auths and links to the full ADR documents where they exist.

## ADR Index

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [ADR-001](#adr-001-repo-per-tenant-isolation) | Repo-per-tenant isolation | Accepted | 2026-02-21 |
| [ADR-002](#adr-002-git-backed-keri-ledger) | Git-backed KERI ledger | Accepted | 2026-02-27 |
| [ADR-003](#adr-003-tiered-cache-and-write-contention) | Tiered cache and write-contention mitigation | Accepted | 2026-02-27 |
| [ADR-004](#adr-004-async-executor-protection) | Async executor protection | Accepted | 2026-02-27 |

## ADR format

Each ADR is a Markdown file named `ADR-NNN-short-title.md` containing:

1. **Title** -- short imperative phrase.
2. **Status** -- `Proposed`, `Accepted`, `Deprecated`, or `Superseded by ADR-NNN`.
3. **Context** -- the situation that motivated the decision.
4. **Decision** -- what was decided and why.
5. **Consequences** -- positive and negative outcomes.

To add a new ADR: copy the structure from an existing one, use the next sequential number, and start with `Status: Proposed`.

---

## Why Git for storage

Auths stores all identity data and attestations as Git refs. The `~/.auths` directory is a Git repository. This was chosen because:

- **Content addressing is structural.** Git's SHA DAG is a Merkle structure. Every object's hash is a cryptographic commitment to its content and its ancestors, requiring no additional verification layer.
- **Replication is structural.** `git push` / `git pull` to any remote propagates the full history. Radicle integration requires zero serialization format changes.
- **No new infrastructure.** Every developer already has Git. The ledger is auditable with standard `git log` tooling.
- **Backup and restore are trivial.** Copy the directory. No schema migration, no ref renaming.

Identity data lives under `refs/auths/` and KERI Key Event Logs live under `refs/keri/` (or `refs/did/keri/<prefix>/kel` for commit-chain KELs).

## Why Ed25519

All signing operations in Auths use Ed25519:

- **Deterministic signatures.** Given the same key and message, Ed25519 always produces the same signature. This simplifies testing and auditing.
- **Small keys and signatures.** 32-byte public keys, 64-byte signatures. Efficient for storage in Git blobs and transmission in attestation JSON.
- **Wide ecosystem support.** Ed25519 is supported by OpenSSH, GPG, `ring`, and the W3C DID specification. SDK consumers in Python, TypeScript, Go, and Swift all have mature Ed25519 libraries.
- **No parameter choices.** Unlike RSA or ECDSA over arbitrary curves, Ed25519 has no key-size or curve selection -- there is one set of parameters.

The `ring` crate provides the implementation (see below).

## Why ring

Auths uses the [`ring`](https://github.com/briansmith/ring) crate for all cryptographic operations:

- **No unsafe Rust in the crypto path.** `ring` wraps BoringSSL (Google's OpenSSL fork) with a safe Rust API. The C code is battle-tested in Chrome and Android.
- **Minimal API surface.** `ring` exposes only what it considers safe. There are no footguns like "encrypt without authentication" or "sign with weak parameters."
- **FIPS-derived codebase.** BoringSSL has undergone FIPS 140-2 validation. While `ring` itself is not FIPS-certified, the underlying primitives share the validated codebase.
- **Cross-platform.** Builds on all Auths CI targets: Linux x86_64, macOS aarch64, Windows x86_64, and WASM (for `auths-verifier`).

The `ring::signature::Ed25519KeyPair` type is `!Send`, which is why signing operations are dispatched via `tokio::task::spawn_blocking` in server contexts (see ADR-004).

## Why KERI

Auths uses KERI (Key Event Receipt Infrastructure) principles for identity management:

- **Pre-rotation.** The hash of the next rotation key is committed in the current event. An attacker who compromises the current key cannot rotate the identity -- they do not know the pre-committed next key's pre-image.
- **Decentralized.** No central authority, blockchain, or consensus protocol. The Key Event Log is self-certifying: anyone with the log can verify the full key history.
- **Survives key rotation.** The identity DID (`did:keri:E...`) is derived from the inception event and remains stable across any number of key rotations. This is unlike `did:key`, where the identifier changes with the key.
- **Append-only.** The KEL is a hash-linked chain of events. Forking (two valid branches) is a hard, unrecoverable error -- detected immediately by `KelError::ChainIntegrity`.

KERI events are stored as Git commits (ADR-002), giving the KEL content-addressed integrity and Git-native replication.

---

## ADR-001: Repo-per-tenant isolation

**Decision:** Multi-tenant deployments use one Git repository per tenant, not ref-based namespacing within a shared repository.

**Rationale:**

- Blast radius of a bug (e.g., accidental ref deletion) is limited to one tenant.
- Backup = `cp -a tenants/acme`. Restore = `cp -a`. Migrate = `mv`.
- OS-level permission controls (directory permissions, ACLs) apply per tenant.
- Zero changes required to the existing `PackedRegistryBackend` storage implementation.

**Trade-offs:** More directories to manage at scale; LRU cache (`moka`) has no TTL by default for suspended tenants.

## ADR-002: Git-backed KERI ledger

**Decision:** KERI Key Event Logs are stored as Git commit chains under `refs/did/keri/<prefix>/kel`.

**Rationale:**

- Git's SHA DAG provides content-addressed Merkle-proof tamper evidence with no custom verification layer.
- Replication to Radicle peers is a single `git push` with no serialization format translation.
- A custom write-ahead log would require reimplementing content-addressing, append-only enforcement, and distributed replication -- all of which Git already solves.

**State resolution** uses a three-tier approach: cache hit (O(1)), incremental validation (O(k) for k new events), or full replay (O(n) on cold start).

**Trade-offs:** `libgit2` is synchronous (dispatched via `spawn_blocking`); write contention is managed by the `ArchivalWorker` (ADR-003).

## ADR-003: Tiered cache and write-contention

**Decision:** Redis (Tier 0) absorbs identity resolution reads; Git (Tier 1) is the write path. A background `ArchivalWorker` serializes Git writes with exponential backoff. Permanently failed writes route to a Redis Stream Dead Letter Queue.

**Rationale:**

- Direct Git reads under concurrent HTTP traffic cause O(n) replays that saturate the `spawn_blocking` pool.
- Redis hit rates for stable identities are effectively 100% in steady state.
- The DLQ preserves KERI hash-chain ordering for failed writes.

**Trade-offs:** Redis is an additional infrastructure dependency; DLQ depth must be monitored.

## ADR-004: Async executor protection

**Decision:** All CPU-bound and synchronous I/O operations (Argon2id, Ed25519 via `ring`, `git2`) are dispatched via `tokio::task::spawn_blocking`. Distributed singleton enforcement uses `pg_try_advisory_xact_lock`.

**Rationale:**

- Blocking Tokio worker threads causes reactor starvation. At 16 concurrent Argon2 operations on a 4-core machine, the entire async runtime halts.
- `spawn_blocking` dispatches work to a dedicated pool (default ceiling: 512 threads), keeping async task scheduling uninterrupted.
- `pg_try_advisory_xact_lock` returns immediately and auto-releases on crash -- no stale locks.

**Trade-offs:** `spawn_blocking` closures require owned data (`move`); keypair re-materialization adds ~2us overhead per signing operation.

---

## STRIDE threat model

A comprehensive STRIDE threat analysis covering six trust boundaries (FFI surface, cryptographic enclave, KERI chain integrity, clock/timestamp, tenant namespace, session/Postgres singleton) is maintained as `THREAT-MODEL-001-stride.md`. It documents all controls with code evidence and residual risk ratings.
