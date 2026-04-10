# Architecture Decisions

This page summarizes the key architectural decisions in Auths and links to the full ADR documents where they exist.

## ADR Index

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [ADR-001](#adr-001-repo-per-tenant-isolation) | Repo-per-tenant isolation | Accepted | 2026-02-21 |
| [ADR-002](#adr-002-git-backed-keri-ledger) | Git-backed KERI ledger | Accepted | 2026-02-27 |
| [ADR-003](#adr-003-tiered-cache-and-write-contention) | Tiered cache and write-contention mitigation | Accepted | 2026-02-27 |
| [ADR-004](#adr-004-async-executor-protection) | Async executor protection | Accepted | 2026-02-27 |
| [ADR-005](#adr-005-ed25519-only-for-hsm) | Ed25519-only for HSM | Accepted | 2026-03-05 |
| [ADR-006](#adr-006-c2sp-tlog-tiles-transparency-log) | C2SP tlog-tiles transparency log | Accepted | 2026-03-13 |
| [ADR-007](#adr-007-sigstore-rekor-as-bootstrap-transparency-log) | Sigstore Rekor as bootstrap transparency log | Accepted | 2026-04-10 |

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

## ADR-005: Ed25519-only for HSM

**Decision:** The PKCS#11 HSM backend targets Ed25519 exclusively via `CKM_EDDSA`. No P-256 or other curve support is added.

**Context:**

- Apple Secure Enclave only supports P-256 via public CryptoKit APIs (`SecureEnclave.P256`). Ed25519 is used internally by Platform SSO but through private APIs unavailable to third-party developers.
- CryptoKit's `Curve25519.Signing` module is software-only (no Secure Enclave backing).
- AWS CloudHSM, Azure Managed HSM, and Google Cloud KMS support P-256 but not Ed25519 (`CKM_EDDSA`) as of PKCS#11 v2.40.
- Adding P-256 would require changes across every layer: KERI CESR prefix codes, DID:key multicodec, SSHSIG formatting, `auths-verifier`, attestation signing.

**Rationale:**

- No cross-cutting crypto changes — existing KERI events, DIDs, and verification remain untouched.
- Single algorithm path through signing and verification reduces implementation and testing surface.
- Ed25519 advantages preserved: deterministic signatures, small keys (32 bytes), no parameter choices.

**Compatible HSMs:** YubiKey HSM2, Thales Luna, Nitrokey HSM, SoftHSMv2 (testing).

**Trade-offs:**

- Cannot use Apple Secure Enclave (P-256 only via public API).
- Cannot use AWS CloudHSM, Azure Managed HSM, Google Cloud KMS (P-256 only).
- Limits FIPS 140-2 compliance story (NIST curves required by some standards).

**Future path:**

- Multi-curve support epic (est. 3-4 weeks) as prerequisite for P-256 backends.
- Apple Secure Enclave adapter gated behind multi-curve.
- Cloud HSM adapters (AWS CloudHSM, Azure, GCP) also gated behind multi-curve.
- Monitor Apple exposing Ed25519 Secure Enclave APIs publicly (Platform SSO already uses it internally).

## ADR-006: C2SP tlog-tiles transparency log

**Status:** Accepted

**Context:**

KERI Key Event Logs stored in Git (ADR-002) provide per-identity tamper evidence, but they don't answer a global question: "has the registry ever presented different views of the same identity to different parties?" This is the split-view attack — the log operator shows one version of history to the verifier and a different version to the auditor. [Certificate Transparency](https://certificate.transparency.dev/) solved this for TLS with append-only Merkle trees and independent witnesses. Auths needed the same guarantee for identity operations.

Three options were evaluated:

1. **Rekor (Sigstore's log).** Production-proven, but introduces a Sigstore infrastructure dependency and an OIDC trust requirement — contradicting the self-sovereign design.
2. **Custom append-only log.** Full control, but requires designing a tile format, proof serialization, witness protocol, and client caching from scratch.
3. **C2SP tlog-tiles specification.** An open spec on [Tiled Transparency Logs](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) from the C2SP (Cryptographic Specification Project) that defines Merkle tree tiling, checkpoint signed notes, and witness cosignature formats. Already used by Go's `sumdb` and Sigsum.

**Decision:** Implement C2SP tlog-tiles as the `auths-transparency` crate. Use the spec's tile layout, signed note format, and witness cosignature protocol. Build the Merkle tree using [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) hash functions ([SHA-256 with domain-separated leaf/node prefixes](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#merkle-tree)).

**Architecture:**

The crate is split into two feature tiers:

- **No features (WASM-safe):** Core types (`MerkleHash`, `LogOrigin`), Merkle math (`hash_leaf`, `hash_children`, `compute_root`), proof verification (`verify_inclusion`, `verify_consistency`), signed note parsing, tile path encoding. This compiles to WASM for in-browser verification.
- **`native` feature:** `TileStore` trait, `FsTileStore` implementation, `WitnessClient` trait, cosignature collection, offline bundle verification. This runs in the registry server and CLI.

Key types:

```
Checkpoint { origin, size, root, timestamp }
    → SignedCheckpoint { checkpoint, log_signature, log_public_key, witnesses[] }
        → WitnessCosignature { witness_key_id, witness_name, signature, timestamp }

Entry { sequence, entry_type, content, actor_did, timestamp, signature }
    → EntryType: Register | Rotate | DeviceBind | DeviceRevoke | Attest | NamespaceClaim | OrgAddMember | ...
    → EntryContent: typed body specific to each EntryType

InclusionProof { leaf_index, tree_size, hashes[] }
ConsistencyProof { old_size, new_size, hashes[] }
```

The Merkle tree uses tiles — fixed-size blocks of 256 hashes (2^8, per C2SP `TILE_HEIGHT=8`). Tile paths follow C2SP encoding: `tile/{level}/{index}` with 3-digit zero-padded segments. Full tiles are immutable and cached aggressively; partial tiles have short TTLs.

**Witness protocol:**

Witnesses are independent servers that verify checkpoint consistency before cosigning. The protocol:

1. Sequencer produces a new `SignedCheckpoint` after appending entries.
2. Background task fans out `CosignRequest` to configured witness endpoints.
3. Each witness verifies the consistency proof from its last-seen size to the new size.
4. Witnesses return `CosignResponse` with a timestamped Ed25519 cosignature (algorithm byte `0x04`).
5. When quorum is met, the witnessed checkpoint is cached for serving via `GET /v1/log/checkpoint`.

The witness quorum, endpoint list, and per-witness timeout are configurable. Witnesses that fail or timeout are skipped — the system degrades gracefully to log-signed-only checkpoints.

**Entry signing:**

Every mutation to registry state is recorded as a log entry. The sequencer:

1. Receives the entry content and actor signature.
2. Validates the entry (signature, authorization, deduplication).
3. Computes the leaf hash: `SHA-256(0x00 || canonical_json(entry))`.
4. Appends the leaf to the Merkle tree, updates tiles.
5. Signs a new checkpoint over the updated root.
6. Materializes the entry to Postgres for query serving.

Deduplication uses an in-memory LRU cache keyed by `(actor_did, content_hash)` with a 60-second TTL.

**Consequences:**

Positive:
- Split-view attacks are detectable by any party that monitors checkpoints from multiple vantage points.
- The WASM-safe core means browsers can verify inclusion proofs without trusting the server.
- C2SP compatibility means existing tlog tooling (Go's `tlog` package, Sigsum monitors) can audit the Auths log with minimal adaptation.
- Tile-based storage enables efficient CDN caching — full tiles are immutable, so `Cache-Control: immutable` applies.

Negative:
- SHA-256 for Merkle hashing (required by RFC 6962 / C2SP) differs from Blake3 used in KERI SAIDs. Two hash functions in the system, requiring `blake3` and `sha2` crates. That's ~50KB of compiled code, so treating it as negligible bloat.
- The sequencer is a single-writer bottleneck. Horizontal scaling requires a distributed sequencer (future work).
- Witness liveness affects checkpoint freshness but not correctness — a distinction that requires documentation for operators.

**Trade-offs vs. alternatives:**

| | C2SP tlog-tiles (chosen) | Rekor | Custom log |
|---|---|---|---|
| Spec compliance | C2SP, RFC 6962 | Sigstore-specific | None |
| WASM verification | Yes | No (gRPC client) | Depends on impl |
| Infrastructure dependency | None (self-hosted) | Sigstore infra | None |
| Witness protocol | C2SP cosignature | N/A (centralized) | Custom |
| Ecosystem tooling | Go sumdb, Sigsum | Sigstore clients | None |

## ADR-007: Sigstore Rekor as bootstrap transparency log

**Status:** Accepted

**Context:**

Auths needs a witness network. Without one, a malicious registry operator could present different views of the same identity to different parties (the split-view attack). ADR-006 defined the C2SP tlog-tiles format for a self-hosted transparency log, but running your own log requires infrastructure, uptime guarantees, and a witness ecosystem — all overhead that slows a pre-launch project to a crawl.

Meanwhile, Sigstore's Rekor is a production transparency log that has been running since 2021. It's free, public, append-only, and serves millions of entries. Every entry gets an inclusion proof and a signed checkpoint. The catch: it's centralized infrastructure operated by the Linux Foundation. That's philosophically misaligned with auths' decentralized identity model.

**Decision:** Use Sigstore's production Rekor instance (`rekor.sigstore.dev`) as the default transparency log for auths attestations. Implement this as a pluggable adapter (`auths-infra-rekor`) behind the `TransparencyLog` port trait, so it can be swapped out without changing any core or SDK code.

**Why Rekor despite centralization:**

1. **Meet developers where they are.** Sigstore is the de facto standard for software supply chain transparency. Developers already trust it for container signing (cosign), npm provenance, and Python package attestations. An entry in Rekor is immediately auditable with standard tooling (`rekor-cli get`, `cosign verify`).

2. **Bootstrap without infrastructure.** A pre-launch project cannot credibly operate its own witness network. Rekor gives us cryptographic auditability on day one with zero operational cost. Users get the security property (append-only, publicly auditable) without auths needing to run servers.

3. **Trojan horse strategy.** Auths doesn't adopt Sigstore's identity model (no Fulcio, no OIDC, no short-lived certificates). It only uses Rekor as a public append-only log. Auths attestations land in the same log as every other Sigstore entry, making them discoverable and verifiable by the entire ecosystem — but the identity chain is pure KERI, not Sigstore's CA model. We piggyback on their infrastructure while keeping our own trust model.

4. **The port trait makes it reversible.** The `TransparencyLog` trait in `auths-core/src/ports/transparency_log.rs` defines `submit()`, `get_checkpoint()`, `get_inclusion_proof()`, and `get_consistency_proof()`. The Rekor adapter is one implementation. Switching to a self-hosted C2SP log, a Sigsum log, or a future native auths log is a configuration change, not a code change. No core logic depends on Rekor-specific behavior.

**Implementation: `auths-infra-rekor` crate**

The adapter lives in `crates/auths-infra-rekor/` and implements `TransparencyLog` against Rekor's v1 REST API. Key design decisions:

- **DSSE entry type, not hashedrekord.** Rekor's `hashedrekord` requires the signature to verify against SHA-256 of the submitted data. Auths attestation signatures cover the canonicalized attestation content (our protocol), not a bare hash. DSSE (Dead Simple Signing Envelope) wraps the payload and signature together. The signature covers the DSSE PAE (Pre-Authentication Encoding: `"DSSEv1" || len || payloadType || len || payload`), which the adapter computes at signing time while the key is still in scope.

- **SPKI PEM for public keys.** Rekor expects public keys in PEM-encoded SPKI (SubjectPublicKeyInfo) format. The adapter converts raw key bytes to PEM at the submission boundary using the `p256` crate for P-256 keys and a fixed RFC 8410 header for Ed25519. This conversion is isolated to the adapter — internal auths code never sees PEM.

- **P-256 as default curve.** Sigstore's ecosystem is built on ECDSA P-256. Auths' default curve (since the fn-112 epic) is also P-256. This means auths entries in Rekor use the same key type as native Sigstore entries, maximizing interoperability.

- **Checkpoint signature: ECDSA P-256.** Rekor's production shard signs checkpoints with ECDSA P-256 (not Ed25519). The adapter parses C2SP signed note checkpoints and stores the ECDSA signature for verification against the trust config's public key.

- **409 Conflict = idempotent success.** Re-submitting the same attestation returns HTTP 409 with the existing entry. The adapter fetches the existing entry and returns its inclusion proof — no error, no duplicate.

- **Rate limiting surfaces, not retries.** HTTP 429 returns `LogError::RateLimited { retry_after_secs }`. The SDK does not retry — that's a CLI/caller decision. The CLI retries once, then fails with exit code 4.

**Consequences:**

Positive:
- Auths attestations are publicly auditable from day one with zero infrastructure.
- Entries are verifiable by `rekor-cli` and `cosign` — developers can audit auths without installing auths tooling.
- The adapter is ~500 lines of code. The entire Sigstore dependency is one crate behind a trait boundary.

Negative:
- Availability dependency on `rekor.sigstore.dev`. If Rekor is down, `--log sigstore-rekor` fails. Mitigated by `--allow-unlogged` for offline/air-gapped environments.
- Trust dependency on the Linux Foundation's operational security for the Rekor log. A compromised Rekor could present split views — but any party monitoring checkpoints from multiple vantage points would detect it (same threat model as Certificate Transparency).
- DSSE PAE requires the signing key to be available at log submission time. For ephemeral CI keys this is natural; for device-key signing, the user enters their passphrase a second time (or the key is cached in the agent).

**Future path:**
- Self-hosted C2SP tlog-tiles log (ADR-006 implementation) as an alternative backend for organizations that cannot depend on Sigstore.
- Sigsum as a witness network for the self-hosted log (decentralized witnesses, Ed25519).
- `auths trust log add` CLI command to register custom log backends in the trust config.

---

## STRIDE threat model

A comprehensive STRIDE threat analysis covering six trust boundaries (FFI surface, cryptographic enclave, KERI chain integrity, clock/timestamp, tenant namespace, session/Postgres singleton) is maintained as `THREAT-MODEL-001-stride.md`. It documents all controls with code evidence and residual risk ratings.
