# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### KERI spec-compliance follow-ups: attachment persistence + CESR migration + u128 sequences + keripy fixture

Closes the four documented gaps from the prior spec-compliance pass.

- **Attachment persistence (regression fix).** `GitRegistryBackend` now implements `append_signed_event(prefix, event, attachment)` and `get_attachment(prefix, seq)` by refactoring the old `append_event` body into a private `write_event_tree(prefix, event, attachment)` that writes event JSON + tip + state + attachment blob in a single Git commit. `append_event` delegates with an empty attachment for trait back-compat. Every registry-backend signing site in `auths-id` (inception/rotation/initialize) now calls `append_signed_event` with the externalized signature, closing the prior regression where sigs were computed-then-dropped.
- **CESR text-domain attachment format.** `auths_keri::{serialize_attachment, parse_attachment}` now emit and parse CESR `-A##<siger>…` indexed-signature groups via `cesride::{Indexer, Siger}`. Wire format: `-A` counter + 2-char base64url count + each `IndexedSignature` as an 88-char CESR `Siger` body. On-disk attachment path renamed `event.attachments.json` → `event.attachments.cesr`. Old `auths-infra-git::attachment` JSON scaffold deleted. `cesride` flipped from optional to unconditional dep of `auths-keri`.
- **u128 sequence widening.** All sequence fields workspace-wide moved u64 → u128: `KeyState.sequence`, `TipInfo.sequence`, every `ValidationError::*.sequence` payload, `DuplicityEvidence.sequence`, `IndexedIdentity.sequence`, `PinnedIdentity.kel_sequence`, `RotationKeyInfo.sequence`, `RotationResult.sequence`, `NamespaceClaimResult.log_sequence`, `DeviceLinkVerification.seal_sequence`, `InsufficientKelSequence.{have, need}`, `RadicleBridgeRequest.min_kel_seq`, `RegistryError::EventExists.seq`, `SequenceGap.{expected, got}`, `InvalidSequence.{expected, actual}`, `BrokenChain.sequence`. `KeriSequence` API collapsed: deleted `new(u64)` + truncating `value() -> u64`; single pair is `new(u128)` + `value() -> u128`. Trait methods widened: `RegistryBackend::{get_event, visit_events, get_attachment}`, `EventLogReader::read_event_at`, `GitRegistryBackend::get_tip`, `DuplicityDetector::{check_event, has_seen, get_said}`, `WitnessStorage::{record_first_seen, get_first_seen, check_duplicity, create_receipt}`. Pre-launch posture — no compat shim; prior-version `state.json`/`tip.json` blobs won't deserialize.
- **keripy interop fixture seeded.** Generated a real `icp` event via keripy 1.3.4 (Ed25519 single-sig, 299 bytes) and wrote it to `crates/auths-keri/tests/fixtures/keripy/icp.bin`. Un-ignored `fixture_mode_round_trips_icp`. 6/6 `keripy_interop` cases pass — spec-order, hex sequence, no `x` field, version-string byte count, self-addressing AID, and full-byte round-trip.

### KERI spec compliance: externalized signatures + delegated events + u128 hex sequences

- Removed in-body `x` field from all KEL event types (`IcpEvent`, `RotEvent`, `IxnEvent`, `DipEvent`, `DrtEvent`). Signatures externalize via `SignedEvent.signatures: Vec<IndexedSignature>`.
- `DrtEvent` gained `di: Prefix` (KERI §11 delegator identifier). Serialize impl and spec field order updated.
- Delegated events now validate: `validate_delegated_rotation` and `validate_delegated_inception` land, backed by a new `DelegatorKelLookup` trait. `validate_kel_with_lookup(events, lookup)` is the full entry; `validate_kel(events)` is the no-delegation convenience wrapper.
- New error variants: `ValidationError::DelegatorSealNotFound { sequence, delegator_aid }`, `ValidationError::DelegatorLookupMissing { sequence }`.
- Sequence hex-serialization verified at u128 boundary with a 9-case test sweep (0, 9, 10 → "a", 15 → "f", 16 → "10", 255, 256, u64::MAX, u64::MAX+1, u128::MAX).
- Removed the legacy `verify_event_signature` function and `Event::signature()` helper — signatures are verified through `validate_signed_event` on the externalized `SignedEvent` wrapper.
- keripy interop conformance test at `crates/auths-keri/tests/cases/keripy_interop.rs`: spec field order, no `x` in output, hex sequences, version-string byte count matches. Subprocess mode (`KERIPY_INTEROP=1`) invokes `python3 -c "from keri.core.serdering import Serder; …"` when available; fixture mode scaffolded for `tests/fixtures/keripy/icp.bin` once a real keripy output is seeded.
- `GitRegistryBackend::append_signed_event` override that persists attachment blobs in the same commit as the event body. Trait method landed with a default impl; persistence is stubbed.
- Attachment payload migration from the JSON sidecar format to real CESR text-domain `-A##` indexed-signature groups via `cesride`.
- `TipInfo.sequence` / `KeyState.sequence` / `ValidationError.sequence` widening to u128 — would flip the remaining `KeriSequence::new(u64)` / `value() -> u64` call sites to the u128 pathway.
- Seeding a real keripy fixture to activate `fixture_mode_round_trips_icp`.

### Curve-agnostic refactor Round 2 (fn-116) + fn-115 follow-up

- **Witness server** (`crates/auths-core/src/witness/server.rs`) — P-256 witnesses now supported end-to-end. `WitnessServerInner.{seed, public_key}` replaced with `signer: TypedSignerKey` (curve-tagged); `WitnessServerConfig::with_generated_keypair(db_path, curve: CurveType)` accepts curve parameter; DID derivation uses `auths_crypto::{ed25519,p256}_pubkey_to_did_key` per curve (no more `z6Mk` hardcode). CLI layer defaults to P-256 witnesses.
- **KERI event-submission validator** now parses `k[0]` via `KeriPublicKey::parse` (CESR-aware); dispatches signature verify on parsed curve. Hex-encoded `k[0]` retained as legacy back-compat branch for Ed25519-only.
- **CESR strict parser** — `KeriPublicKey::parse` rejects legacy `1AAJ` P-256 verkey prefix (CESR spec's `1AAJ` is the P-256 *signature* code, not a verkey code). `1AAI` is the only accepted P-256 verkey prefix. Pre-launch posture — no on-disk v1 identities to protect.
- **Typed newtypes** for non-signing 32-byte fields:
  - `auths_crypto::Hash256` (re-exported via `auths_verifier::Hash256`) for content digests. `ApprovalAttestation.request_hash` migrated.
  - `auths_pairing_protocol::X25519PublicKey` for X25519 ECDH keys. `CompletedPairing.initiator_x25519_pub` migrated.
  - Both use `#[serde(transparent)]` — byte-identical wire format.
- **`SeedSignerKey`** now holds `DevicePublicKey` + `curve: CurveType` instead of `[u8; 32]`. Sign path dispatches via `TypedSignerKey::sign` (curve-aware).
- **`RotationSigner` type alias deleted** — all workspace callers migrated to `TypedSignerKey`.
- **`did_key_to_ed25519` and `ed25519_to_did_key` wrappers deleted** from `auths_id::identity::resolve`. Callers use `auths_crypto::did_key_decode` + `DecodedDidKey` variants. Deny-list entry removed from all 7 `clippy.toml` files.
- **`ED25519_PUBLIC_KEY_LEN`** no longer used outside `auths_crypto` — `wasm.rs` migrated to `CurveType::from_public_key_len` for curve-aware length validation.
- **Doc comment sweep** — `auths-core/src/ports/{network,transparency_log}` and `packages/auths-python` docstrings updated to not claim Ed25519-specificity in curve-agnostic functions.
- **Pairing-protocol test helper** — `generate_ed25519_keypair_sync` no longer byte-slices ring PKCS8 internals; routes through `auths_crypto::parse_key_material` (curve-detecting).

### SSH P-256 wire format (fn-117)

- **RFC 5656 `ecdsa-sha2-nistp256` SSH support landed.** Agent-mode signing, `add_identity`, `request_identities`, `sign`, `remove_identity`, OpenSSH PEM export (`export_key_openssh_pem`), and `.pub` line export (`export_key_openssh_pub`) all curve-dispatch. `SeedSignerKey::kind()` reports the correct `SshAlgorithm::Ecdsa { curve: NistP256 }` for P-256 seeds; `SeedSignerKey::sign()` produces DER-encoded `(r, s)` signatures via `typed_sign`.
- **`AgentError::P256SshUnsupported` variant deleted** (was error code `AUTHS-E3026`, introduced in fn-116.18 as a loud-fail placeholder). P-256 identities now work with the SSH agent flow with no caller-visible errors.
- **`AgentCore` stores curve alongside seed** (`StoredKey { seed, curve }`) so the sign path dispatches on the curve of the key that was registered — no more inference from public-key length.
- **macOS system agent registration** (`register_keys_with_macos_agent_with_handle`) propagates curve through to PEM conversion; both Ed25519 and P-256 keys can be `ssh-add`ed via the platform agent.

### Deferred follow-up (tracked in `.flow/fn-114-dirty-crates.txt`)

- `TypedSignature` enum graduation (variant-per-curve) — deferred. Current newtype covers the 64-byte coincidence (Ed25519 = P-256 r||s). Full enum becomes load-bearing when a curve with a different signature length arrives (ML-DSA-44 = 2420 bytes).
- B3 typed-wrapper sweep (`Ed25519PublicKey` / `Ed25519Signature` struct fields across ~20 production files) — deferred alongside the enum graduation.
- Per-site migration of remaining banned-API call sites across production crates. Workspace clippy green via the crate-level transitional allows that fn-115 was scoped to remove.

### Removed

- **xtask:** Removed `cargo xt ci-setup`. Use `auths ci setup` (or `just ci-setup`) instead.

### Added (Unified Python SDK)

- **`auths-python`: Unified Python SDK package** — consolidated `auths-verifier-python` and `auths-agent-python` into a single `packages/auths-python` crate. Shared FFI runtime, module registration, and type definitions in `src/runtime.rs` and `src/types.rs`.
- **`auths-python`: `Auths` client class** — Stripe-style client with `repo_path` and `passphrase` constructor, resource services (`auths.identities`, `auths.devices`), and typed error hierarchy (`AuthsError`, `CryptoError`, `KeychainError`, `StorageError`, `NetworkError`, `IdentityError`, `VerificationError`).
- **`auths-python`: Identity lifecycle FFI** — `create_identity`, `provision_agent`, `link_device_to_identity`, `revoke_device_from_identity` Rust FFI functions with PyO3 bindings. `IdentityService` and `DeviceService` resource classes expose these as `auths.identities.create()`, `auths.identities.provision_agent()`, `auths.devices.link()`, `auths.devices.revoke()`.
- **`auths-python`: Keychain-backed signing** — `sign_as_identity` and `sign_action_as_identity` FFI functions resolve DID-or-alias to a keychain key and sign bytes or action envelopes. Exposed as `auths.sign_as()` and `auths.sign_action_as()`.
- **`auths-python`: Capability-scoped verification** — `verify_attestation_with_capability` and `verify_chain_with_capability` FFI functions. Python wrappers on the `Auths` client.
- **`auths-python`: Getting Started README** — quickstart example covering identity creation, device linking, signing, and verification.

### Added (Python SDK Advanced Lifecycle)

- **`auths-python`: Time-pinned verification** — `verify_at_time` and `verify_at_time_with_capability` FFI functions accept an ISO 8601 timestamp string, enabling "was this valid at time T?" queries for audit and compliance.
- **`auths-python`: Witness chain verification** — `verify_chain_with_witnesses` FFI function accepts witness receipts, threshold, and public keys for k-of-n quorum verification.
- **`auths-python`: Key rotation** — `rotate_identity_ffi` FFI function and `auths.identities.rotate()` Python method. `IdentityRotationResult` dataclass with `controller_did`, `new_key_fingerprint`, `previous_key_fingerprint`, `sequence`.
- **`auths-python`: Device authorization extension** — `extend_device_authorization_ffi` FFI function and `auths.devices.extend()` Python method. `DeviceExtension` dataclass.
- **`auths-python`: Attestation query service** — `list_attestations`, `list_attestations_by_device`, `get_latest_attestation` FFI functions. `AttestationService` resource class with `auths.attestations.list()`, `auths.attestations.by_device()`, `auths.attestations.latest()`.
- **`auths-python`: Artifact attestation signing** — `sign_artifact` and `sign_artifact_bytes` FFI functions. `auths.sign_artifact()` and `auths.sign_artifact_bytes()` Python methods. `ArtifactSigningResult` dataclass.
- **`auths-python`: Git commit signing** — `sign_commit` FFI function and `auths.sign_commit()` Python method. `CommitSigningResult` dataclass.
- **`auths-python`: Policy engine** — `compile_policy` FFI function, `PyCompiledPolicy` and `PyEvalContext` classes. `PolicyBuilder` fluent API for constructing policies in Python.
- **`auths-python`: JWT validation** — `AuthsClaims` dataclass and JWKS client helper for validating Auths-issued JWTs.

### Changed (Semantic Naming Consistency)

- **`auths-sdk`: Identity creation function renames** — `setup_developer()` → `create_developer_identity()`, `quick_setup()` → `create_developer_identity_quick()`, `setup_ci()` → `create_ci_identity()`, `setup_agent()` → `create_agent_identity()`, `build_agent_proposal()` → `build_agent_identity_proposal()`. Naming now conveys identity lifecycle semantics ("create" = inception) rather than generic "setup".
- **`auths-sdk`: Config type renames** — `DeveloperSetupConfig` → `CreateDeveloperIdentityConfig`, `CiSetupConfig` → `CreateCiIdentityConfig`, `AgentSetupConfig` → `CreateAgentIdentityConfig` (with corresponding builder renames).
- **`auths-sdk`: Result type renames** — `SetupResult` → `CreateIdentityResult`, `CiSetupResult` → `CreateCiIdentityResult`, `AgentSetupResult` → `CreateAgentIdentityResult`.
- **`auths-sdk`: Rotation type renames** — `RotationConfig` → `IdentityRotationConfig`, `RotationResult` → `IdentityRotationResult`. Clarifies these operate on KERI identities (`did:keri:`), not device keys.
- **`auths-python`: Agent operation split** — `provision_agent()` replaced with two distinct operations: `create_agent_identity()` (standalone `did:keri:` identity) and `delegate_agent()` (delegated `did:key:` under a parent). Python API: `auths.identities.create_agent()` and `auths.identities.delegate_agent()`.
- **`auths-python`: `Agent` dataclass replaced** — split into `AgentIdentity` (standalone, `did:keri:`) and `DelegatedAgent` (delegated, `did:key:`).
- **`auths-python`: `Identity.public_key` → `Identity.key_alias`** — field name now matches the Rust SDK terminology.
- **`auths-python`: `RotationResult` → `IdentityRotationResult`** — consistent with Rust SDK rename.
- **`auths-cli`: Updated call sites** — `init.rs` and `id/identity.rs` updated to use renamed SDK functions and types.

## [0.0.1-rc.4] - 2026-03-04

### Changed

- **`auths-core`: SSH agent abstracted behind `SshAgentPort` trait** — `Command::new("ssh-add")` subprocess calls extracted from `runtime.rs` into a new `ports::ssh_agent` module with `SshAgentPort` trait and `SshAgentError` typed error. `MacOsSshAgentAdapter` in `auths-cli` implements the trait. Enables testing and alternative SSH agent backends without subprocess shell-outs.
- **`auths-core`/`auths-sdk`: `#![deny(clippy::unwrap_used, clippy::expect_used)]` enforced** — all `unwrap()`/`expect()` calls in production code replaced with proper error propagation (`?`, `map_err`, `unwrap_or_else` for poisoned mutexes). `allow-unwrap-in-tests` and `allow-expect-in-tests` set in `.clippy.toml` to preserve test ergonomics. `witness/server.rs` `create_receipt` and `sign_payload` now return `Result` instead of panicking.
- **`auths-core`: `CommitSigningContext` dependency struct** — lightweight struct holding `key_storage`, `passphrase_provider`, and `agent_signing` trait objects, replacing scattered parameter passing in the signing pipeline.

### Fixed

- **CI: `Cargo.lock` now committed** — the blanket `*.lock` gitignore pattern was preventing `Cargo.lock` from being tracked, causing `cargo audit` in CI to fail. Replaced with specific JS lock file patterns (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
- **CI: Platform-gated dead code in `passphrase_cache.rs`** — `PASSPHRASE_SERVICE`, `encode_secret`, and `decode_secret` now gated with `#[cfg(any(target_os = "macos", ...))]` to eliminate dead-code warnings on Linux CI builds.

## [0.0.1-rc.2] to [0.0.1-rc.3] - 2026-03-04

> These releases were bumped while resolving circular dev-dependency cycles that blocked `cargo publish --workspace`. Key fixes: distributed the `auths-test-utils` monolith into per-crate `test-utils` features, removed the `auths-infra-git` upward dev-dependency from `auths-id`, and moved git-storage implementations from `auths-id` to `auths-storage`. See `docs/plans/dependency-architecture-refactor.md` for full details.

## [0.0.1-rc.1] - 2026-03-04

### Added

- **`auths-crypto`: `CryptoProvider` trait and native/WASM abstraction** — new async `CryptoProvider` trait abstracting Ed25519 operations (sign, verify, generate keypair, derive public key from seed). `RingCryptoProvider` implements the trait for native targets using `ring`. `WebCryptoProvider` stub scaffolded for `wasm32` targets. Feature-gated: `native` enables ring+tokio, `wasm` enables the WASM path. `SecureSeed` (zeroize-on-drop) is now the canonical key representation across all crates.
- **`auths-crypto`: `key_material` module** — canonical key parsing functions (`parse_ed25519_seed`, `parse_ed25519_key_material`, `build_ed25519_pkcs8_v2`) consolidated from scattered implementations across auths-core and auths-cli.
- **`auths-test-utils`: `MockCryptoProvider`** — deterministic mock for testing crypto operations without ring dependency.

- **Type Safety Audit** — comprehensive replacement of stringly-typed fields with semantic newtypes across the entire workspace:
  - `auths-verifier`: Added `ResourceId` and `Role` newtypes; `Ed25519PublicKey` newtype replacing `Vec<u8>` (32-byte fixed array, `Copy`); `Ed25519Signature` newtype replacing `Vec<u8>` (64-byte fixed array)
  - `auths-id`: Added `SealType` enum, `KeriSequence` newtype (wraps `u64`), `GitRef`/`BlobName` newtypes for storage layout; typed witness and receipt fields
  - `auths-verifier`: `BridgeError` and `VerifyResult` now use structured reason enums instead of opaque strings
  - `auths-core`: `ResolvedDid` converted from struct+`DidMethod` enum to a two-variant enum (`Key`/`Keri`) with accessor methods; `DidMethod` deleted. Same pattern applied to `ResolvedIdentity` in network ports
  - `auths-sdk`: `SetupParams`, `DeviceRegistration`, `SigningConfig` fields use `IdentityDID`, `DeviceDID`, `Vec<Capability>` instead of `String`/`Vec<String>`
  - `auths-id`: `StoredIdentityData.controller_did`, `AgentIdentityBundle.agent_did` → `IdentityDID`; `MemberView` fields → `Role`, `Vec<Capability>`, `IdentityDID`, `ResourceId`; `MemberFilter` → `HashSet<Role>`/`HashSet<Capability>`; `MemberInvalidReason` fields → `DeviceDID`/`IdentityDID`; `OrgMemberEntry.org` → `IdentityDID`
  - `auths-core`: Added `Base64UrlEncoded` newtype for pairing types with `encode()`/`decode()`/`Deref<Target=str>`/`#[serde(transparent)]`/`JsonSchema`; `CreateSessionRequest.ephemeral_pubkey` → `Base64UrlEncoded`; `SubmitResponseRequest` fields → `Base64UrlEncoded`/`DeviceDID`
  - All newtypes use `#[serde(transparent)]` — wire format unchanged, zero migration needed

### Changed

- **`auths-verifier`: Refactored to use `CryptoProvider`** — all Ed25519 verification now routes through the `CryptoProvider` trait instead of calling `ring` directly. `ring` is feature-gated behind `native` (default). WASM builds use `--no-default-features --features wasm` to avoid pulling tokio/ring.
- **`auths-core`: Removed `ring` from production dependencies** — `ring` moved to dev-dependencies (test-only). All production crypto operations route through `auths-crypto::CryptoProvider` via a sync bridge (`provider_bridge.rs`). Key storage changed from raw PKCS#8 bytes to `SecureSeed`.
- **`auths-core`: `AgentCore` keys stored as `SecureSeed`** — `HashMap<Vec<u8>, SecureSeed>` replaces previous `Zeroizing<Vec<u8>>` storage. PKCS#8 bytes rebuilt on-demand via `build_ed25519_pkcs8_v2` when needed for macOS agent registration.

- **`auths-registry-server`:** Stripe integration and api endpoints.
- **`auths-registry-server`: Repo-per-tenant isolation** — introduced a `TenantResolver` port trait with two adapters: `SingleTenantResolver` (existing single-tenant deployments, unchanged behaviour) and `FilesystemTenantResolver` (multi-tenant SaaS, one Git repository per tenant under `{base}/tenants/{id}/`). `FilesystemTenantResolver` caches open `PackedRegistryBackend` instances in a bounded moka LRU cache (capacity configurable); errors are never cached. `invalidate(tenant_id)` and `invalidate_all()` allow callers to evict stale entries after suspension or deprovisioning. Path traversal is blocked via `canonicalize` of the tenants root followed by a `starts_with` check on the computed tenant path (symlink hardening). A `TenancyModeKind` enum (`Single` / `Multi`) is exposed by every resolver so middleware can gate multi-tenant routes without reaching into config. All existing routes are re-mounted under `/v1/t/:tenant_id` via a `TenantBackend` axum extractor; single-tenant mode routes continue to work as before. `POST /v1/admin/tenants` provisions a new tenant registry; the endpoint is idempotent — first provisioning returns `201 Created`, subsequent calls return `200 OK` with `"already_provisioned"`. The endpoint is protected by `RequireAdminToken` (strict `Bearer ` prefix parsing, constant-time token comparison, `501 Not Implemented` when no admin token is configured). ADR-001 (`docs/adr/ADR-001-repo-per-tenant-isolation.md`) documents the design decisions and rejected alternatives. Edge cases covered in `tests/cases/tenant_http.rs`: reserved tenant IDs → 400, unknown tenant → 404, single-tenant mode rejects `/v1/t/...` → 404, bad/missing admin token → 401/501, moka cache eviction and re-resolution correctness.
- **`auths-index`: `identities` and `org_members` SQLite tables** — new schema tables with WAL mode. `IndexedIdentity` (prefix, current keys, sequence, tip SAID) and `IndexedOrgMember` (org/member/issuer DIDs, rid, revoked/expires timestamps) types with `upsert_*`, `query_identity`, and `list_org_members_indexed` methods.
- **`auths-id`: `rebuild_identities_from_registry` and `rebuild_org_members_from_registry`** — free functions (feature: `indexed-storage`) that walk the packed Git registry and repopulate a fresh `AttestationIndex`, enabling full index reconstruction from Git without downtime.
- **`auths-oidc-bridge`: GitHub Actions OIDC cross-reference (`github-oidc` feature)** — new `github_oidc` module fetches GitHub's JWKS, validates RS256 tokens, and extracts actor/repository claims. `JwksClient` implements in-memory caching with configurable TTL, `tokio::sync::Mutex`-based request coalescing (thundering herd protection), circuit breaker (5 failures → 60s cooldown), exponential backoff with jitter, and stale-cache fallback on fetch failure.
- **`auths-oidc-bridge`: Actor cross-reference module** — `cross_reference.rs` verifies the GitHub `actor` claim matches the expected KERI identity holder before JWT issuance, creating a two-factor proof (KERI chain + CI/CD environment).
- **`auths-oidc-bridge`: AWS STS integration tests** — `tests/aws_integration.rs` with real `AssumeRoleWithWebIdentity` test (requires `AWS_ROLE_ARN` + `AUTHS_BRIDGE_URL` env vars) and LocalStack fallback test. Both `#[ignore]` by default for CI safety.
- **`auths-oidc-bridge`: `claims_supported` in OpenID Configuration** — `/.well-known/openid-configuration` now includes the full list of supported JWT claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `keri_prefix`, `capabilities`, `witness_quorum`, `github_actor`, `github_repository`).
- **`docs/oidc-enterprise-guide.md`** — enterprise security documentation covering trust boundaries, STRIDE threat model (8 attack vectors), key rotation procedure (90-day cadence), Break Glass incident response playbook (<15 min RTO), AWS IAM integration guide, Terraform and CloudFormation IaC templates, and GitHub Actions workflow examples.

### Changed

- **`auths-registry-server`: Migrated pairing and tenant metadata stores from SQLite to PostgreSQL** — `SqlitePairingStore` and `SqliteTenantMetadataStore` and their `rusqlite` dependency have been removed. Replaced by `PostgresPairingStore` and `PostgresTenantMetadataStore` backed by sqlx 0.8 with compile-time query verification. Both `PairingStore` and `TenantMetadataStore` traits are now fully async via `async-trait`. Schema managed via sqlx migrations (`migrations/001_pairing_sessions.sql`, `migrations/002_tenant_metadata.sql`). A single shared `PgPool` (max 10 connections) is injected into both stores at startup; set `REGISTRY_POSTGRES_URL` to a PostgreSQL connection string. sqlx offline query cache (`.sqlx/`) committed for builds without a live database (`SQLX_OFFLINE=true`).

- **`auths-cli`: `setup` renamed to `init`; `status` promoted to primary surface** — `auths setup` is now `auths init` (same profiles: `developer`, `ci`, `agent`). `auths status` is now a top-level command alongside `init`, `sign`, and `verify` instead of living under `auths advanced`. Witness flags (`--witness`, `--witness-threshold`, `--witness-policy`) are removed from the onboarding path; use `auths advanced witness` for witness management.
- **`auths-cli`: `auths advanced` nesting removed** — all subcommands are now top-level: `auths device`, `auths id`, `auths key`, `auths policy`, `auths emergency`, etc. The `auths advanced <cmd>` prefix no longer exists. `auths --help` still shows only the four primary commands; the rest are discoverable via `auths <cmd> --help`.

- **`auths-oidc-bridge`: Exchange handler refactored for composable validation** — `token_exchange` handler now performs GitHub cross-reference as a decoupled pre-step (SRP) before calling `OidcIssuer::exchange()`. Structured tracing events emitted for every exchange: `auths.exchange.github_cross_reference.success`, `.failure`, and `keri_only`. `exchange()` accepts an optional `CrossReferenceResult` to populate `github_actor` and `github_repository` claims in the minted JWT.
- **`auths-oidc-bridge`: `ExchangeRequest` expanded** — accepts optional `github_oidc_token` and `github_actor` fields (feature-gated behind `github-oidc`).
- **`auths-oidc-bridge`: `BridgeConfig` expanded** — new fields `github_oidc_issuer`, `github_expected_audience`, and `github_jwks_cache_ttl_secs` for GitHub OIDC configuration.
- **`auths-index`: Renamed `rebuild_from_git` → `rebuild_attestations_from_git`** — updated all callers in `auths-id` and `auths-cli`.
- **`auths-id`: `PackedRegistryBackend` now wires SQLite index writes on every mutation** — `store_attestation`, `store_org_member`, and `append_event` perform best-effort write-through to `Arc<Mutex<AttestationIndex>>` (feature-gated: `indexed-storage`). Index is best-effort; Git remains the source of truth.
- **`auths-id`: `list_org_members_fast` added to `RegistryBackend` trait** — default delegates to `list_org_members`; `PackedRegistryBackend` override uses the SQLite index for O(1) lookups, falling back to Git when the index is empty or a capability filter requires full attestation data.
- **`auths-id`: Replaced redb cache with Redis-backed tiered storage** — removed the embedded `redb` read-through cache (`RegistryCache`) from `PackedRegistryBackend`. Identity resolution now uses a two-tier architecture: Tier 0 (Redis) for sub-millisecond cached lookups and Tier 1 (Git) as the persistent cryptographic ledger. New `auths-cache` crate implements `TierZeroCache` (Redis via `bb8` pool) and `TierOneArchive` (Git via `spawn_blocking`), orchestrated by a `TieredResolver` using Cache-Aside reads and Write-Through writes with a background `ArchivalWorker`. Failed Git writes route to a Redis Stream dead letter queue to protect KERI hash chain integrity. Redis is optional — when `AUTHS_REDIS_URL` is not set, the system falls back to direct Git reads.
- **`auths-sdk`/`auths-cli`: Extracted business logic from CLI to SDK** — signing pipeline (`sign_artifact`, `validate_freeze_state`), device pairing orchestration (`validate_short_code`, `verify_device_did`, `create_pairing_attestation`), git audit engine (`AuditWorkflow` + `GitLogProvider` port), artifact digest abstraction (`ArtifactSource` port + `LocalFileArtifact` adapter), system diagnostics (`DiagnosticProvider` port), SSH crypto ops, and capability parsing all moved behind trait-based ports in `auths-sdk`. CLI is now a thin presentation layer delegating to SDK workflows.
- **`auths-core`: `EnvironmentConfig` / `KeychainConfig`** — new structs that collect all environment-variable reads (`AUTHS_KEYCHAIN_BACKEND`, `AUTHS_HOME`, `AUTHS_KEYCHAIN_FILE`, `AUTHS_PASSPHRASE`) at the process boundary. `get_platform_keychain_with_config()` and `auths_home_with_config()` replace zero-argument functions that read env vars internally. `EnvironmentConfig::from_env()` is the single permitted I/O site; all downstream logic receives the config by value. Eliminates hidden I/O coupling and makes the keychain backend fully injectable for tests.
- **`auths-core`: `ClockProvider` trait and `SystemClock` / `MockClock` implementations** — abstracts `Utc::now()` calls across `auths-sdk` (setup, device, pairing, signing, rotation), `auths-id`, and `auths-verifier`. `MockClock` in `auths-test-utils` enables deterministic time in tests without `unsafe` env-var mutation.
- **Clock injection completed (Epic 2)** — zero `Utc::now()` calls remain in `auths-core/src/` or `auths-id/src/` outside `#[cfg(test)]`. All time-sensitive functions (`create_signed_attestation`, `verify_with_resolver`, `extend_expiration`, `try_incremental_validation`, `provision_agent_identity`, `resolve_trust`, `PairingToken::generate*`, `WitnessStorage::store_receipt`, `GitKel::get_state`, `RegistryMetadata::new`) accept `now: DateTime<Utc>` as an explicit parameter. `auths-sdk` passes `clock.now()`; CLI passes `Utc::now()` at the presentation boundary.
- **`auths-core`: `EventSink` telemetry port** — new `EventSink` trait decouples structured event emission from stdout. `StdoutSink` (async MPSC worker, non-blocking `emit()`, blocking `flush()`) and `MemorySink` (in-process test capture) are the two provided implementations. `init_telemetry()` / `init_telemetry_with_sink()` set the global sink once at startup. `DROPPED_AUDIT_EVENTS` counter surfaces backpressure in the SIEM pipeline.
- **`auths-sdk`: `GitConfigProvider` port trait** — `set(key, value)` abstraction removes `std::process::Command::new("git")` and `which::which` from `auths-sdk`. `SystemGitConfigProvider` in `auths-cli` implements the trait via the system `git` binary. `DeveloperSetupConfig` gains an optional `sign_binary_path` field; the CLI resolves the path via `which::which("auths-sign")` and passes it at the presentation boundary.
- **`auths-sdk`: `SdkStorageError` typed enum** — replaces `anyhow::Error` in `SetupError::StorageError` and `DeviceError::StorageError`. `RegistrationError::NetworkError` now wraps `auths_core::ports::network::NetworkError` (typed). `RegistrationError::LocalDataError` carries a `String`. `map_storage_err()` and `map_device_storage_err()` helper functions removed; callers use inline `.map_err(|e| ...StorageError(SdkStorageError::OperationFailed(e.to_string())))`. `anyhow` removed from `auths-sdk/Cargo.toml`.

---

> Note: notes on release `0.0.1-rc.11` and prior come from an earlier repository that (a) lived on the my personal account and (b) included crates that have since been stripped out. I've decided to leave them intact for documenting the development.

## [0.0.1-rc.11] - 2026-02-18

### Changed

- **`auths-auth-server`: Migrated session store from SQLite to PostgreSQL** — `SqliteSessionStore` and its `rusqlite` dependency have been removed (hard cut, no backward compatibility). Replaced by `PostgresSessionStore` (`crates/auths-auth-server/src/adapters/postgres_session_store.rs`) backed by sqlx 0.8 with compile-time query verification. Schema managed via sqlx migrations (`migrations/001_init.sql`). The `SessionStore` trait is now fully async via `async-trait`, making it dyn-compatible as `Box<dyn SessionStore>`. Set `DATABASE_URL` to a PostgreSQL connection string to enable; falls back to `InMemorySessionStore` when unset. sqlx offline query cache (`.sqlx/`) committed for builds without a live database (`SQLX_OFFLINE=true`).

### Security

- **`auths-auth-server`: Atomic CAS nonce invalidation in `verify_auth`** — `SessionStore::update_status` now takes `from` + `to` parameters and returns `Ok(bool)`. `SqliteSessionStore` uses `UPDATE … WHERE status = ?` (evaluated atomically by SQLite); `InMemorySessionStore` uses `std::mem::discriminant` comparison inside its write lock. Concurrent requests racing to verify the same session now get exactly one `200 OK`; the rest receive `409 CONFLICT` (`SessionAlreadyVerified`). Also adds `PRAGMA synchronous=NORMAL` alongside WAL mode.

### Added

- **`auths setup --profile developer`: Step 6/6 — signing pipeline verification** — after git config, runs a test commit in a throwaway temp repo to confirm `auths-sign` is wired end-to-end. Reports `Skipped` gracefully if `auths-sign` is not yet on PATH.
- **`UnifiedPassphraseProvider` (`auths-core`):** New passphrase provider that prompts exactly once regardless of how many distinct prompt messages are presented. Used in `auths device link` so the entire link operation requires only one passphrase entry instead of two.
- **`auths doctor`: exact runnable fix commands** — all suggestion strings now start with `Run:` and are copy-pasteable. `check_git_signing_config` expanded from checking only `gpg.format` to all 5 required signing configs (`gpg.format`,`commit.gpgsign`, `tag.gpgsign`, `user.signingkey`, `gpg.ssh.program`).
- **`auths-cli` README: CI setup section** — copy-pasteable GitHub Actions workflows for signed commits (`auths setup --profile ci`) and commit signature verification (`auths verify-commit HEAD`).
- **`LocalGitResolver` for air-gapped identity resolution (`auths-auth-server`):** New adapter reads KERI key state directly from a local git registry (`refs/auths/registry`) via `PackedRegistryBackend`, requiring zero network access. Eliminates the single point of failure from `RegistryIdentityResolver` requiring a live HTTP endpoint.
- **`ResolverMode` config enum (`auths-auth-server`):** `AuthServerConfig.registry_url: String` replaced with `resolver_mode: ResolverMode` (`RegistryHttp { url }` | `LocalGit { repo_path }`). Builder methods: `with_registry_url()` and `with_local_git_resolver()`.
- **`AUTH_SERVER_LOCAL_GIT_REPO` env var (`auths-auth-server`):** When set, the server uses `LocalGitResolver` backed by the given path instead of the HTTP registry. Overrides `AUTH_SERVER_REGISTRY_URL` if both are set.
- **Air-gapped integration tests (`auths-auth-server`):** `tests/air_gapped.rs` covers full auth flow, unknown-DID rejection, and wrong-key rejection using a temp-dir git repo — no registry server needed.

- **Bundle TTL:** `IdentityBundle` now requires `bundle_timestamp` and `max_valid_for_secs` fields. Bundles fail verification once stale, preventing revoked keys from passing CI indefinitely.
- `auths id export-bundle` gains a required `--max-age-secs` flag to set bundle TTL at export time.
- New `AttestationError::BundleExpired` variant (`AUTHS_BUNDLE_EXPIRED`) with a re-export suggestion.
- GitHub Action enforces bundle age before invoking CLI verification.

### Fixed

- **PKCS#8 magic offset removed from `extract_seed_from_pkcs8`** — replaced the brittle `key_bytes[16..48]` fallback with a direct `PrivateKeyInfo::from_der` call and an exhaustive slice-pattern match on inner key bytes. Handles both the RFC 8410 DER OCTET STRING wrapping (`04 20 <seed>`) that ring produces and bare 32-byte seeds. Fails loudly with a descriptive error on unexpected formats.
- **`auths verify-commit` always failing with empty error** — `ssh-keygen -Y verify -I "*"` does not treat `*` as a wildcard; it searches for a literal `*` entry in the allowed_signers file. Fixed by running `find-principals` first to resolve the actual signer identity, then passing it to `verify`. Also fixed error capture: `ssh-keygen` writes `"Could not verify signature."` to stdout, not stderr.

> **TODO:** Cut a new release (`v0.0.1-rc.12`) so CI downloads the fixed binary and commit verification passes in GitHub Actions.

## [0.0.1-rc.10] - 2026-02-18

### Added

- Support for homebrew install via `brew install auths-dev/auths-cli/auths`

## [0.0.1-rc.8] to [0.0.1-rc.9] - 2026-02-17

> Note: these releases were a series of trial and error to get homebrew install working, which required several quick releases with nominal changes to configurations.

## [0.0.1-rc.7] - 2026-02-17

> Note: these releases were a series of trial and error to get homebrew install working, which required several quick releases with nominal changes to configurations.

### Added

- Improved CLI error messages with actionable suggestions.
- New `auths doctor` command to diagnose setup issues.
- **ci:** Release workflow builds a native `auths` binary on the host and signs release artifacts using a device-only key from the encrypted CI keychain (`AUTHS_CI_KEYCHAIN`), with no identity/root key present in CI. `.auths.json` attestation files are included in the release upload.
- **xtask:** New `xtask` workspace crate (`publish = false`) replaces the 187-line shell `ci-setup` recipe in the justfile. Uses the idiomatic Rust xtask pattern for project-internal CI tooling. Invokable via `cargo xt ci-setup` or `just ci-setup`.
- **xtask:** Native base64 encoding (`base64` crate) eliminates the macOS `base64` 76-char line-wrapping bug that caused `base64: invalid input` on Linux CI runners.
- **xtask:** `TempDir`-based cleanup replaces manual `rm -f` — seed and keychain temp files are cleaned up automatically even on error.
- **xtask:** Passphrase prompting via `rpassword` — passphrase never appears in process arguments (unlike shell `read -s` piped through variable expansion).
- **xtask:** `GH_TOKEN`/`GITHUB_TOKEN` env vars are cleared via `env_remove()` on every `gh` invocation, fixing the silent auth failure when a stale token overrides the keyring account.
- **xtask:** Native tar/gzip archiving with `tar`+`flate2`+`walkdir` crates — excludes `*.sock` files, no `rsync` dependency.
- **docs:** adds docs on GitHub action and tarball signing workflows.
- **docs:** adds commit signing troubleshooting guide covering agent, keychain, and git config issues.
- **auths-cli:** New `auths key copy-backend` subcommand — copies a key from the current keychain backend to a file-based keychain without exposing raw key material. Accepts `--dst-backend`, `--dst-file`, and `--dst-passphrase` (or `AUTHS_PASSPHRASE` env var). Replaces the fragile PEM-export → seed-parse → re-import pipeline previously used by `just ci-setup`.

### Fixed

- **auths-core:** Implement `add_identity`, `remove_identity`, and `remove_all_identities` on the SSH agent session. Previously the agent rejected all key-loading requests with `UnsupportedCommand`, making `auths agent unlock` fail and breaking Git commit signing via the agent.
- **auths-cli:** `auths-sign` Tier 2 keychain failure no longer causes an early return. When keychain or passphrase prompts fail (common in subprocess contexts), the error message now includes actionable instructions to start the agent and unlock the key.
- **ci:** Fix WASM build check — qualify feature with package name (`--features auths_verifier/wasm`) as required by Rust 1.93 / resolver 3 when running from a workspace root.
- **ci:** Fix Windows build — gate `agent::client` module and all consumers behind `#[cfg(unix)]` since `std::os::unix::net::UnixStream` does not exist on Windows.
- **ci:** Fix `cargo test` invocation — split `--doc` into a separate step because cargo cannot mix `--doc` with `--lib`/`--bins` target selectors.
- **auths-core:** `AUTHS_KEYCHAIN_FILE` env var is now implemented — the file keychain backend uses the specified path instead of the default `~/.auths/keys.enc`.
- **auths-core:** `AUTHS_PASSPHRASE` env var is now wired to the file keychain password, enabling fully headless CI artifact signing without interactive prompts.
- **auths-core:** `EncryptedFileStorage::get_password()` now falls back to the `AUTHS_PASSPHRASE` environment variable when no password has been set via `set_password()`. This fixes a "Missing Passphrase" error that occurred when a new `EncryptedFileStorage` instance was created after the initial one had the password wired in.
- **release.yml:** Homebrew step secrets error secrets is only valid inside `${{ }}` interpolation, not as a bare named value in `if:` expressions. Solution: expose a boolean `HAS_HOMEBREW_TOKEN` env var at the job level (where `${{ }}` is valid), then gate the step on `env.HAS_HOMEBREW_TOKEN == 'true'`.

### Changed

- **auths-verifier:** `identity_signature` on `Attestation` is now optional — serialized with `skip_serializing_if = "Vec::is_empty"` and deserialized with `default`. Dual-signed attestations are unchanged; device-only attestations omit the field (backward-compatible).
- **auths-cli:** `--identity-key-alias` on `auths artifact sign` is now optional. Omitting it produces a device-only attestation; the identity key never needs to enter CI.
- **auths-id:** `create_signed_attestation`, `resign_attestation`, and `extend_expiration` accept `identity_alias: Option<&str>`. Passing `None` skips identity signing.
- **auths-core:** `EncryptedFileStorage::set_password()` now takes `Zeroizing<String>` instead of `String`, enforcing secure handling of the passphrase from the point of construction. All callers updated.
- **justfile:** `ci-setup` recipe now delegates to `cargo xt ci-setup` (was 187 lines of shell).
- **docs:** Release process guide leads with justfile (`just release`, `just ci-setup`) and moves manual steps to a secondary section.

## [0.0.1-rc.6] - 2026-02-16

### Fixed

- **auths-cli:** `auths emergency report` now loads real identity and device data from storage instead of returning hardcoded mock DIDs.
- **auths-cli:** `auths agent lock` / `unlock` wired end-to-end — lock removes keys from agent memory, unlock reloads from keychain.
- **auths-cli:** `--schema` flag on `auths device link` now validates the payload against the JSON schema instead of being silently ignored.
- **auths-cli:** `auths migrate status` distinguishes GPG vs SSH signatures using `%GS` signer format instead of assuming GPG.
- **auths-id:** `extend_expiration()` and `resign_attestation()` rewritten to use `SecureSigner` instead of raw seeds.
- **auths-id:** Revocation attestations now carry the real device public key (looked up from existing attestations) instead of a zeroed placeholder.
- **auths-nostr:** `run_with_permission_callback()` now checks the callback before signing requests instead of ignoring it.
- **auths-core:** Invalid custom policy actions return an error instead of silently falling back to `sign_commit`.
- **auths-core:** Socket timeout errors in the agent client are now propagated instead of silently discarded.
- **auths-core:** Replaced commented-out HTTP server code with a clean placeholder module.

### Security

- **auths-id:** Auto-install pre-receive hook during `auths init` — rejects non-fast-forward pushes and ref deletions for `refs/keri/`, `refs/auths/`, and `refs/did/keri/`, preventing Git-level KEL rewrites that bypass the Rust registry.
- **auths-id:** Add replay attack prevention to `store_attestation()` — timestamp monotonicity and `rid`-based duplicate detection.
- **auths-verifier:** Introduce `VerifiedAttestation` newtype; attestations must pass verification before storage.
- **auths-verifier:** Add `MAX_ATTESTATION_JSON_SIZE` (64 KiB) and `MAX_JSON_BATCH_SIZE` (1 MiB) limits — all JSON deserialization points across Rust, FFI, WASM, Python, Swift, and Go reject oversized inputs before parsing.

### Added

- **auths-cli:** `auths artifact sign` and `auths artifact verify` commands for signing and verifying arbitrary files (tarballs, binaries). Uses dual-signed attestations with `sign_release` capability, SHA-256 content addressing, and optional witness quorum verification. Hexagonal `ArtifactSource` trait enables future Docker/NPM/Cargo adapters.
- **auths-id:** End-to-end witness integration — `WitnessConfig` and `WitnessPolicy` (Enforce/Warn/Skip) structs for identity-level witness configuration; `create_keri_identity()`, `rotate_keys()`, and `abandon_identity()` now populate KERI event `bt`/`b` fields from config; witness receipts are automatically collected and stored after inception and rotation events when the `witness-client` feature is enabled.
- **auths-id:** `witness_integration` module (feature-gated behind `witness-client`) — `collect_and_store_receipts()` wires `HttpWitnessClient`, `ReceiptCollector`, and `GitReceiptStorage` into the identity lifecycle with policy-based degradation.
- **auths-cli:** `auths init` gains `--witness`, `--witness-threshold`, and `--witness-policy` flags for configuring witnesses at identity creation time.
- **auths-cli:** `auths witness add`, `auths witness remove`, and `auths witness list` subcommands for managing witness URLs in identity metadata post-init.
- **auths-cli:** `auths id rotate` now loads witness config from identity metadata and threads it through to KERI rotation, automatically collecting receipts for rotation events.
- **auths-auth-server:** SQLite-backed `SqliteSessionStore` as default session store — sessions persist across restarts with WAL mode for read concurrency, background cleanup task evicts expired sessions every 60s. `SessionStore` trait expanded with `delete()`, `list_active()`, and `cleanup_expired()` methods.
- **auths-registry-server:** Extract `PairingStore` trait and add SQLite-backed `SqlitePairingStore` as default pairing session store — sessions persist across restarts, background cleanup task evicts expired sessions every 60s. WebSocket notifiers remain ephemeral (in-memory).
- **auths-oidc-bridge:** New crate that exchanges KERI attestation chains for short-lived RS256 JWTs consumable by cloud providers (AWS STS, GCP, Azure AD).
- **auths-core (witness):** Optional TLS via `tls` feature flag (`axum-server` + `rustls`).
- **auths-id:** `freeze` module — time-bounded identity freeze with `auths emergency freeze` / `unfreeze`.
- **auths-cli:** `auths-sign` refuses to sign while identity is frozen.
- **auths-verifier:** FFI exports expanded to 4 functions: added `ffi_verify_chain_json()` and `ffi_verify_device_authorization_json()`.
- **auths-registry-server:** OpenAPI 3.0 spec served at `/api-docs/openapi.json`.
- Dockerfiles for `auths-registry-server` and `auths-auth-server`, plus `docker-compose.yml`.
- GitHub Actions release workflow for cross-platform binaries (linux, macOS, Windows).
- CI: code coverage via `cargo-llvm-cov` + Codecov, mobile FFI tests, Go bindings tests.

### Changed

- **auths-cli:** `auths verify-commit --identity-bundle` now verifies the full attestation chain (revocation, expiry, signature integrity) instead of only extracting the public key for SSH verification. `--witness-receipts`, `--witness-threshold`, and `--witness-keys` flags are now functional, enabling quorum-based witness verification for commit signatures. Refactored internals to eliminate duplicated range/single dispatch and unified JSON/text output with new `ssh_valid`, `chain_valid`, `chain_report`, `witness_quorum`, and `warnings` fields. Extracted shared `parse_witness_keys()` helper into `verify_helpers` module.
- **auths-verifier:** Replace `revoked: bool` with `revoked_at: Option<DateTime<Utc>>` on `Attestation` — enables time-aware revocation checks ("was this attestation valid at time T?") for audit and compliance. `None` = active, `Some(t)` = revoked at time `t`. Adds `is_revoked()` helper. Propagated across all crates, SQLite index, Go bindings, CLI, and registry server.
- **auths-verifier:** `verify_with_keys_at()` now performs time-aware revocation — attestations revoked after the reference time are still considered valid at that point.
- **auths-verifier:** `is_device_listed()` now requires `&[VerifiedAttestation]` instead of `&[Attestation]` — enforces signature verification at the type level.
- **auths-verifier:** Remove deprecated `is_device_authorized()` from Rust, Go, Python, and Swift bindings.
- **auths-registry-server:** Wire org management endpoints (`add_member`, `revoke_member`, `update_capabilities`) to real storage with Ed25519 signature verification and admin authorization.
- **auths-verifier:** Add witness receipt verification with k-of-n quorum support, FFI/WASM bindings, and CLI `--witness-receipts` flags.

### Fixed

- **GitHub Action:** `getAuthsDownloadUrl()` now returns correct release asset URLs.

## [0.0.1-rc.5] - 2026-02-14

### Security

- **auths-policy:** Replace non-cryptographic `DefaultHasher` (SipHash) with `blake3` for policy
  source hashing. The previous implementation used `std::collections::hash_map::DefaultHasher`
  with a comment acknowledging it was a placeholder. Policy hashes are now computed with
  `blake3::hash()`, a cryptographic hash function.

- **auths-core (witness):** Fix receipt SAID computation to use proper Blake3 hash instead of a
  truncated string slice (`format!("E{}", &event_said[1..].chars().take(20)...)`). Receipts now
  compute SAID via `compute_said()` over the canonical signing payload and sign that payload
  rather than a `format!("{}:{}:{}", ...)` string.

- **auths-core (witness):** Add event verification to `submit_event` handler. The witness server
  previously issued receipts for any submitted event without validation. Now verifies:
  - SAID integrity (zeroes `d` field, recomputes Blake3 hash, compares)
  - Structural requirements (required fields per event type)
  - Signature format (`x` field must be valid hex encoding 64 bytes)
  - Inception self-signature (Ed25519 verification of `k[0]` over the event)

- **auths-registry-server:** Add real Ed25519 signature verification for authenticated API
  requests. The `VerifiedSignature` extractor (renamed to `SignatureHeaders`) previously extracted
  headers but had a TODO where verification should occur. Added
  `verify_request_signature(headers, body)` which decodes hex public key and signature, validates
  timestamp within a 300-second window, constructs the signing payload, and verifies via
  `ring::signature::UnparsedPublicKey`.

- **auths-cli:** Remove fake success messages from emergency commands. `revoke-device` now calls
  `create_signed_revocation()` and exports via `AttestationSink`. `rotate-now` now calls
  `rotate_keri_identity()`. `freeze` now returns an honest error stating the feature is not yet
  implemented, instead of printing a fake "Identity frozen" success message.

### Changed

- **auths-registry-server:** `ring` moved from dev-dependencies to dependencies.
- **auths-registry-server:** `VerifiedSignature` renamed to `SignatureHeaders`; a type alias
  preserves backward compatibility.
- **auths-core (witness):** `submit_event` handler now accepts `Json<serde_json::Value>` instead
  of `Json<SubmitEventRequest>` to enable full-event validation.
- **auths-cli:** `emergency revoke-device` now requires `--identity-key-alias` (or interactive
  prompt). `emergency rotate-now` now requires `--current-alias` and `--next-alias` (or
  interactive prompts).

### Added

- **auths-policy:** `blake3` dependency (`1.5`).
- **auths-registry-server:** `verify_request_signature()` public function for verifying Ed25519
  request signatures with timestamp replay protection.
- **auths-core (witness):** `verify_event_said()`, `validate_event_structure()`,
  `validate_signature_format()`, and `verify_inception_self_signature()` functions.

## 0.0.1-rc.1 to 0.0.1-rc.4 [YANKED]

These pre-release versions were yanked from crates.io.
