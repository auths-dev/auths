# Auths V2 Launch: Engineering Roadmap & Ecosystem Strategy

## Executive Summary

Auths is a decentralized identity primitive for developers: cryptographic commit signing with Git-native storage, KERI-inspired identity, and zero central servers. The codebase is ~80K lines of Rust across 18 crates with strong architectural layering.

This document reviews external engineering feedback against the actual codebase state, identifies what's done vs. what remains, and outlines a prioritized roadmap that positions Auths as foundational zero-trust identity infrastructure — not just a developer tool.

---

## Part 1: Status Assessment — Done vs. Not Done

### Feedback Epic 1: The Robust Developer Primitive (Hardening)

| Subtask | Feedback Says | Actual Status | Gap |
|---------|--------------|---------------|-----|
| 1.1 Refactor CLI signing into SDK | "Extract monolithic signing from CLI into composable SDK workflow" | **DONE.** `CommitSigningWorkflow` already exists at `crates/auths-sdk/src/workflows/signing.rs` with three-tier fallback (Agent → Auto-start → Direct), `CommitSigningContext` for dependency injection, and `CommitSigningParams` builder. The CLI's `bin/sign.rs` delegates to this. | None. The feedback's proposed code is almost identical to what's already implemented. |
| 1.2 Isolate network/system deps | "Remove subprocess shell-outs and HTTP clients from core" | **MOSTLY DONE.** `auths-sdk/src/ports/` defines trait abstractions (`AgentSigningPort`, `GitLogProvider`, `ArtifactSource`). `auths-core/src/ports/` has `network.rs` with `NetworkError`. Infrastructure adapters live in `auths-infra-git` and `auths-infra-http`. | Minor: `auths-core/src/api/runtime.rs` still uses `anyhow::Context` for macOS SSH key handling (platform FFI bridge). One `system_diagnostic.rs` adapter in CLI could be further abstracted. |
| 1.3 Eradicate unhandled panics | "Eliminate unwrap()/expect() outside tests" | **PARTIALLY DONE.** SDK enforces `#![deny(clippy::unwrap_used, clippy::expect_used)]`. But ~2,500 `unwrap()`/`expect()` remain across `auths-id` (586), `auths-core` (433), `auths-storage` (289). One explicit `panic!` in `auths-core/src/agent/client.rs:662`. | **Significant.** The SDK layer is clean, but core/id/storage layers have substantial unwrap density. This is the highest-priority hardening task. |

### Feedback Epic 2: KERI Compliance Translation Layer

| Subtask | Feedback Says | Actual Status | Gap |
|---------|--------------|---------------|-----|
| 2.1 Stub `auths-keri` crate | "Create Cargo.toml and lib.rs" | **DONE.** `auths-keri` exists as a full crate with `codec.rs`, `event.rs`, `said.rs`, `stream.rs`, `version.rs`, `roundtrip.rs`, `error.rs`. Uses `cesride` library for CESR encoding. | None. |
| 2.2 CESR encoding & SAID | "Implement CesrEncoder and SaidCalculator" | **DONE.** `CesrCodec` trait with `CesrV1Codec` implementation handles Ed25519 keys, indexed signatures, and Blake3-256 digests. `compute_spec_said()` implements the exact `#`-placeholder methodology. Full test coverage including determinism, `x`-field exclusion, and inception `i`-field placeholder. | None. The feedback's proposed code is a simplified version of what's already built. |
| 2.3 Detached signatures & version serialization | "Extract signatures, attach as CESR groups, compute KERI10JSON version string" | **DONE.** `event.rs` has `serialize_for_cesr()`, `stream.rs` has `assemble_cesr_stream()` with `AttachmentGroup`, `version.rs` has `compute_version_string()`. `roundtrip.rs` provides `export_kel_as_cesr()` and `import_cesr_to_events()`. | None. |

### Feedback Epic 3: Ecosystem Integration & Mobile Readiness

| Subtask | Feedback Says | Actual Status | Gap |
|---------|--------------|---------------|-----|
| 3.1 Integrate UniFFI, eliminate locking | "Replace cbindgen with uniffi-rs" | **PARTIALLY DONE.** `auths-mobile-ffi` crate exists with UniFFI 0.28 proc-macro bindings (Swift/Kotlin). Covers identity creation, signing, auth challenges, and pairing. However, `auths-verifier` still uses manual `cbindgen` for its C FFI. These serve different targets (mobile vs. embedded C), so both are valid. | The feedback conflates two different FFI surfaces. `auths-verifier/src/ffi.rs` (C FFI for embedded systems) is deliberately minimal and shouldn't move to UniFFI. `auths-mobile-ffi` (iOS/Android) already uses UniFFI. No action needed on the UniFFI migration — it's done where it matters. Locking audit (RwLock/parking_lot) is worth evaluating for high-contention FFI paths. |
| 3.2 Abstract LAN pairing | "Extract LAN pairing from CLI into pure protocol crate" | **PARTIALLY DONE.** Core pairing protocol types (`PairingToken`, `PairingResponse`, X25519 ECDH + Ed25519 binding) live in `auths-core/src/pairing/`. Mobile-compatible pairing exists in `auths-mobile-ffi`. However, the LAN server (Axum HTTP + mDNS) remains in `auths-cli/src/commands/device/pair/lan_server.rs`. | **Moderate.** The cryptographic protocol is already abstracted. The transport layer (HTTP server, mDNS advertisement) remains CLI-specific. Extracting to `auths-pairing-protocol` would enable native mobile mDNS (NSNetService/NsdManager) to use the same protocol without pulling in CLI deps. |

### Feedback Epic 4: Enterprise CI/CD Dominance

| Subtask | Feedback Says | Actual Status | Gap |
|---------|--------------|---------------|-----|
| 4.1 Freeze JSON contracts + fuzzing | "Cryptographically freeze schemas, add property-based fuzzing" | **NOT DONE.** `auths-verifier/src/core.rs` defines `Attestation` and `CanonicalAttestationData` but no schema versioning beyond `version: u32` field. No fuzz directory exists. | **Significant for enterprise adoption.** Schema stability guarantees are critical for Fortune 500 CI pipelines. Need: (1) JSON Schema files committed as contract artifacts, (2) `cargo-fuzz` targets for `verify_chain()` and attestation deserialization. |
| 4.2 Scale Git storage (batch CAS) | "Batch Compare-and-Swap tree updates for thousands of KEL appends" | **NOT DONE.** `GitRegistryBackend` in `auths-storage/src/git/adapter.rs` uses `fs2::FileExt` file locking and individual tree mutations. `tree_ops.rs` has `TreeMutator`/`TreeNavigator` but no batch path. | **Important for scale.** Current single-event-per-commit approach will hit throughput limits at ~1000+ identities per registry. Batch CAS would eliminate per-event commit overhead. |

### Feedback Epic 5: IAM Displacement

| Subtask | Feedback Says | Actual Status | Gap |
|---------|--------------|---------------|-----|
| 5.1 Map OIDC claims to policy engine | "Make policy engine natively understand OidcClaims" | **PARTIALLY DONE.** The policy engine (`auths-policy`) already evaluates workload-related predicates: `WorkloadIssuerIs`, `WorkloadClaimEquals`, `IsAgent`, `IsWorkload`, `IsHuman`. `EvalContext` includes `workload_issuer` and `workload_claims` fields. The OIDC bridge (`auths-oidc-bridge`) issues JWTs with capabilities that could feed into policy evaluation. | **The gap is the glue.** The policy engine has the predicates. The bridge produces the claims. But there's no wiring that takes an `OidcClaims` struct and constructs an `EvalContext` for policy evaluation. This is a ~100-line adapter function, not an architectural gap. |
| 5.2 SSI-to-OIDC trust registry | "Centralized trust registry within auths-id for cross-domain trust limits" | **NOT DONE.** No `oidc_trust.rs` in `auths-id`. The OIDC bridge validates GitHub actor/repository via cross-referencing, but enterprise trust policy (which OIDC providers can issue attestations for which capabilities) is not formalized. | **Strategic gap.** This is the "enterprise control plane" feature — security teams defining trust boundaries. |
| 5.3 HSM abstraction + agent provisioning | "KeyStorage traits for Secure Enclave, YubiKey FIDO2 via PCSC/CCID" | **NOT DONE.** `KeyStorage` trait in `auths-core/src/storage/keychain.rs` supports macOS Keychain, Linux Secret Service, Windows Credential Manager, and encrypted file fallback. No HSM/PKCS#11/FIDO2 backends. No `AGENT_PROVISIONING.md`. | **Strategic gap for enterprise.** HSM support is table-stakes for regulated industries (banking, healthcare, government). |

---

## Part 2: Revised Epics (Priority-Ordered)

### Epic 1: Panic Eradication & Error Boundary Hardening

**Priority: P0 — Ship blocker**
**Effort: 2-3 weeks**
**Why first:** A single `unwrap()` panic in a Git hook kills a developer's commit flow. In CI, it's a pipeline outage. This is the #1 barrier to production trust.

#### 1.1 Audit and eliminate panics in hot paths

Focus on the signing and verification paths first — these are the code paths that run on every `git commit`.

**Files (highest unwrap density):**
- `crates/auths-id/src/` — 586 occurrences
- `crates/auths-core/src/` — 433 occurrences (including 1 explicit `panic!` at `agent/client.rs:662`)
- `crates/auths-storage/src/` — 289 occurrences

**Approach:**
1. Enable `#![deny(clippy::unwrap_used, clippy::expect_used)]` crate-by-crate, starting with `auths-core`
2. Triage each occurrence:
   - **Infallible context** (e.g., `"0".parse::<u32>().unwrap()`) → keep with `// SAFETY:` comment or use `const` alternatives
   - **Test-only** → gate behind `#[cfg(test)]`
   - **Recoverable** → convert to `?` with appropriate `thiserror` variant
   - **Structural impossibility** → `unreachable!()` with explanation
3. Replace the `panic!("Expected Ed25519 key")` at `agent/client.rs:662` with a proper `AgentError::UnsupportedKeyType` variant

**Testing:**
```bash
# After each crate migration, run full test suite
cargo nextest run --workspace
# Verify no new panics in signing path
cargo nextest run -E 'test(sign)' -E 'test(verify)'
```

#### 1.2 Enforce deny rules workspace-wide

Add to `Cargo.toml` workspace lints or each crate's `lib.rs`:
```rust
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
```

The SDK already does this. Extend to core, id, storage, and verifier.

#### 1.3 Clean up the anyhow boundary

The `auths-core/src/api/runtime.rs` anyhow usage should be migrated to typed errors. The SDK error types (`SdkStorageError`, etc.) are already clean — no `anyhow` wrapping. The feedback's claim about `StorageError(#[source] anyhow::Error)` variants is **incorrect for the current codebase** — the SDK uses `SdkStorageError::OperationFailed(String)` instead.

---

### Epic 2: OIDC-to-Policy Bridge (The Glue Layer)

**Priority: P1 — Unlocks enterprise CI/CD**
**Effort: 1-2 weeks**
**Why second:** The pieces exist. The OIDC bridge issues JWTs with capabilities. The policy engine evaluates capabilities. Connecting them turns Auths from "signing tool" to "authorization infrastructure."

#### 2.1 Create `OidcClaims → EvalContext` adapter

**File to create:** `crates/auths-policy/src/oidc.rs` (feature-gated behind `oidc` feature)

```rust
/// Constructs a policy evaluation context from verified OIDC claims.
///
/// Args:
/// * `claims`: Verified OIDC claims from the bridge.
/// * `now`: Current wall-clock time for expiration checks.
///
/// Usage:
/// ```ignore
/// let ctx = build_eval_context_from_oidc(&claims, Utc::now());
/// let decision = evaluate_strict(&policy, &ctx);
/// ```
pub fn build_eval_context_from_oidc(
    claims: &OidcClaims,
    now: DateTime<Utc>,
) -> EvalContext {
    let mut ctx = EvalContext::new(
        now,
        CanonicalDid::parse(&claims.sub).unwrap_or_default(),
        CanonicalDid::parse(&claims.sub).unwrap_or_default(),
    );

    for cap in &claims.capabilities {
        if let Ok(c) = CanonicalCapability::parse(cap) {
            ctx = ctx.capability(c);
        }
    }

    ctx = ctx.signer_type(SignerType::Workload);

    if let Some(ref provider) = claims.target_provider {
        ctx = ctx.attr("provider", provider);
    }
    if let Some(ref actor) = claims.github_actor {
        ctx = ctx.attr("github_actor", actor);
    }
    if let Some(ref repo) = claims.github_repository {
        ctx = ctx.repo(repo);
    }

    ctx
}
```

**Critical note on clock injection:** The feedback's `verify_workload_expiration()` function calls `chrono::Utc::now()` directly — this violates the project's clock injection rule. The policy engine already handles expiration via `NotExpired` and `ExpiresAfter` predicates with injected `now`. Don't duplicate this.

#### 2.2 Wire into the OIDC bridge token exchange

**File to modify:** `crates/auths-oidc-bridge/src/issuer.rs`

After chain verification succeeds and before issuing the JWT, optionally evaluate a policy:

```rust
if let Some(ref policy) = config.workload_policy {
    let ctx = build_eval_context_from_oidc(&claims, now);
    let decision = evaluate_strict(policy, &ctx);
    if decision.is_denied() {
        return Err(BridgeError::PolicyDenied(decision.message));
    }
}
```

**Testing:**
```bash
# Unit test the adapter
cargo nextest run -p auths-policy -E 'test(oidc)'
# Integration test with bridge
cargo nextest run -p auths-oidc-bridge -E 'test(policy)'
```

---

### Epic 3: OIDC Trust Registry

**Priority: P1 — Enterprise control plane**
**Effort: 2-3 weeks**
**Why:** Enterprise security teams need to define "GitHub Actions from repo X can only issue deploy:staging attestations." Without this, the bridge is open-loop.

#### 3.1 Define trust registry types

**File to create:** `crates/auths-id/src/registry/oidc_trust.rs`

```rust
/// A trust boundary mapping OIDC providers to allowed capabilities.
///
/// Args:
/// * `provider_issuer`: The OIDC issuer URL (e.g., "https://token.actions.githubusercontent.com").
/// * `rules`: Scoping rules for what this provider can authorize.
pub struct TrustRegistryEntry {
    pub provider_issuer: String,
    pub allowed_repos: Vec<String>,       // e.g., ["org/repo-*"]
    pub allowed_capabilities: Vec<String>, // e.g., ["deploy:staging"]
    pub max_token_ttl_seconds: u64,
    pub require_witness_quorum: Option<usize>,
}

pub struct OidcTrustRegistry {
    entries: Vec<TrustRegistryEntry>,
}
```

#### 3.2 Store trust policies in Git

Trust registry entries should be stored as JSON under `refs/auths/trust-policy/` — consistent with the Git-as-storage pattern. Signed by the identity owner to prevent tampering.

#### 3.3 Integrate with bridge admission

The bridge checks the trust registry before issuing tokens:
1. Look up the OIDC provider's issuer URL in the registry
2. Verify the requesting repo/actor matches allowed patterns
3. Intersect requested capabilities with allowed capabilities
4. Enforce max TTL

**Testing — end-to-end flow:**
```bash
# 1. Create a trust policy
auths trust-policy add \
  --provider "https://token.actions.githubusercontent.com" \
  --repo "myorg/myrepo" \
  --capabilities "deploy:staging,sign:commit" \
  --max-ttl 3600

# 2. Start the bridge
auths-oidc-bridge --config bridge.toml

# 3. From a GitHub Action, exchange token
curl -X POST https://bridge.example.com/token \
  -d '{"chain": [...], "root_public_key": "..."}'

# 4. Verify the issued JWT respects trust boundaries
# Requesting "deploy:production" should fail if policy only allows "deploy:staging"
```

---

### Epic 4: Schema Stability & Fuzzing

**Priority: P2 — Enterprise confidence**
**Effort: 1-2 weeks**

#### 4.1 Commit JSON schemas as contract artifacts

**Files to create:**
- `schemas/attestation-v1.json` — JSON Schema for `CanonicalAttestationData`
- `schemas/identity-bundle-v1.json` — JSON Schema for `IdentityBundle`
- `schemas/keri-icp-v1.json` — JSON Schema for inception events

Add a CI check that validates existing test fixtures against these schemas. This makes the implicit contract explicit.

#### 4.2 Add cargo-fuzz targets

**Files to create:** `crates/auths-verifier/fuzz/fuzz_targets/`

Priority fuzz targets:
1. `fuzz_verify_chain` — Random attestation chain JSON → `verify_chain()` should never panic
2. `fuzz_attestation_deser` — Random bytes → `serde_json::from_slice::<Attestation>()` should never panic
3. `fuzz_cesr_roundtrip` — Random KERI events → CESR encode → decode → compare

```bash
# Run fuzzing (requires nightly)
cd crates/auths-verifier
cargo +nightly fuzz run fuzz_verify_chain -- -max_total_time=300
```

**Testing:**
```bash
# CI should run short fuzz campaigns
cargo +nightly fuzz run fuzz_verify_chain -- -max_total_time=60
cargo +nightly fuzz run fuzz_attestation_deser -- -max_total_time=60
```

---

### Epic 5: Batch Git Storage

**Priority: P2 — Scale enabler**
**Effort: 2-3 weeks**

#### 5.1 Batch CAS tree updates

**File to modify:** `crates/auths-storage/src/git/adapter.rs`

The current `GitRegistryBackend` creates one commit per event. For registries with thousands of identities, this is O(n) commits for n updates.

```rust
/// Applies multiple KEL events in a single Git commit.
///
/// Args:
/// * `events`: Ordered list of events to apply atomically.
///
/// Usage:
/// ```ignore
/// let backend = GitRegistryBackend::new(repo_path)?;
/// backend.batch_append_events(&events)?;
/// ```
pub fn batch_append_events(&self, events: &[Event]) -> Result<(), RegistryError> {
    let _lock = self.acquire_lock()?;
    let parent = self.tip_commit()?;
    let mut tree_builder = /* start from parent tree */;

    for event in events {
        self.apply_event_to_tree(&mut tree_builder, event)?;
    }

    let new_tree = tree_builder.write()?;
    self.atomic_commit(&parent, &new_tree, "batch: {} events", events.len())?;
    Ok(())
}
```

**Key constraint:** The existing file locking (`fs2::FileExt`) provides process-level exclusion. Batch CAS should use the same lock but hold it for the entire batch, not per-event.

**Testing:**
```bash
# Benchmark: 1000 KEL appends, batch vs. sequential
cargo nextest run -p auths-storage -E 'test(batch)'
# Concurrency test: parallel writers should not corrupt
cargo nextest run -p auths-storage -E 'test(concurrent)'
```

---

### Epic 6: LAN Pairing Protocol Extraction

**Priority: P3 — Mobile enabler**
**Effort: 1 week**

#### 6.1 Extract transport-agnostic pairing protocol

The cryptographic protocol is already in `auths-core/src/pairing/`. What's missing is a clean protocol crate that mobile apps can use without pulling in `axum`, `tower-http`, or `mdns-sd`.

**File to create:** `crates/auths-pairing-protocol/src/lib.rs`

This crate should re-export the core pairing types and add:
- Protocol state machine (Initiated → AwaitingResponse → Completed/Failed)
- Serialization for the wire format (already JSON-based)
- No transport dependencies — mobile apps bring their own (NSNetService, NsdManager, BLE)

The CLI's `lan_server.rs` becomes a thin Axum adapter over this protocol.

---

### Epic 7: HSM & Hardware Key Storage

**Priority: P3 — Regulated industry enabler**
**Effort: 3-4 weeks**

#### 7.1 PKCS#11 backend for `KeyStorage`

**File to create:** `crates/auths-core/src/storage/pkcs11.rs`

The `KeyStorage` trait is already abstracted. Adding a PKCS#11 backend enables:
- YubiKey HSM2
- AWS CloudHSM
- Azure Managed HSM
- Any PKCS#11-compliant token

```rust
pub struct Pkcs11KeyStorage {
    session: pkcs11::Session,
}

impl KeyStorage for Pkcs11KeyStorage {
    fn store_key(&self, alias: &KeyAlias, data: &[u8]) -> Result<(), KeyStorageError> { ... }
    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), KeyStorageError> { ... }
    fn delete_key(&self, alias: &KeyAlias) -> Result<(), KeyStorageError> { ... }
}
```

#### 7.2 Apple Secure Enclave backend

For iOS via `auths-mobile-ffi`, use the Security Framework's `kSecAttrTokenIDSecureEnclave` to generate and store keys that never leave hardware.

#### 7.3 Agent provisioning documentation

**File to create:** `docs/AGENT_PROVISIONING.md`

Document the complete flow:
1. Human creates KERI identity (hardware-backed)
2. Human provisions agent with scoped attestation
3. Agent receives OIDC identity via bridge
4. Agent's capabilities are policy-evaluated at every signing operation
5. Agent can be revoked without affecting human identity

---

## Part 3: Ecosystem Strategy — Beyond the Codebase

### The Platform Play

Auths as it stands is a developer primitive. The V2 roadmap transforms it into an ecosystem with three concentric rings:

```
Ring 1 (Core): Signing & Verification
  └── What exists today: CLI, SDK, verifier, Git storage

Ring 2 (Bridge): Identity Federation
  └── OIDC bridge (done), trust registry (Epic 3), policy engine (done)
  └── Enables: GitHub Actions, AWS STS, GCP WI, Azure AD

Ring 3 (Platform): Infrastructure
  └── HSMs (Epic 7), mobile (done), enterprise registries (Epic 5)
  └── Enables: Regulated industries, IoT, autonomous agents
```

### Competitive Positioning

| Competitor | What They Do | Auths Advantage |
|-----------|-------------|-----------------|
| Sigstore/Cosign | Container signing with Fulcio CA | Auths has no CA dependency — Git is the root of trust. Works offline. |
| SPIFFE/SPIRE | Workload identity for services | Auths extends to human + agent + workload identity in one chain. SPIFFE is service-only. |
| Vault | Secret management + identity | Vault is a server. Auths is infrastructure-as-code (Git refs). No central point of failure. |
| DID:web | Decentralized identity via DNS | `did:web` requires DNS infrastructure. `did:keri` is self-certifying — works in air-gapped environments. |

### Revenue/Ecosystem Angles

1. **Managed Registry Service**: Host `GitRegistryBackend` as SaaS for teams that don't want to self-host. Charge per identity/month.
2. **Enterprise OIDC Bridge**: Hosted bridge with trust registry UI, audit logging, and compliance reports. Annual contracts.
3. **Verifier-as-a-Service**: Embed `auths-verifier` (WASM) in CI platforms as a native integration. Partner with GitHub, GitLab, Gitea.
4. **HSM Integration Partnerships**: Certified integrations with YubiKey, Nitrokey, Apple Secure Enclave. Co-marketing.
5. **Compliance Certification**: SOC2/FedRAMP certification for the managed service. Unlocks government and financial sector.
6. **AI Agent Identity**: As AI agents proliferate in CI/CD (Copilot, Cursor, autonomous deploy bots), Auths becomes the identity layer that distinguishes "human approved this deploy" from "agent triggered this deploy." First-mover advantage.

### Key Differentiator: The Delegation Chain

No other identity system provides cryptographically-verified delegation chains:
```
Human (KERI identity)
  → Device (Ed25519 attestation, dual-signed)
    → AI Agent (scoped capabilities: sign:commit only)
      → CI Workload (scoped: deploy:staging, expires in 1h)
```

Every link is independently verifiable. Capabilities only narrow, never expand. This is the zero-trust model that regulated industries need.

---

## Part 4: Testing Strategy — End-to-End

### E2E Test: Full Identity Lifecycle

```bash
# 1. Initialize identity
auths init --name "test-user"

# 2. Create device attestation
auths device link

# 3. Provision AI agent
auths attest \
  --subject did:key:z6Mk... \
  --capabilities "sign:commit" \
  --signer-type agent \
  --expires-in 24h

# 4. Agent signs a commit
echo "test" | auths-sign

# 5. Verify the commit
git log --show-signature

# 6. Rotate keys
auths rotate

# 7. Verify old commits still validate (pre-rotation commitment)
auths verify-commit HEAD~1

# 8. Revoke agent
auths revoke --subject did:key:z6Mk...

# 9. Agent signing should now fail
echo "test" | auths-sign  # Expected: error
```

### E2E Test: OIDC Bridge Flow

```bash
# 1. Start bridge
auths-oidc-bridge --config test-bridge.toml &

# 2. Create attestation chain for CI
auths attest \
  --subject did:key:z6Mk_ci_runner \
  --capabilities "deploy:staging" \
  --signer-type workload

# 3. Exchange for OIDC token
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{
    "attestation_chain": [...],
    "root_public_key": "...",
    "requested_capabilities": ["deploy:staging"]
  }'

# 4. Validate JWT
# Decode and verify: capabilities should be ["deploy:staging"]
# Verify: iss matches bridge URL
# Verify: sub matches KERI DID

# 5. Use JWT with cloud provider
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789012:role/deploy-staging \
  --web-identity-token "$TOKEN"
```

### E2E Test: Policy Enforcement

```bash
# 1. Define policy
cat > policy.json <<EOF
{
  "and": [
    {"is_agent": true},
    {"has_capability": "sign:commit"},
    {"not_revoked": true},
    {"not_expired": true},
    {"max_chain_depth": 2}
  ]
}
EOF

# 2. Evaluate against attestation
auths policy evaluate \
  --policy policy.json \
  --attestation attestation.json

# Expected: Allow (if all conditions met)
```

### CI Test Matrix

```yaml
# Run on every PR
cargo nextest run --workspace                    # All unit + integration tests
cargo test --all --doc                           # Doc tests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check --all
cargo audit                                      # Security audit

# WASM verification
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# Cross-platform: Ubuntu x86_64, macOS aarch64, Windows x86_64
# Rust 1.93+
```

---

## Part 5: Feedback Corrections

Several items in the external feedback are based on outdated or incorrect assumptions:

1. **"Files to Create: auths-keri"** — Already exists with full CESR codec, SAID computation, stream assembly, and roundtrip conversion. The feedback's proposed `CesrEncoder` and `SaidCalculator` are simplified versions of the existing `CesrV1Codec` and `compute_spec_said()`.

2. **"Refactor CLI signing into SDK"** — Already done. `CommitSigningWorkflow` in `auths-sdk/src/workflows/signing.rs` is the exact pattern the feedback proposes, with additional features (freeze validation, passphrase retry, builder pattern).

3. **"SDK error types wrap anyhow::Error"** — No longer true. `SdkStorageError::OperationFailed(String)` replaced the anyhow wrapping. `RegistrationError::NetworkError` wraps a typed `auths_core::ports::network::NetworkError`, not anyhow.

4. **"Replace cbindgen with uniffi-rs"** — These serve different audiences. `cbindgen` generates C headers for `auths-verifier`'s embedded FFI (Rust → C). `uniffi` generates Swift/Kotlin bindings for `auths-mobile-ffi` (Rust → iOS/Android). Both are appropriate for their use cases.

5. **`verify_workload_expiration()` calling `Utc::now()`** — Violates the project's clock injection rule. The policy engine already handles time-dependent evaluation correctly via injected `now` in `EvalContext`.

---

## Part 6: Execution Priority Summary

| # | Epic | Priority | Effort | Impact |
|---|------|----------|--------|--------|
| 1 | Panic eradication & error hardening | P0 | 2-3 weeks | Ship blocker — production reliability |
| 2 | OIDC-to-policy bridge | P1 | 1-2 weeks | Unlocks enterprise CI/CD authorization |
| 3 | OIDC trust registry | P1 | 2-3 weeks | Enterprise control plane |
| 4 | Schema stability & fuzzing | P2 | 1-2 weeks | Enterprise confidence, prevents regression |
| 5 | Batch Git storage | P2 | 2-3 weeks | Scale to thousands of identities |
| 6 | LAN pairing protocol extraction | P3 | 1 week | Mobile ecosystem enabler |
| 7 | HSM & hardware key storage | P3 | 3-4 weeks | Regulated industry access |

**Total estimated effort: 12-18 weeks for full execution.**

Epics 1-3 are the critical path to V2 launch. Epics 4-7 can be parallelized or deferred to V2.1.
