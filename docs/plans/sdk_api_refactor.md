# SDK → API Refactor Plan

**Objective**: Migrate pure domain logic from `auths-sdk` into `auths-api` following the rule: API = domain orchestration (sign, rotate, verify, attest, claim, delegate); SDK = client context, lifecycle, concrete adapters.

**Principle**: Cut aggressively. No backwards compatibility. Delete duplicates. Move all testable-without-I/O logic to auths-api.

---

## Cryptographic Identity Boundary

**Core Principle**: Every handler must verify the request signature to establish the signer's identity. That verified identity (did:key or did:keri) is the authorization proof. No token lookups. No secrets. No session tables.

This refactor is only valuable if **every service is crypto-native**.

### Why This Matters

Traditional SaaS:
```
Handler → Extract bearer token → Look up user in DB → Check role column → Allow/deny
```
**Problem**: Secrets to manage, sessions to revoke, databases to query. Auths rejects this model.

Auths pattern:
```
Handler → Verify signature in request → Extract verified DID → Check attestation chain → Service logic operates only on proven facts
```
**Benefit**: Identity is cryptographic proof, not a lookup. Revocation is instant (expired keys). Multi-tenancy is trait-based, not row-filtered. Audit trail is unforgeable.

### Handler Boundary (All Domains)

**All HTTP handlers must follow this pattern**:

```rust
/// POST /v1/signing/sign
/// Request must be signed with the caller's private key.
pub async fn sign_artifact(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,  // ← Must contain signature
) -> Result<(StatusCode, Json<SignResponse>), ApiError> {
    // Step 1: Verify cryptographic proof (non-negotiable)
    let verified_did = req.verify_signature()
        .map_err(|_| ApiError::InvalidSignature)?;

    // Step 2: Load capability attestations for this DID
    // No database lookup — fetch from attestation store (trait-based)
    let capabilities = state.attestation_registry
        .get_capabilities(&verified_did)
        .await?;

    // Step 3: Check capability claim (e.g., "can sign artifacts")
    if !capabilities.has_capability("sign:artifact") {
        return Err(ApiError::InsufficientCapabilities);
    }

    // Step 4: Call service with verified identity
    // Service NEVER re-verifies, NEVER looks up in database
    let service = SigningService::new(
        state.attestation_source.clone(),
        state.attestation_sink.clone(),
    );

    let response = service
        .sign(verified_did, req.payload, &capabilities)
        .await?;

    Ok((StatusCode::OK, Json(response)))
}
```

**Anti-patterns to reject**:
- ❌ `extract_bearer_token(req)` — No tokens
- ❌ `db.lookup_user_by_id(...)` — No user tables
- ❌ `check_jwt_secret()` — No shared secrets
- ❌ `session_table.get(session_id)` — No sessions
- ❌ `refresh_token()` — Expiration is cryptographic (key age), not DB-managed

### Service Boundary (All Domains)

Services accept **verified identities and capability proofs**, never identifiable credentials:

```rust
/// Sign an artifact on behalf of verified signer.
///
/// Args:
/// * `signer_did` — Verified DID (signature already checked in handler)
/// * `payload` — Request data (untrusted until verified below)
/// * `capabilities` — Capability attestations proving signer's rights
///
/// The service DOES NOT perform any DID lookups or re-verification.
/// All identity evidence is in `capabilities`.
pub async fn sign<A, S>(
    &self,
    signer_did: DidKey,        // ← Already verified in handler
    payload: SignPayload,
    capabilities: &Attestation, // ← Proof of permission
) -> Result<SignResponse> {
    // Evaluate: "Does this attestation claim the capability to sign?"
    // Pure logic: no I/O except trait calls

    // Create attestation for artifact
    let attestation = self.create_attestation(
        &signer_did,
        &payload,
        &capabilities,
    )?;

    // Store (trait impl handles where/how)
    self.attestation_sink.store(&attestation).await?;

    Ok(SignResponse { attestation })
}
```

### Multi-Tenancy (Crypto-Based, Not Database-Filtered)

Isolation via **trait implementations, not SQL WHERE clauses**:

```rust
// Each tenant gets a different attestation source
pub struct TenantAttestationSource {
    tenant_id: String,
    storage: Arc<TenantStorage>,
}

#[async_trait]
impl AttestationSource for TenantAttestationSource {
    async fn load(&self, did: &DidKey) -> Result<Vec<Attestation>> {
        // All attestations for this DID in THIS tenant's namespace
        // No cross-tenant data leakage — it's cryptographically isolated
        self.storage.query_tenant(self.tenant_id, did).await
    }
}

// Handler establishes which tenant based on verified DID
pub async fn sign_in_tenant(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Response> {
    let verified_did = req.verify_signature()?;

    // Determine tenant from DID
    let tenant_id = extract_tenant_from_did(&verified_did)?;

    // Create tenant-specific service
    let service = SigningService::new(
        TenantAttestationSource::new(tenant_id, state.storage.clone()),
        TenantAttestationSink::new(tenant_id, state.storage.clone()),
    );

    service.sign(verified_did, req.payload, &capabilities).await
}
```

**Key insight**: Tenancy is not a row-level filter. It's a **trait implementation**. Same logic, different data visibility via constructor parameters.

### Trait Design (Crypto-Native)

All new traits must assume **verified DIDs and attestation chains**:

```rust
/// Attestation source: loads capability proofs for a verified DID
///
/// Implementation varies by context (per-tenant, per-org, per-network).
/// Logic layer never knows which backend is active.
#[async_trait]
pub trait AttestationSource: Send + Sync {
    /// Load attestations for an already-verified DID.
    /// Returns only claims relevant to this context (tenant, org, etc).
    async fn load(&self, verified_did: &DidKey) -> Result<Vec<Attestation>>;
}

/// Attestation sink: stores newly issued capability proofs
#[async_trait]
pub trait AttestationSink: Send + Sync {
    /// Store an attestation issued by verified signer.
    /// Implementation handles deduplication, revocation chains, retention.
    async fn store(&self, attestation: &Attestation) -> Result<()>;
}

/// Signer: signs data on behalf of a verified key
#[async_trait]
pub trait Signer: Send + Sync {
    /// Sign data. Called only after DID is cryptographically verified in handler.
    /// Implementation may use HSM, TPM, secure enclave, or in-memory key.
    async fn sign(&self, data: &[u8]) -> Result<Signature>;
}
```

No "lookup by ID" trait. No "get user" trait. Only **action traits on verified identities**.

---

## Current State Analysis

### auths-sdk Structure
**Purpose**: Application services layer (orchestration + lifecycle management)

**Modules**:
- `context.rs` — `AuthsContext` (dependency injection container) — **STAYS**
- `device.rs` — Device linking operations — **STAYS** (owns lifecycle)
- `domains/` — Domain services (auth, compliance, device, diagnostics, identity, namespace, org, signing) — **MIXED** (split logic)
- `keys.rs` — Key import/management — **STAYS** (owns keychain context)
- `namespace_registry.rs` — Namespace verifier adapter registry — **STAYS** (owns concrete impls)
- `oidc_jti_registry.rs` — Token replay detection registry — **MIXED** (logic can move, registry stays)
- `pairing/` — Device pairing orchestration — **STAYS** (owns session lifecycle)
- `platform.rs` — Platform identity claim creation — **MIXED** (pure logic can move)
- `ports/` — Trait abstractions (artifact, git, diagnostics) — **STAYS** (architectural boundaries)
- `presentation/` — HTML/report rendering — **STAYS** (view layer, not domain)
- `registration.rs` — Registry publication — **MIXED** (orchestration stays, logic moves)
- `signing.rs` — Artifact signing pipeline — **MIXED** (pure logic moves, context stays)
- `setup.rs` — Identity provisioning — **MIXED** (pure logic moves, wiring stays)
- `types.rs` — Config/request types — **STAYS** (not duplicated)
- `workflows/` — Higher-level identity workflows — **MOVE TO API** (pure orchestration of domain steps)

### auths-api Current Structure
**Purpose**: HTTP server for agent provisioning and authorization

**Existing Modules**:
- `app.rs` — Router and AppState
- `domains/agents/` — Agent provisioning and authorization
- `error.rs` — API error handling
- `middleware/` — Request/response middleware
- `persistence/` — Redis/storage backends

**Sparse**: Only agents domain exists. Other domains (identity, device, signing, compliance) are not yet structured.

---

## Classification Rules (Applied)

### MOVE to auths-api

**Criteria**: Pure domain logic with no lifecycle concerns

1. **Workflows** (all)
   - `workflows/signing.rs` → `domains/signing/workflows.rs`
   - `workflows/rotation.rs` → `domains/identity/workflows.rs`
   - `workflows/provision.rs` → `domains/identity/workflows.rs`
   - `workflows/auth.rs` → `domains/auth/workflows.rs`
   - `workflows/approval.rs` → `domains/auth/workflows.rs`
   - `workflows/artifact.rs` → `domains/signing/workflows.rs`
   - `workflows/allowed_signers.rs` → `domains/signing/workflows.rs`
   - `workflows/git_integration.rs` → `domains/signing/workflows.rs`
   - `workflows/machine_identity.rs` → `domains/identity/workflows.rs`
   - `workflows/policy_diff.rs` → `domains/policy/workflows.rs` (new domain)
   - `workflows/diagnostics.rs` → `domains/diagnostics/workflows.rs`
   - `workflows/namespace.rs` → `domains/namespace/workflows.rs`
   - `workflows/org.rs` → `domains/org/workflows.rs`
   - `workflows/transparency.rs` → `domains/transparency/workflows.rs` (new domain)
   - `workflows/platform.rs` → `domains/identity/workflows.rs`
   - `workflows/status.rs` → `domains/diagnostics/workflows.rs`

2. **Domain services** that are pure (no lifecycle ownership)
   - `domains/identity/service.rs` (rotation, registration, provision logic)
   - `domains/signing/service.rs` (signing pipeline)
   - `domains/compliance/service.rs` (policy evaluation)
   - `domains/diagnostics/service.rs` (analysis logic)
   - `domains/namespace/service.rs` (resolution)
   - `domains/org/service.rs` (org management)

3. **Pure utility functions** currently in SDK
   - `platform.rs` attestation building functions (move logic, not entire module)
   - `signing.rs` artifact canonicalization (move to services)

### STAY in auths-sdk

**Criteria**: Client context, lifecycle, concrete adapter wiring

1. **Context & DI**
   - `context.rs` — `AuthsContext` initialization, trait resolution

2. **Lifecycle ownership**
   - `device.rs` — Device link session state
   - `pairing/` — Pairing daemon session management
   - `keys.rs` — Keychain context and credential refresh

3. **Adapter resolution**
   - `namespace_registry.rs` — Concrete verifier implementations
   - `oidc_jti_registry.rs` — Registry state (logic moves, registry stays)
   - `ports/` — All trait definitions (stay, they're architectural)

4. **Presentation**
   - `presentation/` — HTML rendering, report formatting

---

## Migration Strategy

### Phase 1: Establish auths-api Domain Structure
*Goal: Create empty domain modules to match SDK organization*

Create directory structure under `crates/auths-api/src/domains/`:
```
domains/
├── agents/          (exists)
├── auth/
│   ├── mod.rs
│   ├── error.rs
│   ├── types.rs
│   ├── service.rs
│   ├── handlers.rs
│   └── routes.rs
├── compliance/
│   ├── mod.rs
│   ├── error.rs
│   ├── types.rs
│   ├── service.rs
│   └── (no HTTP handlers yet)
├── device/
├── diagnostics/
├── identity/
├── namespace/
├── org/
├── policy/          (new)
├── signing/
├── transparency/    (new)
└── mod.rs
```

### Phase 2: Move Workflow Modules
*Goal: Transfer pure orchestration from auths-sdk to auths-api*

For each workflow file in `auths-sdk/src/workflows/*.rs`:
1. Copy into `auths-api/src/domains/{domain}/workflows.rs`
2. Adjust imports (remove SDK adapters, use traits from auths-core/auths-id)
3. Delete original in auths-sdk
4. Update auths-sdk/src/workflows/mod.rs

**Example: signing.rs (crypto-native)**
```rust
// auths-api/src/domains/signing/workflows.rs
use auths_core::signing::Signer;
use auths_id::attestation::{AttestationSource, AttestationSink, Attestation};
use crate::domains::signing::service::SigningService;
use auths_crypto::did::DidKey;

/// Sign an artifact on behalf of a verified signer.
///
/// This workflow assumes:
/// - `signer_did` is already cryptographically verified (signature checked in HTTP handler)
/// - `capabilities` are loaded from attestation source (proving signer's rights)
/// - All inputs are trusted facts, not user input
///
/// Args:
/// * `signer_did` — Verified DID (signature already validated)
/// * `artifact` — Data to sign
/// * `capabilities` — Capability attestations proving signer's permissions
/// * `source` — Where to load attestation chains
/// * `sink` — Where to store signed attestation
pub async fn sign_artifact_workflow(
    signer_did: DidKey,
    artifact: &[u8],
    capabilities: &Attestation,
    source: impl AttestationSource,
    sink: impl AttestationSink,
    signer: impl Signer,
) -> Result<Attestation, SigningError> {
    // Pure orchestration: inputs are cryptographically proven facts
    let service = SigningService::new(source, sink);

    // Service never re-verifies signer_did — it's already proven
    service.sign(signer_did, artifact, capabilities, signer).await
}
```

### Phase 3: Move Domain Service Logic
*Goal: Transfer business logic from auths-sdk domain services to auths-api*

For each domain service currently in auths-sdk:
1. Move `domains/{domain}/service.rs` → `auths-api/src/domains/{domain}/service.rs`
2. Update service constructor to accept trait implementations (not AuthsContext)
3. **Ensure all methods accept verified DIDs, not identifiable credentials**
4. Delete from auths-sdk
5. Update auths-sdk/src/domains/mod.rs

**Example: signing/service.rs (crypto-native)**

Before (SDK — context-bound):
```rust
// auths-sdk/src/domains/signing/service.rs
pub struct SigningService {
    context: Arc<AuthsContext>,  // Owns everything: keychain, git, adapters
}

impl SigningService {
    pub fn new(context: Arc<AuthsContext>) -> Self { /* ... */ }

    // ❌ Wrong: Takes artifact path, looks up signer
    pub async fn sign(&self, artifact_path: &str) -> Result<Signature> {
        let signer_did = self.context.load_signer()?;  // DB lookup
        let config = self.context.load_config()?;       // File I/O
        // ...
    }
}
```

After (API — trait-based, crypto-native):
```rust
// auths-api/src/domains/signing/service.rs
/// Signing service: orchestrates artifact signing with capability checks.
///
/// Takes trait implementations, not context. Accepts verified DID + proof.
/// Can be tested without I/O, used in any context (CLI, API, agent).
pub struct SigningService<A, S> {
    attestation_source: A,
    attestation_sink: S,
}

impl<A: AttestationSource, S: AttestationSink> SigningService<A, S> {
    /// Create signing service with pluggable attestation storage.
    ///
    /// Usage:
    /// ```ignore
    /// let service = SigningService::new(
    ///     LocalAttestationSource::new(...),
    ///     LocalAttestationSink::new(...)
    /// );
    /// ```
    pub fn new(attestation_source: A, attestation_sink: S) -> Self {
        Self { attestation_source, attestation_sink }
    }

    /// Sign artifact on behalf of verified signer.
    ///
    /// Args:
    /// * `signer_did` — Cryptographically verified DID (not looked up)
    /// * `artifact` — Data to sign
    /// * `capabilities` — Capability attestations proving `signer_did`'s rights
    /// * `signer` — Signing implementation (HSM, enclave, in-memory, etc)
    ///
    /// ✅ Pure logic: no DID lookups, no secret comparisons, no database queries
    pub async fn sign(
        &self,
        signer_did: DidKey,
        artifact: &[u8],
        capabilities: &Attestation,
        signer: impl Signer,
    ) -> Result<Attestation> {
        // Step 1: Verify capability claim (pure logic on attestation)
        if !capabilities.has_capability("sign:artifact") {
            return Err(SigningError::InsufficientCapabilities);
        }

        // Step 2: Create signature (signer impl handles key access)
        let signature = signer.sign(artifact).await?;

        // Step 3: Create attestation (pure logic)
        let attestation = Attestation::new(
            signer_did,
            artifact,
            signature,
            capabilities,
        )?;

        // Step 4: Store attestation (trait impl handles persistence)
        self.attestation_sink.store(&attestation).await?;

        Ok(attestation)
    }
}
```

**Key differences**:
- ❌ No context, no lifecycle ownership
- ✅ Trait parameters (swappable implementations)
- ✅ Accepts verified DID (not credential path)
- ✅ Accepts capability proof (not permission lookup)
- ✅ Pure business logic (testable without I/O)

### Phase 4: Stub SDK Domain Modules
*Goal: Keep domains/mod.rs in SDK for re-export, stub implementations*

After moving service logic, auths-sdk domain modules shrink to minimal re-exports:
```rust
// auths-sdk/src/domains/signing/mod.rs
pub use auths_api::domains::signing::{SigningError, SigningService};

pub type SigningService = auths_api::domains::signing::SigningService<
    <AuthsContext as HasAttestationSource>::Source,
    <AuthsContext as HasAttestationSink>::Sink,
>;
```

**Alternative**: If re-exports become complex, just re-export from auths-api directly in lib.rs:
```rust
// auths-sdk/src/lib.rs
pub use auths_api::domains;
```

### Phase 5: Update Consumers (auths-cli)
*Goal: Adjust imports to pull from auths-api instead of auths-sdk*

For commands importing SDK domain logic:
1. Change imports from `auths_sdk::domains::*` → `auths_api::domains::*`
2. Change imports from `auths_sdk::workflows::*` → `auths_api::domains::{domain}::workflows`
3. Verify logic still works (no I/O changes)

**Example: auths-cli/src/commands/sign.rs**

Before:
```rust
use auths_sdk::workflows::signing::sign_artifact;
```

After:
```rust
use auths_api::domains::signing::workflows::sign_artifact;
```

### Phase 6: Audit and Delete Duplicates
*Goal: Remove any leftover SDK code that duplicates auths-api*

1. Run `git diff HEAD...` and check for remaining SDK domain services
2. Delete any lingering service.rs files in auths-sdk/src/domains/
3. Remove empty directories
4. Run tests to verify no import breakage

---

## Crypto-Native Patterns Checklist

**Before moving ANY code to auths-api, verify it follows these patterns.**

### Handler Checklist (All HTTP endpoints)

For each handler in `auths-api/src/domains/{domain}/handlers.rs`:

- [ ] Request type includes signature (or signature in header)
- [ ] Handler calls `req.verify_signature()` or `extract_signature(req)` first
- [ ] Handler extracts `DidKey` from verified signature (not user ID)
- [ ] Handler loads capability attestations (not permissions from database)
- [ ] Handler checks capability claim: `capabilities.has_capability("action:type")`
- [ ] Handler passes verified DID to service (never re-verified)
- [ ] Handler passes capability attestation to service (never re-looked-up)
- [ ] ❌ No bearer tokens, JWT subject claims, or session IDs in handler logic
- [ ] ❌ No database lookups (no `db.get_user()`, `session_table.lookup()`, etc.)
- [ ] ❌ No shared secrets, HMAC validation, or password hashing

**Example (verify against this)**:
```rust
pub async fn sign_artifact(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,  // ← Contains signature
) -> Result<(StatusCode, Json<SignResponse>), ApiError> {
    // ✅ Step 1: Verify crypto (NOT lookup)
    let verified_did = req.verify_signature()?;

    // ✅ Step 2: Load attestations (trait impl, not DB query)
    let capabilities = state.attestation_registry.get_capabilities(&verified_did).await?;

    // ✅ Step 3: Check capability claim
    if !capabilities.has_capability("sign:artifact") {
        return Err(ApiError::InsufficientCapabilities);
    }

    // ✅ Step 4: Create service and call
    let service = SigningService::new(state.source.clone(), state.sink.clone());
    let response = service.sign(verified_did, req.payload, &capabilities).await?;

    Ok((StatusCode::OK, Json(response)))
}
```

### Service Checklist (All domain services)

For each service in `auths-api/src/domains/{domain}/service.rs`:

- [ ] Constructor accepts traits, not context (`AttestationSource`, `AttestationSink`, `Signer`)
- [ ] Public methods accept `DidKey` (verified DID), not credential paths or IDs
- [ ] Public methods accept capability proofs (`&Attestation`), not role enums
- [ ] Service calls `capabilities.has_capability(...)` to verify permissions (pure logic)
- [ ] Service uses trait methods to access data (not direct DB queries)
- [ ] ❌ No calls to `AuthsContext`, `load_user()`, `lookup_key()`, or any SDK context
- [ ] ❌ No database access except through trait methods
- [ ] ❌ No "re-verification" of DIDs (handler proved it already)

**Example (verify against this)**:
```rust
pub struct SigningService<A, S> {
    attestation_source: A,
    attestation_sink: S,
}

impl<A: AttestationSource, S: AttestationSink> SigningService<A, S> {
    /// ✅ Accepts verified DID + capability proof
    pub async fn sign(
        &self,
        signer_did: DidKey,        // ← Already verified
        artifact: &[u8],
        capabilities: &Attestation, // ← Already loaded
        signer: impl Signer,
    ) -> Result<Attestation> {
        // ✅ Pure logic: no lookups
        if !capabilities.has_capability("sign:artifact") {
            return Err(SigningError::InsufficientCapabilities);
        }

        let signature = signer.sign(artifact).await?;
        let attestation = Attestation::new(...)?;
        self.attestation_sink.store(&attestation).await?;
        Ok(attestation)
    }
}
```

### Trait Checklist (All trait definitions)

For each trait in `auths-api/src/`:

- [ ] Trait accepts `DidKey` (verified identity), not string IDs
- [ ] Trait accepts `&Attestation` (proof), not role enums
- [ ] Trait methods are **actions on verified identities**, not lookups
- [ ] Trait is implemented per-context (tenant, org, network) via constructor parameter
- [ ] ❌ No "get by ID" traits (that's a lookup)
- [ ] ❌ No traits that return user/role/permission data
- [ ] ❌ No traits that validate identities (handler does that)

**Examples (verify against this)**:
```rust
// ✅ Good: action on verified DID
#[async_trait]
pub trait AttestationSink: Send + Sync {
    async fn store(&self, attestation: &Attestation) -> Result<()>;
}

// ✅ Good: load data for verified DID
#[async_trait]
pub trait AttestationSource: Send + Sync {
    async fn load(&self, verified_did: &DidKey) -> Result<Vec<Attestation>>;
}

// ❌ Bad: lookup by ID
#[async_trait]
pub trait UserStore {
    async fn get_user(&self, user_id: &str) -> Result<User>;
}

// ❌ Bad: return permissions
#[async_trait]
pub trait PermissionChecker {
    async fn get_permissions(&self, user_id: &str) -> Result<Vec<String>>;
}
```

### Test Checklist (All unit tests)

For each test in `auths-api/src/domains/{domain}/tests/`:

- [ ] Test uses `FakeSigner`, `FakeAttestationSource`, `FakeAttestationSink` (no I/O)
- [ ] Test creates capability attestation (not role string)
- [ ] Test passes `DidKey` (not user ID)
- [ ] Test passes capability attestation (not looked up by ID)
- [ ] Test verifies attestation signature (cryptographic proof, not DB validation)
- [ ] Test rejects insufficient capabilities (attestation claim missing)
- [ ] ❌ No `.setup_database()`, `.create_session()`, or `.mock_http()`
- [ ] ❌ No lookup tests (e.g., "test get_user by ID")
- [ ] ❌ No secrets, tokens, or passwords in test data

---

## Migration Checklist

### Step-by-Step Tasks

- [ ] **Create auths-api domain structure** (empty modules)
- [ ] **Move workflows/signing.rs** → auths-api/domains/signing/
  - [ ] Copy file
  - [ ] Update imports
  - [ ] Add to auths-api/src/domains/signing/mod.rs
  - [ ] Delete from auths-sdk
  - [ ] Test no breakage
- [ ] **Move workflows/rotation.rs** → auths-api/domains/identity/
- [ ] **Move workflows/provision.rs** → auths-api/domains/identity/
- [ ] **Move workflows/auth.rs** → auths-api/domains/auth/
- [ ] **Move workflows/approval.rs** → auths-api/domains/auth/
- [ ] **Move workflows/artifact.rs** → auths-api/domains/signing/
- [ ] **Move workflows/allowed_signers.rs** → auths-api/domains/signing/
- [ ] **Move workflows/git_integration.rs** → auths-api/domains/signing/
- [ ] **Move workflows/machine_identity.rs** → auths-api/domains/identity/
- [ ] **Move workflows/policy_diff.rs** → auths-api/domains/policy/ (new)
- [ ] **Move workflows/diagnostics.rs** → auths-api/domains/diagnostics/
- [ ] **Move workflows/namespace.rs** → auths-api/domains/namespace/
- [ ] **Move workflows/org.rs** → auths-api/domains/org/
- [ ] **Move workflows/transparency.rs** → auths-api/domains/transparency/ (new)
- [ ] **Move workflows/platform.rs** → auths-api/domains/identity/
- [ ] **Move workflows/status.rs** → auths-api/domains/diagnostics/
- [ ] **Move domain services** (signing, identity, compliance, diagnostics, namespace, org)
  - [ ] Copy service.rs to auths-api
  - [ ] Update constructors to accept trait implementations
  - [ ] Delete from auths-sdk
  - [ ] Test
- [ ] **Update auths-sdk/src/lib.rs** re-exports (or use auths-api module directly)
- [ ] **Update auths-cli imports**
  - [ ] Search for `auths_sdk::workflows::`
  - [ ] Search for `auths_sdk::domains::`
  - [ ] Update to `auths_api::domains::*`
- [ ] **Run test suite** (no I/O changes, only import adjustments)
- [ ] **Audit and delete empty SDK modules**
- [ ] **Verify no circular dependencies** between auths-api and auths-sdk
- [ ] **Documentation**: Update CLAUDE.md layer diagram if needed

---

## Testing Strategy

### Crypto-Native Testing (No I/O, No Lookup)

Each moved function must be testable **without**:
- ❌ Filesystem access
- ❌ Network calls
- ❌ Keychain access
- ❌ Git operations
- ❌ Database lookups
- ❌ User tables
- ❌ Session queries

**Test Template (Crypto-Native)**:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use auths_api::testing::fakes::*;

    #[tokio::test]
    async fn test_signing_with_verified_did() {
        // Setup: Create cryptographically verifiable test data
        let test_key = auths_test_utils::crypto::get_shared_keypair();
        let signer_did = DidKey::from_keypair(&test_key);

        // Create a capability attestation proving the signer can sign
        let capabilities = Attestation::capability(
            signer_did.clone(),
            vec!["sign:artifact".into()],
        );

        // Setup: Mock implementations (no real I/O)
        let source = FakeAttestationSource::with_attestations(vec![capabilities.clone()]);
        let sink = FakeAttestationSink::new();
        let signer = FakeSigner::with_keypair(test_key);

        // Test: Service accepts verified DID + capability proof
        let service = SigningService::new(source, sink);
        let artifact = b"test artifact";

        let result = service
            .sign(signer_did, artifact, &capabilities, signer)
            .await;

        // Verify: Attestation was created and stored
        assert!(result.is_ok());
        let attestation = result.unwrap();
        assert_eq!(attestation.issuer, signer_did);
        assert!(attestation.verify_signature().is_ok());
    }

    #[tokio::test]
    async fn test_signing_rejects_insufficient_capabilities() {
        let test_key = auths_test_utils::crypto::get_shared_keypair();
        let signer_did = DidKey::from_keypair(&test_key);

        // Capability WITHOUT sign permission
        let limited_capabilities = Attestation::capability(
            signer_did.clone(),
            vec!["read:only".into()],  // ← Wrong capability
        );

        let source = FakeAttestationSource::with_attestations(vec![limited_capabilities.clone()]);
        let sink = FakeAttestationSink::new();
        let signer = FakeSigner::with_keypair(test_key);

        let service = SigningService::new(source, sink);

        // Service should reject: capability proof doesn't include "sign:artifact"
        let result = service
            .sign(signer_did, b"test", &limited_capabilities, signer)
            .await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            SigningError::InsufficientCapabilities
        );
    }

    #[tokio::test]
    async fn test_attestation_chain_verification() {
        // Test that attestation chains are verified without database lookups
        let issuer_key = auths_test_utils::crypto::get_shared_keypair();
        let issuer_did = DidKey::from_keypair(&issuer_key);

        let delegator_key = auths_test_utils::crypto::create_test_keypair();
        let delegator_did = DidKey::from_keypair(&delegator_key);

        // Issuer delegates capability to delegator
        let capability = Attestation::capability(delegator_did.clone(), vec!["sign:artifact".into()])
            .issued_by(issuer_did)
            .sign_with(&issuer_key)?;

        // Service verifies delegation via signature, not database lookup
        let source = FakeAttestationSource::with_attestations(vec![capability.clone()]);
        let sink = FakeAttestationSink::new();
        let signer = FakeSigner::with_keypair(delegator_key);

        let service = SigningService::new(source, sink);
        let result = service
            .sign(delegator_did, b"test", &capability, signer)
            .await;

        assert!(result.is_ok());
    }
}
```

**Key testing principles**:
1. **Verified inputs only** — Pass `DidKey` (proven via signature), not user IDs
2. **Attestation proof** — Pass capability attestations, not role strings
3. **Fake traits** — `FakeSigner`, `FakeAttestationSource` implement the traits, no I/O
4. **Deterministic** — Use `get_shared_keypair()` for reproducible tests
5. **No lookups** — Service never queries a database, file, or network

### Verification Commands
```bash
# Rebuild after each phase
cargo build --all

# Run tests (no I/O)
cargo nextest run --workspace

# Check imports
grep -r "auths_sdk::workflows\|auths_sdk::domains" crates/auths-cli/

# Clippy
cargo clippy --all-targets --all-features -- -D warnings

# Verify no new unwrap/expect
cargo clippy --all -- -D clippy::unwrap_used -D clippy::expect_used
```

---

## Risk Assessment

### Low Risk
- Workflow migrations (pure functions, no I/O)
- Service logic moves (just restructuring, no behavior change)
- Import updates (mechanical)

### Medium Risk
- Re-export complexity (SDK might need complex type aliases)
- Circular dependency (auths-api depends on auths-sdk for types, vice versa)

### Mitigation
- **Keep SDK as re-export layer** initially if re-exports become unwieldy
- **auths-api should NOT import from auths-sdk** (one-way dependency: auths-cli → auths-api; auths-cli → auths-sdk for context only)
- **Test immediately after each move** (cargo test --workspace)

---

## Post-Migration Validation

### Acceptance Criteria

**Code structure:**
1. ✅ All workflows moved from auths-sdk to auths-api domains
2. ✅ All domain services moved (except those managing lifecycle)
3. ✅ All tests pass (cargo nextest run --workspace)
4. ✅ No `unwrap()` or `expect()` without // INVARIANT comments
5. ✅ All public functions have doc comments
6. ✅ auths-cli compiles and runs end-to-end
7. ✅ No circular dependencies (verified with `cargo check`)

**Crypto-native patterns (non-negotiable):**
8. ✅ **No handler accepts bare credentials** — All handlers verify signatures and extract `DidKey`
9. ✅ **No service performs lookups** — Services accept verified DIDs, never re-verify
10. ✅ **Capability proofs are first-class** — Attestations passed as params, not looked up by ID
11. ✅ **Traits model actions on verified identities** — No "get_user" trait, only "sign", "verify", "store"
12. ✅ **Multi-tenancy via trait impl, not row filtering** — Different `AttestationSource` per tenant, same logic
13. ✅ **All services testable without I/O** — No database mocks needed, only `Fake*` trait impls
14. ✅ **Audit trail is cryptographic** — Attestations are signed and timestamped, not logged to a table

**Testing:**
15. ✅ Each service has tests that pass verified DIDs + capability proofs (no user ID lookups)
16. ✅ Each service test rejects insufficient capabilities (capability validation is tested in isolation)
17. ✅ Each workflow test verifies attestation chain signature (cryptographic proof, not DB validation)

---

## File-Level Migration Map

| auths-sdk/src | → auths-api/src | Purpose |
|---|---|---|
| `workflows/signing.rs` | `domains/signing/workflows.rs` | Sign artifact orchestration |
| `workflows/rotation.rs` | `domains/identity/workflows.rs` | Key rotation workflow |
| `workflows/provision.rs` | `domains/identity/workflows.rs` | Identity provisioning |
| `workflows/auth.rs` | `domains/auth/workflows.rs` | Auth challenge workflow |
| `workflows/approval.rs` | `domains/auth/workflows.rs` | Approval workflow |
| `workflows/artifact.rs` | `domains/signing/workflows.rs` | Artifact handling |
| `workflows/allowed_signers.rs` | `domains/signing/workflows.rs` | Allowed signers logic |
| `workflows/git_integration.rs` | `domains/signing/workflows.rs` | Git integration |
| `workflows/machine_identity.rs` | `domains/identity/workflows.rs` | CI/ephemeral identities |
| `workflows/policy_diff.rs` | `domains/policy/workflows.rs` | Policy diffing |
| `workflows/diagnostics.rs` | `domains/diagnostics/workflows.rs` | Diagnostic collection |
| `workflows/namespace.rs` | `domains/namespace/workflows.rs` | Namespace management |
| `workflows/org.rs` | `domains/org/workflows.rs` | Org operations |
| `workflows/transparency.rs` | `domains/transparency/workflows.rs` | Transparency/auditability |
| `workflows/platform.rs` | `domains/identity/workflows.rs` | Platform identity |
| `workflows/status.rs` | `domains/diagnostics/workflows.rs` | Status aggregation |
| `domains/signing/service.rs` | `domains/signing/service.rs` | ⬆️ Signing service |
| `domains/identity/service.rs` | `domains/identity/service.rs` | ⬆️ Identity service |
| `domains/compliance/service.rs` | `domains/compliance/service.rs` | ⬆️ Compliance service |
| `domains/diagnostics/service.rs` | `domains/diagnostics/service.rs` | ⬆️ Diagnostics service |
| `domains/namespace/service.rs` | `domains/namespace/service.rs` | ⬆️ Namespace service |
| `domains/org/service.rs` | `domains/org/service.rs` | ⬆️ Org service |
| `context.rs` | — | **STAYS** (lifecycle) |
| `device.rs` | — | **STAYS** (session state) |
| `pairing/mod.rs` | — | **STAYS** (session management) |
| `keys.rs` | — | **STAYS** (keychain context) |
| `namespace_registry.rs` | — | **STAYS** (adapter resolution) |
| `oidc_jti_registry.rs` | — | **STAYS** (registry state) |
| `ports/mod.rs` | — | **STAYS** (trait abstractions) |
| `presentation/mod.rs` | — | **STAYS** (view layer) |

---

## Anti-Patterns That Break Auths (REJECT THESE)

**If you see these in auths-api code, stop and refactor:**

### 1. Handler Accepts Credential Path Instead of Verified DID
```rust
// ❌ WRONG: Handler accepts credential path, performs lookup
pub async fn sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Response> {
    let key_path = &req.key_path;  // ← Not verified
    let key = load_key_from_path(key_path)?;  // ← Lookup!
    let signature = sign_with_key(&key, &req.artifact)?;
    // ...
}

// ✅ RIGHT: Handler verifies signature, extracts DID
pub async fn sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,  // ← Contains signature
) -> Result<Response> {
    let verified_did = req.verify_signature()?;  // ← Verify, don't lookup
    // No key loading. Signature is proof of identity.
}
```

**Why**: Credential paths are user input. Signatures are cryptographic proof. Auths rejects the former.

---

### 2. Service Performs User Lookup
```rust
// ❌ WRONG: Service looks up user by ID
pub async fn sign(&self, user_id: &str, artifact: &[u8]) -> Result<Signature> {
    let user = self.db.get_user(user_id)?;  // ← Lookup!
    if !user.can_sign {
        return Err(Error::PermissionDenied);
    }
    // ...
}

// ✅ RIGHT: Service accepts verified identity + proof
pub async fn sign(
    &self,
    signer_did: DidKey,
    artifact: &[u8],
    capabilities: &Attestation,  // ← Proof, not lookup
) -> Result<Signature> {
    if !capabilities.has_capability("sign:artifact") {
        return Err(Error::InsufficientCapabilities);
    }
    // ...
}
```

**Why**: Auths identities are cryptographic. If the handler verified the signature, the service must trust it. No re-verification.

---

### 3. Permission Check Uses Role Enum
```rust
// ❌ WRONG: Hardcoded roles
pub enum Role {
    Admin,
    Developer,
    Readonly,
}

if user.role == Role::Admin {
    allow_operation();
}

// ✅ RIGHT: Capability claimed in attestation
if capabilities.has_capability("sign:artifact") {
    allow_operation();
}
```

**Why**: Roles are mutable. Capabilities are cryptographically signed, immutable, and delegatable.

---

### 4. Multi-Tenancy via Database Column Filter
```rust
// ❌ WRONG: Row-level filtering
pub async fn get_attestations(&self, tenant_id: &str, did: &str) -> Result<Vec<Attestation>> {
    self.db.query("SELECT * FROM attestations WHERE tenant_id = ? AND did = ?", tenant_id, did).await
}

// ✅ RIGHT: Trait impl per tenant
pub struct TenantAttestationSource {
    tenant_id: String,
    pool: Arc<TenantDb>,  // ← Different pool per tenant
}

#[async_trait]
impl AttestationSource for TenantAttestationSource {
    async fn load(&self, did: &DidKey) -> Result<Vec<Attestation>> {
        self.pool.query_tenant(self.tenant_id, did).await  // ← Isolation at trait level
    }
}
```

**Why**: Trait-based isolation is cryptographically enforced (different keys per tenant). SQL WHERE is mutable and error-prone.

---

### 5. Test Uses Database Mocks Instead of Fake Traits
```rust
// ❌ WRONG: Mocking database
#[tokio::test]
async fn test_signing() {
    let mut db = MockDatabase::new();
    db.expect_get_user().return_once(Ok(User { id: "user1" }));
    db.expect_insert_attestation().return_once(Ok(()));

    let service = SigningService::new(db);
    let result = service.sign("user1", b"artifact").await;
    assert!(result.is_ok());
}

// ✅ RIGHT: Using Fake trait implementations
#[tokio::test]
async fn test_signing() {
    let test_key = get_shared_keypair();
    let signer_did = DidKey::from_keypair(&test_key);
    let capabilities = Attestation::capability(signer_did.clone(), vec!["sign:artifact".into()]);

    let source = FakeAttestationSource::with_attestations(vec![capabilities.clone()]);
    let sink = FakeAttestationSink::new();
    let signer = FakeSigner::with_keypair(test_key);

    let service = SigningService::new(source, sink);
    let result = service.sign(signer_did, b"artifact", &capabilities, signer).await;
    assert!(result.is_ok());
}
```

**Why**: Database mocks test the database, not the logic. Fake traits test pure business logic without I/O.

---

### 6. Handler Accepts JWT and Checks `token["sub"]`
```rust
// ❌ WRONG: JWT as identity proof
pub async fn operation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response> {
    let token = extract_bearer_token(&headers)?;
    let claims = decode_jwt(&token, &state.jwt_secret)?;
    let user_id = claims.subject;  // ← Just a claim, not proven
    // ...
}

// ✅ RIGHT: Signature as identity proof
pub async fn operation(
    State(state): State<AppState>,
    Json(req): Json<SignedRequest>,  // ← Entire request is signed
) -> Result<Response> {
    let verified_did = req.verify_signature()?;  // ← Cryptographic proof
    // ...
}
```

**Why**: JWTs are bearer tokens (anyone with the token can use it). Signatures prove you have the private key (non-transferable).

---

### 7. Attestation Stored in Database, Not as Signed Document
```rust
// ❌ WRONG: Attestation as mutable record
INSERT INTO attestations (issuer_id, claims_json, created_at) VALUES (?, ?, ?);

// ✅ RIGHT: Attestation as signed document
struct Attestation {
    issuer: DidKey,
    claims: serde_json::Value,
    issuer_signature: Signature,  // ← Signed, immutable
    device_signature: Signature,  // ← Proof of issuance
}
```

**Why**: Mutable records can be tampered with. Signed documents create unforgeable audit trails.

---

## Success Definition

After migration:

1. **auths-api** is the API layer — contains all domain workflows and services
2. **auths-sdk** is the client layer — owns context, lifecycle, concrete adapters
3. **auths-cli** imports from **auths-api** for logic, **auths-sdk** for context only
4. **No logic duplication** — workflows live in exactly one place
5. **All tests pass** with no I/O, all functions have doc comments
6. **Every handler verifies signatures** (crypto-native auth boundary)
7. **Every service accepts verified DIDs + capability proofs** (no lookups)
8. **Every trait implements an action, not a lookup** (all methods take DidKey, not ID)
9. **Multi-tenancy is trait-based** (different implementations, same logic)
10. **Tests use Fake traits, not database mocks** (pure logic testing)

This refactor *cuts aggressively*: if logic can be tested without I/O, it belongs in auths-api. And if it doesn't follow crypto-native patterns, it doesn't belong anywhere—go back and refactor the handler/service boundary.
