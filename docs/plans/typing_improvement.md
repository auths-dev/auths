# Typing Improvement Plan

Pre-v0.1.0 type safety audit. Each section targets a specific weak type, shows the
proposed change, and explains why it matters — especially in the context of the
Radicle/Heartwood integration where stringly-typed boundaries caused repeated bugs.

---

## 1. `Attestation.rid` — bare `String` to `ResourceId` newtype

**File:** `crates/auths-verifier/src/core.rs:336`

### Current

```rust
pub struct Attestation {
    pub rid: String,
    // ...
}
```

### Proposed

```rust
// crates/auths-verifier/src/core.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ResourceId {
    type Target = str;
    fn deref(&self) -> &str { &self.0 }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct Attestation {
    pub rid: ResourceId,
    // ...
}
```

### Why

`rid` is used to link attestations to storage refs, to Radicle `RepoId`s, and as a
lookup key across the org-member registry. Bare `String` allows accidental substitution
of a DID, a Git ref, or any other string. A newtype makes the intent unambiguous and
prevents cross-field confusion — particularly at the `RadAttestation <-> Attestation`
conversion boundary where the Radicle `RepoId` must map cleanly to this field.

---

## 2. `Attestation.role` — bare `Option<String>` to `Option<Role>`

**File:** `crates/auths-verifier/src/core.rs:367`

### Current

```rust
pub struct Attestation {
    pub role: Option<String>,
    // ...
}
```

### Proposed

```rust
// crates/auths-verifier/src/core.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Role {
    Admin,
    Member,
    Readonly,
}

pub struct Attestation {
    pub role: Option<Role>,
    // ...
}
```

Also update the duplicate `Role` enum in `crates/auths-sdk/src/workflows/org.rs:19-27`
to re-export from `auths-verifier` instead of defining its own copy.

### Why

The role field is compared at runtime in org-member verification
(`org_member.rs` `MemberView.role`, SDK `AddMemberCommand`). Two separate `Role` enums
exist today — one in auths-sdk and an implicit one via `String`. Unifying into a single
source-of-truth enum in auths-verifier (the lowest-dependency crate) prevents typo-based
mismatches like `"Admin"` vs `"admin"` and gives exhaustive match coverage across the
Radicle bridge where role-based capability checks matter.

---

## 3. `Attestation.device_public_key` — `Vec<u8>` to `Ed25519PublicKey`

**Files:**
- `crates/auths-verifier/src/core.rs:343`
- `crates/auths-core/src/signing.rs:96` (`ResolvedDid.public_key`)
- `crates/auths-core/src/ports/network.rs:126` (`ResolvedIdentity.public_key`)

### Current

```rust
// auths-verifier
pub struct Attestation {
    #[serde(with = "hex::serde")]
    pub device_public_key: Vec<u8>,
    // ...
}

// auths-core
pub struct ResolvedDid {
    pub public_key: Vec<u8>,
    // ...
}

pub struct ResolvedIdentity {
    pub public_key: Vec<u8>,
    // ...
}
```

### Proposed

```rust
// crates/auths-verifier/src/core.rs (or a shared types module)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, Ed25519KeyError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Ed25519KeyError::InvalidLength(bytes.len()))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Serde: hex-encode for JSON, raw bytes for binary
impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex::serde::serialize(&self.0.to_vec(), serializer)
    }
}
// (Deserialize mirrors this — validate length on decode)

#[derive(Debug, thiserror::Error)]
pub enum Ed25519KeyError {
    #[error("expected 32 bytes, got {0}")]
    InvalidLength(usize),
}
```

Then update:
```rust
pub struct Attestation {
    pub device_public_key: Ed25519PublicKey,
    // ...
}

pub struct ResolvedDid {
    pub public_key: Ed25519PublicKey,
    // ...
}
```

### Why

Ed25519 public keys are always exactly 32 bytes. Using `Vec<u8>` means every consumer
must runtime-check length — and many don't. During the Radicle integration the bridge
moves keys between `radicle_crypto::PublicKey` (which is `[u8; 32]`) and our `Vec<u8>`,
introducing unnecessary `.try_into().unwrap()` calls. A fixed-size newtype eliminates
an entire class of "wrong length" bugs at construction time rather than at use time.

---

## 4. `Attestation.identity_signature` / `device_signature` — `Vec<u8>` to `Ed25519Signature`

**File:** `crates/auths-verifier/src/core.rs:346,349`

### Current

```rust
pub struct Attestation {
    #[serde(with = "hex::serde")]
    pub identity_signature: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub device_signature: Vec<u8>,
    // ...
}
```

### Proposed

```rust
// crates/auths-verifier/src/core.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, SignatureLengthError> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| SignatureLengthError(bytes.len()))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn empty() -> Self {
        Self([0u8; 64])
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}
// Serialize/Deserialize via hex, same pattern as Ed25519PublicKey

pub struct Attestation {
    pub identity_signature: Ed25519Signature,
    pub device_signature: Ed25519Signature,
    // ...
}
```

### Why

Ed25519 signatures are always 64 bytes. The `identity_signature` field uses
`skip_serializing_if = "Vec::is_empty"` to handle the intermediate state where the
identity hasn't signed yet — `Ed25519Signature::empty()` / `is_empty()` preserves this
while making the invariant explicit. This prevents the class of bug where a truncated
or extra-long signature passes type checks but fails at verification time. The Radicle
`RadAttestation` already has `device_signature: Vec<u8>` and `identity_signature: Vec<u8>`
fields — converting them both to `Ed25519Signature` at the bridge boundary catches
corruption early.

---

## 5. `Seal.seal_type` — bare `String` to `SealType` enum

**File:** `crates/auths-id/src/keri/seal.rs:22`

### Current

```rust
pub struct Seal {
    pub d: Said,
    #[serde(rename = "type")]
    pub seal_type: String,
}

impl Seal {
    pub fn device_attestation(said: Said) -> Self { /* seal_type: "device-attestation" */ }
    pub fn revocation(said: Said) -> Self { /* seal_type: "revocation" */ }
    pub fn delegation(said: Said) -> Self { /* seal_type: "delegation" */ }
}
```

### Proposed

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SealType {
    DeviceAttestation,
    Revocation,
    Delegation,
}

pub struct Seal {
    pub d: Said,
    #[serde(rename = "type")]
    pub seal_type: SealType,
}
```

### Why

The factory methods already prove the set is closed. A bare `String` lets callers
construct a `Seal` with an arbitrary `seal_type` (e.g., `"revocaton"` typo), which
silently passes serialization but breaks downstream consumers. An enum makes invalid
seal types a compile error. `#[non_exhaustive]` preserves forward compatibility for
new seal types.

---

## 6. `StorageLayoutConfig` — `String` fields to `GitRef` / `BlobName` newtypes

**File:** `crates/auths-id/src/storage/layout.rs:82-98`

### Current

```rust
pub struct StorageLayoutConfig {
    pub identity_ref: String,
    pub device_attestation_prefix: String,
    pub attestation_blob_name: String,
    pub identity_blob_name: String,
}
```

### Proposed

```rust
// crates/auths-id/src/storage/layout.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRef(String);

impl GitRef {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn join(&self, segment: &str) -> Self {
        Self(format!("{}/{}", self.0, segment))
    }
}

impl std::fmt::Display for GitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobName(String);

impl BlobName {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

pub struct StorageLayoutConfig {
    pub identity_ref: GitRef,
    pub device_attestation_prefix: GitRef,
    pub attestation_blob_name: BlobName,
    pub identity_blob_name: BlobName,
}
```

### Why

During the RIP-X ref path reconciliation (`fn-3.2`), the biggest source of confusion
was whether a string contained a full ref (`refs/keri/kel`), a prefix
(`refs/auths/keys`), or a blob name (`attestation.json`). Three different semantic
categories were all `String`. The `GitRef` and `BlobName` newtypes make it impossible
to accidentally pass an `identity_blob_name` where a `device_attestation_prefix` is
expected. The `GitRef::join()` method also standardizes ref construction without ad-hoc
`format!` calls scattered across the storage layer.

---

## 7. `Seal.d` / KERI event sequence — `String` to `u64`

**File:** `crates/auths-id/src/keri/event.rs:63,100,140`

### Current

```rust
pub struct IcpEvent {
    pub s: String,  // sequence number as hex string
    // ...
}

pub struct RotEvent {
    pub s: String,
    // ...
}

pub struct IxnEvent {
    pub s: String,
    // ...
}
```

The shared method `Event::sequence()` then parses `s` as hex `u64` each time, and a
`SequenceParseError` exists just for this conversion.

### Proposed

```rust
// crates/auths-id/src/keri/event.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeriSequence(u64);

impl KeriSequence {
    pub fn new(n: u64) -> Self { Self(n) }
    pub fn value(&self) -> u64 { self.0 }
}

impl Serialize for KeriSequence {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for KeriSequence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let n = u64::from_str_radix(&s, 16)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(n))
    }
}

pub struct IcpEvent {
    pub s: KeriSequence,
    // ...
}
```

### Why

Every caller of `Event::sequence()` must handle a `SequenceParseError` that can never
happen if the sequence was validated at deserialization. Moving validation into serde
(parse-don't-validate pattern) eliminates `SequenceParseError` entirely and makes
`Event::sequence()` infallible. In the Radicle bridge, `min_kel_seq: Option<u64>` in
`VerifyRequest` is compared against the identity's sequence — this comparison currently
requires parsing the string first.

---

## 8. SDK result types — bare `String` DIDs to `IdentityDID` / `DeviceDID`

**File:** `crates/auths-sdk/src/result.rs` (entire file)

### Current

```rust
pub struct SetupResult {
    pub identity_did: String,
    pub device_did: String,
    // ...
}

pub struct CiSetupResult {
    pub identity_did: String,
    pub device_did: String,
    // ...
}

pub struct DeviceLinkResult {
    pub device_did: String,
    pub attestation_id: String,
}

pub struct RotationResult {
    pub controller_did: String,
    // ...
}
// ... 7 more structs with String DIDs
```

### Proposed

```rust
use auths_verifier::types::{IdentityDID, DeviceDID};
use auths_verifier::core::ResourceId;

pub struct SetupResult {
    pub identity_did: IdentityDID,
    pub device_did: DeviceDID,
    pub key_alias: KeyAlias,
    pub platform_claim: Option<PlatformClaimResult>,
    pub git_signing_configured: bool,
    pub registered: Option<RegistrationOutcome>,
}

pub struct CiSetupResult {
    pub identity_did: IdentityDID,
    pub device_did: DeviceDID,
    pub env_block: Vec<String>,
}

pub struct DeviceLinkResult {
    pub device_did: DeviceDID,
    pub attestation_id: ResourceId,
}

pub struct RotationResult {
    pub controller_did: IdentityDID,
    pub new_key_fingerprint: String,
    pub previous_key_fingerprint: String,
}

pub struct DeviceExtensionResult {
    pub device_did: DeviceDID,
    pub new_expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct AgentSetupResult {
    pub agent_did: IdentityDID,
    pub parent_did: IdentityDID,
    pub capabilities: Vec<Capability>,
}
```

### Why

`IdentityDID` and `DeviceDID` already exist in auths-verifier with validation and
`Display` impls. The SDK is the primary API surface developers interact with — returning
bare `String` means every consumer must re-validate or blindly trust. Typed DIDs
eliminate an entire category of "passed the wrong DID type" bugs at the SDK boundary.
This directly solves the pain point from `fn-5.5` ("Move away from stringly typed DIDs
to structured objects"). Also replaces `Vec<String>` capabilities with
`Vec<Capability>` — the `Capability` newtype already exists in auths-verifier with
validation.

---

## 9. SDK config types — `Vec<String>` capabilities to `Vec<Capability>`

**Files:**
- `crates/auths-sdk/src/types.rs:375` (`AgentSetupConfig.capabilities`)
- `crates/auths-sdk/src/types.rs:586` (`DeviceLinkConfig.capabilities`)
- `crates/auths-sdk/src/pairing.rs:75,132` (`PairingSessionParams.capabilities`, etc.)
- `crates/auths-sdk/src/workflows/org.rs:185,207` (`AddMemberCommand.capabilities`)

### Current

```rust
pub struct AgentSetupConfig {
    pub capabilities: Vec<String>,
    // ...
}

pub struct DeviceLinkConfig {
    pub capabilities: Vec<String>,
    // ...
}
```

### Proposed

```rust
use auths_verifier::core::Capability;

pub struct AgentSetupConfig {
    pub capabilities: Vec<Capability>,
    // ...
}

pub struct DeviceLinkConfig {
    pub capabilities: Vec<Capability>,
    // ...
}
```

### Why

The `Capability` newtype in auths-verifier already validates: non-empty, max 64 chars,
only `[a-zA-Z0-9:_-]`, no reserved `auths:` prefix. Every `Vec<String>` capability
field today pushes this validation to downstream code (or skips it entirely). Using
`Capability` at the config boundary means invalid capabilities are rejected at
construction time — before they ever reach the signing or attestation layer. The
Heartwood integration specifically needs this because capabilities flow through the
`RadicleAuthsBridge::verify_signer()` path where a malformed string would silently
fail policy matching.

---

## 10. `ResolvedDid.did` — bare `String` to enum dispatch

**File:** `crates/auths-core/src/signing.rs:92-99`

### Current

```rust
pub struct ResolvedDid {
    pub did: String,
    pub public_key: Vec<u8>,
    pub method: DidMethod,
}
```

The `did` field and `method` field are independently set — nothing enforces that a
`did:keri:...` string has `method: DidMethod::Keri { .. }`, or that a `did:key:...`
string has `method: DidMethod::Key`.

### Proposed

```rust
pub enum ResolvedDid {
    Key {
        did: DeviceDID,
        public_key: Ed25519PublicKey,
    },
    Keri {
        did: KeriDid,
        public_key: Ed25519PublicKey,
        sequence: u64,
        can_rotate: bool,
    },
}

impl ResolvedDid {
    pub fn public_key(&self) -> &Ed25519PublicKey {
        match self {
            Self::Key { public_key, .. } | Self::Keri { public_key, .. } => public_key,
        }
    }

    pub fn did_string(&self) -> &str {
        match self {
            Self::Key { did, .. } => did.as_str(),
            Self::Keri { did, .. } => did.as_str(),
        }
    }
}
```

### Why

A struct with parallel `did: String` + `method: DidMethod` fields is a classic
"boolean blindness" anti-pattern — the two fields can be independently set to
contradictory values. An enum makes the DID type and its metadata structurally
inseparable. This directly mirrors the Radicle `Did` enum (`Did::Key(PublicKey)` vs
implicit `Did::Keri`) and eliminates the mismatch bugs reported during the bridge
integration. The `DidResolver` trait would return this enum, making callers use
`match` to handle both DID methods explicitly.

---

## 11. `StoredIdentityData.controller_did` — bare `String` to `IdentityDID`

**File:** `crates/auths-id/src/storage/identity.rs:22`

### Current

```rust
struct StoredIdentityData {
    version: u32,
    controller_did: String,
    metadata: Option<serde_json::Value>,
}
```

### Proposed

```rust
use auths_verifier::types::IdentityDID;

struct StoredIdentityData {
    version: u32,
    controller_did: IdentityDID,
    metadata: Option<serde_json::Value>,
}
```

### Why

`StoredIdentityData` is serialized to/from JSON in Git blobs. Using `IdentityDID`
means deserialization rejects malformed controller DIDs at the storage boundary instead
of propagating them through the identity lifecycle. Since `IdentityDID` already
implements `Serialize`/`Deserialize`, this is a low-risk change.

---

## 12. `MemberInvalidReason` — bare `String` fields to typed DIDs

**File:** `crates/auths-id/src/storage/registry/org_member.rs:120-146`

### Current

```rust
pub enum MemberInvalidReason {
    JsonParseError(String),
    SubjectMismatch {
        filename_did: String,
        attestation_subject: String,
    },
    IssuerMismatch {
        expected_issuer: String,
        actual_issuer: String,
    },
    Other(String),
}
```

### Proposed

```rust
use auths_verifier::types::{DeviceDID, IdentityDID};

pub enum MemberInvalidReason {
    JsonParseError(String),
    SubjectMismatch {
        filename_did: DeviceDID,
        attestation_subject: DeviceDID,
    },
    IssuerMismatch {
        expected_issuer: IdentityDID,
        actual_issuer: IdentityDID,
    },
    Other(String),
}
```

### Why

Error messages constructed from these fields currently display raw strings — but the
fields semantically _are_ DIDs. Typed fields mean Display formatting is consistent
(always `did:key:z6Mk...` or `did:keri:E...`) and prevents accidentally swapping an
issuer DID into a subject position. This also improves error diagnostics in the Radicle
bridge where member validation failures need to clearly identify which identity was
expected vs. found.

---

## 13. `MemberView` — bare `String` fields to typed equivalents

**File:** `crates/auths-id/src/storage/registry/org_member.rs:176-192`

### Current

```rust
pub struct MemberView {
    pub did: DeviceDID,
    pub status: MemberStatus,
    pub role: Option<String>,
    pub capabilities: Vec<String>,
    pub issuer: String,
    pub rid: String,
    // ...
}
```

### Proposed

```rust
pub struct MemberView {
    pub did: DeviceDID,
    pub status: MemberStatus,
    pub role: Option<Role>,
    pub capabilities: Vec<Capability>,
    pub issuer: IdentityDID,
    pub rid: ResourceId,
    // ...
}
```

### Why

`MemberView` is the primary query result for the org-member registry and is rendered
directly in CLI output and API responses. Every field that's currently a `String` has a
well-defined semantic type (`Role`, `Capability`, `IdentityDID`, `ResourceId`) that's
already defined elsewhere. Using them here ensures the view layer can never display
malformed data.

---

## 14. `BridgeError` — bare `String` context to structured variants

**File:** `crates/auths-radicle/src/bridge.rs:140-168`

### Current

```rust
pub enum BridgeError {
    IdentityLoad(String),
    AttestationLoad(String),
    IdentityCorrupt(String),
    PolicyEvaluation(String),
    InvalidDeviceKey(String),
    Repository(String),
}
```

### Proposed

```rust
use auths_verifier::types::{DeviceDID, IdentityDID};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("failed to load identity {did}: {reason}")]
    IdentityLoad { did: IdentityDID, reason: String },

    #[error("failed to load attestation for device {device_did}: {reason}")]
    AttestationLoad { device_did: DeviceDID, reason: String },

    #[error("identity {did} has corrupt KEL: {reason}")]
    IdentityCorrupt { did: IdentityDID, reason: String },

    #[error("policy evaluation failed for {did}: {reason}")]
    PolicyEvaluation { did: IdentityDID, reason: String },

    #[error("invalid device key: {reason}")]
    InvalidDeviceKey { reason: String },

    #[error("repository access error: {reason}")]
    Repository { reason: String },
}
```

### Why

Current `BridgeError` variants carry a single `String` that mixes the "what" (which
identity/device) with the "why" (what went wrong). Structured fields let the Heartwood
integration layer extract the DID for remediation (e.g., "fetch identity repo for
`did:keri:EABC...`") without parsing error messages. This was explicitly called out in
`fn-1.4` as needed to distinguish `IdentityLoad` (missing repo, actionable) from
`IdentityCorrupt` (corrupt data, investigate).

---

## 15. `WitnessConfig.witness_urls` — `Vec<String>` to `Vec<url::Url>`

**File:** `crates/auths-id/src/witness_config.rs:12`

### Current

```rust
pub struct WitnessConfig {
    pub witness_urls: Vec<String>,
    pub threshold: usize,
    pub timeout_ms: u64,
    pub policy: WitnessPolicy,
}
```

### Proposed

```rust
use url::Url;

pub struct WitnessConfig {
    pub witness_urls: Vec<Url>,
    pub threshold: usize,
    pub timeout_ms: u64,
    pub policy: WitnessPolicy,
}
```

### Why

Witness URLs are used to make HTTP requests. A malformed URL will fail at request time
with an opaque error. Using `url::Url` (which is already a dependency via
`reqwest`) validates at construction. This also lets witness URL comparison be
correct — `Url` normalizes trailing slashes, scheme casing, etc.

---

## 16. `ReceiptVerificationResult` — bare `String` fields to typed

**File:** `crates/auths-id/src/policy/mod.rs:245-255`

### Current

```rust
pub enum ReceiptVerificationResult {
    Valid,
    InsufficientReceipts { required: usize, got: usize },
    Duplicity { event_a: String, event_b: String },
    InvalidSignature { witness_did: String },
}
```

### Proposed

```rust
pub enum ReceiptVerificationResult {
    Valid,
    InsufficientReceipts { required: usize, got: usize },
    Duplicity { event_a: Said, event_b: Said },
    InvalidSignature { witness_did: DeviceDID },
}
```

### Why

`event_a` and `event_b` are KERI event SAIDs (Self-Addressing Identifiers) — the `Said`
newtype already exists and is used everywhere else in the KERI layer. `witness_did` is a
DID that identifies a witness node. Using typed fields ensures these values are
structurally valid when constructing the result, rather than trusting arbitrary strings
from the witness protocol.

---

## 17. `AgentIdentityBundle.agent_did` — bare `String` to `IdentityDID`

**File:** `crates/auths-id/src/agent_identity.rs:85`

### Current

```rust
pub struct AgentIdentityBundle {
    pub agent_did: String,
    pub key_alias: KeyAlias,
    pub attestation: Attestation,
    pub repo_path: Option<PathBuf>,
}
```

### Proposed

```rust
pub struct AgentIdentityBundle {
    pub agent_did: IdentityDID,
    pub key_alias: KeyAlias,
    pub attestation: Attestation,
    pub repo_path: Option<PathBuf>,
}
```

### Why

Same rationale as the SDK result types. `agent_did` is constructed from a KERI prefix
and must be a valid `did:keri:...` — using `IdentityDID` enforces this. The
`AgentProvisioningConfig.agent_name` field remains a `String` since it's a free-form
human label, not a DID.

---

## 18. Pairing types — base64url strings to typed wrappers

**File:** `crates/auths-core/src/pairing/types.rs:28-90`

### Current

```rust
pub struct CreateSessionRequest {
    pub ephemeral_pubkey: String,  // base64url
    // ...
}

pub struct SubmitResponseRequest {
    pub device_x25519_pubkey: String,    // base64url
    pub device_signing_pubkey: String,   // base64url
    pub device_did: String,
    pub signature: String,               // base64url
}
```

### Proposed

```rust
// crates/auths-core/src/pairing/types.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base64UrlEncoded(String);

impl Base64UrlEncoded {
    pub fn encode(bytes: &[u8]) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.decode(&self.0)
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

pub struct CreateSessionRequest {
    pub ephemeral_pubkey: Base64UrlEncoded,
    // ...
}

pub struct SubmitResponseRequest {
    pub device_x25519_pubkey: Base64UrlEncoded,
    pub device_signing_pubkey: Base64UrlEncoded,
    pub device_did: DeviceDID,
    pub signature: Base64UrlEncoded,
}
```

### Why

The pairing protocol is an HTTP API surface. These fields are base64url-encoded
cryptographic material but typed as `String` — making it possible to pass hex-encoded
or raw bytes. A `Base64UrlEncoded` wrapper ensures encoding consistency at the boundary.
The `device_did` field also gets typed as `DeviceDID` since it's always a `did:key:...`.

---

## 19. `OrgMemberEntry.org` — bare `String` to `IdentityDID`

**File:** `crates/auths-id/src/storage/registry/org_member.rs:150`

### Current

```rust
pub struct OrgMemberEntry {
    pub org: String,
    pub did: DeviceDID,
    pub filename: String,
    pub attestation: Result<Attestation, MemberInvalidReason>,
}
```

### Proposed

```rust
pub struct OrgMemberEntry {
    pub org: IdentityDID,
    pub did: DeviceDID,
    pub filename: GitRef,
    pub attestation: Result<Attestation, MemberInvalidReason>,
}
```

### Why

`org` is the organization's identity DID, not an arbitrary string. `filename` is a Git
ref path to the member's attestation blob. Both have well-defined types already in scope.

---

## 20. `VerifyResult` reason fields — structured context

**File:** `crates/auths-radicle/src/bridge.rs:39-84`

### Current

```rust
#[non_exhaustive]
pub enum VerifyResult {
    Verified { reason: String },
    Rejected { reason: String },
    Warn { reason: String },
    Quarantine { reason: String, identity_repo_rid: Option<RepoId> },
}
```

### Proposed

```rust
#[non_exhaustive]
pub enum VerifyResult {
    Verified { reason: VerifyReason },
    Rejected { reason: RejectReason },
    Warn { reason: WarnReason },
    Quarantine { reason: QuarantineReason, identity_repo_rid: Option<RepoId> },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifyReason {
    DeviceAttested,
    LegacyDidKey,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RejectReason {
    Revoked,
    Expired,
    NoAttestation,
    PolicyDenied { capability: String },
    KelCorrupt,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WarnReason {
    ObserveModeRejection(RejectReason),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QuarantineReason {
    StaleNode,
    MissingIdentityRepo,
    InsufficientKelSequence { have: u64, need: u64 },
}
```

### Why

The current `reason: String` fields are constructed ad-hoc in the verification pipeline
and consumed as display text. But the Heartwood integration needs to _act_ on these
reasons — e.g., if `Quarantine` is due to a stale node, Heartwood should trigger a
fetch; if due to KEL corruption, it should log and skip. Structured reason enums enable
`match`-based dispatch instead of string parsing. All enums are `#[non_exhaustive]` so
new reasons can be added without breaking downstream.

---

## Summary

| # | Type Change | Crate | Impact |
|---|------------|-------|--------|
| 1 | `Attestation.rid` -> `ResourceId` | auths-verifier | Medium (serialization boundary) |
| 2 | `Attestation.role` -> `Role` enum | auths-verifier | Low (additive) |
| 3 | `device_public_key` -> `Ed25519PublicKey` | auths-verifier, auths-core | High (pervasive) |
| 4 | signatures -> `Ed25519Signature` | auths-verifier | High (pervasive) |
| 5 | `Seal.seal_type` -> `SealType` enum | auths-id | Low (internal) |
| 6 | `StorageLayoutConfig` -> `GitRef`/`BlobName` | auths-id | Medium (storage layer) |
| 7 | Event `s` field -> `KeriSequence` | auths-id | Medium (KERI layer) |
| 8 | SDK result DIDs -> `IdentityDID`/`DeviceDID` | auths-sdk | High (public API) |
| 9 | `Vec<String>` capabilities -> `Vec<Capability>` | auths-sdk | Medium (public API) |
| 10 | `ResolvedDid` struct -> enum | auths-core | High (trait boundary) |
| 11 | `StoredIdentityData.controller_did` -> `IdentityDID` | auths-id | Low (internal) |
| 12 | `MemberInvalidReason` fields -> typed DIDs | auths-id | Low (error display) |
| 13 | `MemberView` fields -> typed | auths-id | Low (query results) |
| 14 | `BridgeError` -> structured variants | auths-radicle | Medium (error handling) |
| 15 | `witness_urls` -> `Vec<Url>` | auths-id | Low (config) |
| 16 | `ReceiptVerificationResult` -> typed fields | auths-id | Low (policy) |
| 17 | `AgentIdentityBundle.agent_did` -> `IdentityDID` | auths-id | Low (internal) |
| 18 | Pairing strings -> `Base64UrlEncoded` + `DeviceDID` | auths-core | Medium (API boundary) |
| 19 | `OrgMemberEntry` fields -> typed | auths-id | Low (internal) |
| 20 | `VerifyResult` reason -> enums | auths-radicle | Medium (bridge contract) |

### Recommended execution order

1. **Foundation types first** (1-4): `ResourceId`, `Role`, `Ed25519PublicKey`, `Ed25519Signature` in auths-verifier — everything else depends on these.
2. **Core internal types** (5-7, 15-16): `SealType`, `GitRef`/`BlobName`, `KeriSequence`, `Url`, receipt fields — contained within auths-id, no cross-crate ripple.
3. **Bridge types** (14, 20): Structured `BridgeError` and `VerifyResult` reasons — directly unblocks Heartwood integration quality.
4. **SDK public API** (8-10): Result DIDs, capabilities, `ResolvedDid` enum — highest-visibility changes, do last to minimize churn while foundation stabilizes.
5. **Remaining internal cleanup** (11-13, 17-19): Low-risk, low-impact — can be done opportunistically.
