# fn-7.7 Internal cleanup: typed DIDs across remaining structs

## Description

Final sweep: replace remaining bare `String` fields with typed equivalents across auths-id, auths-core, and auths-sdk. Low-risk changes that don't affect cross-crate public APIs.

Depends on fn-7.1 (ResourceId, Role) and fn-7.4 (GitRef, BlobName).

### 1. StoredIdentityData (crates/auths-id/src/storage/identity.rs ~line 18)

- `controller_did: String` → `IdentityDID` (~line 22)
- `StoredIdentityData` is a **private** struct — only visible within this file
- It is serialized to/from JSON in Git blobs via serde
- `IdentityDID` has `#[serde(transparent)]` wrapping a `String` — wire-compatible with existing stored data, no migration needed
- Already imported on line 9: `use auths_core::storage::keychain::IdentityDID;`

### 2. MemberInvalidReason (crates/auths-id/src/storage/registry/org_member.rs ~line 120)

- `SubjectMismatch.filename_did: String` → `DeviceDID`
- `SubjectMismatch.attestation_subject: String` → `DeviceDID`
- `IssuerMismatch.expected_issuer: String` → `IdentityDID`
- `IssuerMismatch.actual_issuer: String` → `IdentityDID`

### 3. MemberView (crates/auths-id/src/storage/registry/org_member.rs ~line 176)

Full struct has 10 fields — only changing the String-typed ones:
- `role: Option<String>` → `Option<Role>`
- `capabilities: Vec<String>` → `Vec<Capability>`
- `issuer: String` → `IdentityDID`
- `rid: String` → `ResourceId`
- Leave unchanged: `did: DeviceDID` (already typed), `status: MemberStatus`, `revoked_at`, `expires_at`, `timestamp`, `source_filename`

### 4. MemberFilter (crates/auths-id/src/storage/registry/org_member.rs ~line 37)

- `roles_any: Option<HashSet<String>>` → `Option<HashSet<Role>>`
- `capabilities_any: Option<HashSet<String>>` → `Option<HashSet<Capability>>`

### 5. AgentIdentityBundle (crates/auths-id/src/agent_identity.rs ~line 85)

- `agent_did: String` → `IdentityDID`

### 6. Pairing types (crates/auths-core/src/pairing/types.rs)

Add `Base64UrlEncoded` wrapper:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Base64UrlEncoded(String);

impl Base64UrlEncoded {
    pub fn encode(bytes: &[u8]) -> Self { ... }
    pub fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> { ... }
    pub fn as_str(&self) -> &str { &self.0 }
}
```

`CreateSessionRequest` has 6 fields (~line 27): `session_id`, `controller_did`, `ephemeral_pubkey`, `short_code`, `capabilities: Vec<String>`, `expires_at: i64`.
`SubmitResponseRequest` has 5 fields (~line 60): `device_x25519_pubkey`, `device_signing_pubkey`, `device_did`, `signature`, `device_name: Option<String>`.

Update:
- `CreateSessionRequest.ephemeral_pubkey: String` → `Base64UrlEncoded`
- `CreateSessionRequest.controller_did: String` → stay `String` (identity context, not base64)
- `CreateSessionRequest.expires_at: i64` → stay `i64` (Unix timestamp, not a DID/key)
- `SubmitResponseRequest.device_x25519_pubkey: String` → `Base64UrlEncoded`
- `SubmitResponseRequest.device_signing_pubkey: String` → `Base64UrlEncoded`
- `SubmitResponseRequest.device_did: String` → `DeviceDID`
- `SubmitResponseRequest.signature: String` → `Base64UrlEncoded`
- `SubmitResponseRequest.device_name: Option<String>` → stay `Option<String>` (human-readable label)

Both types derive `schemars::JsonSchema`. `Base64UrlEncoded` MUST also derive `JsonSchema` (or provide a manual impl). Since `#[serde(transparent)]` wraps a `String`, `#[derive(JsonSchema)]` should work cleanly. `DeviceDID` will also need a `JsonSchema` impl if not already present — check `auths_verifier::types`.

### 7. OrgMemberEntry (crates/auths-id/src/storage/registry/org_member.rs ~line 149)

Full struct has 4 fields: `org`, `did: DeviceDID` (already typed), `filename`, `attestation: Result<Attestation, MemberInvalidReason>`.
- `org: String` → `IdentityDID`
- `filename: String` → `GitRef` (from fn-7.4)

### Quick commands

```bash
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths_cli --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `StoredIdentityData.controller_did` is `IdentityDID`
- [ ] `MemberInvalidReason` fields use `DeviceDID`/`IdentityDID`
- [ ] `MemberView` uses `Role`, `Capability`, `IdentityDID`, `ResourceId`
- [ ] `MemberFilter` uses `HashSet<Role>`/`HashSet<Capability>`
- [ ] `AgentIdentityBundle.agent_did` is `IdentityDID`
- [ ] `Base64UrlEncoded` wrapper with `#[serde(transparent)]`
- [ ] Pairing types use `Base64UrlEncoded` and `DeviceDID`
- [ ] `OrgMemberEntry.org` is `IdentityDID`, `.filename` is `GitRef`
- [ ] Serde compatibility preserved (all `#[serde(transparent)]` wrappers — wire format unchanged)
- [ ] `DeviceDID` has `JsonSchema` impl (required for pairing types)
- [ ] `cargo build -p auths-id --all-features` passes
- [ ] `cargo build -p auths-core --all-features` passes
- [ ] `cargo nextest run --workspace` passes

## Done summary
Replaced bare String fields with typed equivalents across auths-id, auths-core, auths-sdk, auths-storage, and auths-cli. Added Base64UrlEncoded newtype for pairing types. All 655 tests pass.
## Evidence
- Commits: 0747aeb
- Tests: auths-id, auths-sdk, auths-core
- PRs:
