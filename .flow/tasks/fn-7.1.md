# fn-7.1 Add ResourceId and Role newtypes in auths-verifier

## Description

Add `ResourceId` newtype and `Role` enum in `crates/auths-verifier/src/core.rs`. Update `Attestation.rid` to `ResourceId` and `Attestation.role` to `Option<Role>`. The verifier currently stores role as `Option<String>` — no Role enum exists there today. The SDK defines a standalone `Role` enum in `org.rs`; once the verifier's canonical `Role` is created, the SDK's version should be deleted and replaced with a re-export. Update all Attestation construction sites.

### Types to add (in core.rs)

**ResourceId:**
- `#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]`
- `#[serde(transparent)]` — JSON output identical to bare String
- Methods: `new(impl Into<String>)`, `as_str() -> &str`
- Impls: `Deref<Target=str>`, `Display`, `From<String>`, `From<&str>`

**Role:**
- `#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]`
- `#[serde(rename_all = "lowercase")]` — produces `"admin"`, `"member"`, `"readonly"`
- Variants: `Admin`, `Member`, `Readonly`
- Impls: `Display` (lowercase), `FromStr` with `RoleParseError`
- Method: `default_capabilities() -> Vec<Capability>` (migrated from auths-sdk)
- Do NOT add `#[non_exhaustive]` — pre-launch, exhaustive matching is more useful

### Attestation field changes (core.rs ~line 330)

- `rid: String` → `rid: ResourceId`
- `role: Option<String>` → `role: Option<Role>`

### CanonicalAttestationData (core.rs ~line 445)

- Keep `rid: &'a str` and `role: Option<&'a str>` — do NOT change these
- Update `from()` to convert: `rid: att.rid.as_str()`, `role: att.role.as_ref().map(|r| r.as_str())`
- This preserves byte-identical canonical JSON for signature stability — critical for verification of existing attestations stored in Git

### Re-exports (lib.rs)

Add `ResourceId`, `Role`, `RoleParseError` to `pub use core::{...}` block

### SDK consolidation (auths-sdk/src/workflows/org.rs)

- Delete the SDK-local `Role` enum (~line 20, variants: Admin, Member, Readonly) and its `Display` impl
- Replace with `use auths_verifier::Role`
- Update `member_role_order()` to match on `Role` enum variants
- Update `AddMemberCommand.role: String` → `role: Role`
- Update `add_organization_member()` to pass `Role` instead of String

### Attestation construction sites to update

All sites need `rid: ResourceId::new(...)` and `role: Some(Role::Admin)` etc. Grep for `rid:` within Attestation struct literals to find all sites. Key files:
- `crates/auths-verifier/src/core.rs` (tests, IdentityBundle::build_*)
- `crates/auths-verifier/src/verify.rs`
- `crates/auths-verifier/src/lib.rs` (tests)
- `crates/auths-verifier/src/ffi.rs`
- `crates/auths-verifier/src/wasm.rs`
- `crates/auths-id/src/attestation.rs`
- `crates/auths-id/src/device.rs`
- `crates/auths-id/src/revocation.rs`
- `crates/auths-id/src/rotation.rs`
- `crates/auths-id/src/storage/registry/org_member.rs`
- `crates/auths-core/src/signing.rs`
- `crates/auths-sdk/src/workflows/org.rs`
- `crates/auths-sdk/src/workflows/setup.rs`
- `crates/auths-sdk/src/workflows/device.rs`
- `crates/auths-radicle/src/bridge.rs`
- `crates/auths-radicle/src/attestation.rs`
- Test files in `tests/` directories

### Policy engine boundary

`auths-policy` stays string-based. Where `Role` is converted for policy eval:
- `crates/auths-sdk/src/workflows/org.rs` — `role.to_string()` for `EvalContext`
- Any site passing role to policy builder

### Quick commands

```bash
cargo build -p auths-verifier --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths_cli --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `ResourceId` newtype with `#[serde(transparent)]`, Deref, Display, From
- [ ] `Role` enum (Admin, Member, Readonly) with `#[serde(rename_all = "lowercase")]`
- [ ] `RoleParseError` thiserror type
- [ ] `Attestation.rid` is `ResourceId`, `Attestation.role` is `Option<Role>`
- [ ] `CanonicalAttestationData` still uses `&str`/`Option<&str>` — canonical JSON unchanged
- [ ] SDK `Role` enum deleted, re-exported from auths-verifier
- [ ] All Attestation construction sites compile (grep for `rid:` in Attestation literals)
- [ ] `cargo build -p auths-verifier --all-features` passes
- [ ] `cargo build -p auths-sdk --all-features` passes
- [ ] WASM target: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] `cargo nextest run --workspace` passes (type changes can break tests even when builds pass)

## Done summary
Added ResourceId and Role newtypes to auths-verifier core.rs. ResourceId wraps String with transparent serde, Deref<Target=str>, PartialEq<str/&str/String>. Role enum has Admin/Member/Readonly with serde rename_all lowercase. Deleted duplicate SDK Role enum, re-exported from auths-verifier. Updated all 27 files across workspace. CanonicalAttestationData unchanged for signature stability.
## Evidence
- Commits:
- Tests:
- PRs:
