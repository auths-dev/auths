# fn-7.3 Add Ed25519Signature newtype, replace Vec<u8>

## Description

Add `Ed25519Signature([u8; 64])` newtype in `crates/auths-verifier/src/core.rs`. Replace `Vec<u8>` signature fields in Attestation. Custom hex serde. Handle empty/unsigned signatures via zero-value array.

Depends on fn-7.2 (Ed25519PublicKey) being complete since both are defined in core.rs and share patterns.

### Type to add (in core.rs)

**Ed25519Signature:**
- `#[derive(Debug, Clone, PartialEq, Eq)]`
- Inner: `[u8; 64]`
- Methods: `from_bytes([u8; 64])`, `try_from_slice(&[u8]) -> Result<Self, SignatureLengthError>`, `as_bytes() -> &[u8; 64]`, `empty() -> Self` (returns `[0u8; 64]`), `is_empty() -> bool` (all zeros check)
- Custom `Serialize`/`Deserialize` via hex (same pattern as Ed25519PublicKey)
- `Display`: hex-encoded string

**SignatureLengthError:**
- `#[derive(Debug, thiserror::Error)]`
- `#[error("expected 64 bytes, got {0}")]` — single variant

### Default/serde behavior for empty signatures

Current code uses `#[serde(default, skip_serializing_if = "Vec::is_empty")]` on `identity_signature`.
With the newtype:
- `#[serde(default)]` requires `impl Default for Ed25519Signature` returning `Ed25519Signature::empty()`
- `#[serde(skip_serializing_if = "Ed25519Signature::is_empty")]`
- Semantic change: `Vec::is_empty()` = len 0, `Ed25519Signature::is_empty()` = all zeros. Acceptable for pre-launch.

### Fields to change (core.rs Attestation)

- `identity_signature: Vec<u8>` → `Ed25519Signature` (~line 344-346)
  - Current annotation: `#[serde(with = "hex::serde", default, skip_serializing_if = "Vec::is_empty")]` (all on one attribute)
  - Replace with: `#[serde(default, skip_serializing_if = "Ed25519Signature::is_empty")]`
- `device_signature: Vec<u8>` → `Ed25519Signature` (~line 347-349)
  - Current annotation: `#[serde(with = "hex::serde")]` only — note there is NO `skip_serializing_if` on this field (asymmetric with identity_signature)
  - Remove the `#[serde(with = "hex::serde")]` annotation; custom Serialize/Deserialize on the newtype handles it

### CanonicalAttestationData

- Keep `identity_signature: &'a [u8]` and `device_signature: &'a [u8]`
- Update `from()`: `.identity_signature: att.identity_signature.as_bytes()`, `.device_signature: att.device_signature.as_bytes()`

### Org member attestations

Sites that construct `Attestation` with `identity_signature: vec![]` and `device_signature: vec![]`:
- Use `Ed25519Signature::empty()` — zero-value array means "not yet signed"
- Primary site: `crates/auths-sdk/src/workflows/org.rs`

### Construction/verification sites

All Attestation construction sites (same as fn-7.1) plus:
- `crates/auths-verifier/src/verify.rs` — signature verification calls `.as_bytes()` instead of slice
- `crates/auths-id/src/attestation.rs` — signing fills in signature bytes
- `crates/auths-radicle/src/attestation.rs` — RadAttestation conversion

### Quick commands

```bash
cargo build -p auths-verifier --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `Ed25519Signature([u8; 64])` with custom hex serde
- [ ] `SignatureLengthError` thiserror type
- [ ] `empty()` returns `[0u8; 64]`, `is_empty()` checks all zeros
- [ ] `Default` impl returns `empty()`
- [ ] `Attestation.identity_signature` and `device_signature` are `Ed25519Signature`
- [ ] `skip_serializing_if` works with `is_empty()`
- [ ] Canonical data fields stay `&[u8]`
- [ ] Hex round-trip: serialize → deserialize produces identical signature
- [ ] `cargo build -p auths-verifier --all-features` passes
- [ ] WASM target: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] `cargo nextest run --workspace` passes

## Done summary
Added Ed25519Signature newtype, replaced Vec<u8> across 25 files
## Evidence
- Commits:
- Tests:
- PRs:
