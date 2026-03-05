# fn-7.2 Add Ed25519PublicKey newtype, replace Vec<u8>

## Description

Add `Ed25519PublicKey([u8; 32])` newtype in `crates/auths-verifier/src/core.rs`. Replace `Vec<u8>` public key fields across auths-verifier and auths-core. Custom hex serde to maintain JSON compatibility.

### Type to add (in core.rs)

**Ed25519PublicKey:**
- `#[derive(Debug, Clone, PartialEq, Eq, Hash)]`
- Inner: `[u8; 32]`
- Methods: `from_bytes([u8; 32])`, `try_from_slice(&[u8]) -> Result<Self, Ed25519KeyError>`, `as_bytes() -> &[u8; 32]`
- Custom `Serialize`: hex-encode the 32 bytes (matches existing `#[serde(with = "hex::serde")]` output)
- Custom `Deserialize`: hex-decode, validate exactly 32 bytes
- `Display`: hex-encoded string

**Ed25519KeyError:**
- `#[derive(Debug, thiserror::Error)]`
- `#[error("expected 32 bytes, got {0}")]` `InvalidLength(usize)`
- `#[error("invalid hex: {0}")]` `InvalidHex(String)`

### Serde implementation detail

Use `hex::serde` helpers on the inner array. `hex::serde` works on types implementing `hex::FromHex` — `[u8; 32]` implements this natively. No intermediate Vec allocation needed:
```rust
impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex::serde::serialize(self.0, s)
    }
}
```

### Fields to change

1. **`Attestation.device_public_key: Vec<u8>`** → `Ed25519PublicKey` (core.rs ~line 343)
   - Remove `#[serde(with = "hex::serde")]` annotation (handled by custom Serialize/Deserialize)

2. **`ResolvedDid.public_key: Vec<u8>`** → `Ed25519PublicKey` (auths-core/src/signing.rs ~line 92)
   - ResolvedDid is NOT serialized — pure API change

3. **`ResolvedIdentity.public_key: Vec<u8>`** → `Ed25519PublicKey` (auths-core/src/ports/network.rs ~line 126)
   - Note: `ResolvedDid` and `ResolvedIdentity` are structurally identical but separate types — both need updating independently

### CanonicalAttestationData (core.rs ~line 443)

- Keep `device_public_key: &'a [u8]`
- Update `from()`: `device_public_key: att.device_public_key.as_bytes()`

### Org member attestations

Sites that construct `Attestation` with `device_public_key: vec![]` (unsigned org members):
- Use `Ed25519PublicKey::from_bytes([0u8; 32])` — zero-value array means "not set"
- Primary site: `crates/auths-sdk/src/workflows/org.rs` `add_organization_member()`

### All construction/usage sites

Same Attestation construction sites as fn-7.1 plus:
- `crates/auths-verifier/src/verify.rs` — `did_to_ed25519()` returns `Vec<u8>`, callers convert
- `crates/auths-core/src/signing.rs` — `ResolvedDid` construction
- `crates/auths-core/src/ports/network.rs` — `ResolvedIdentity` construction
- `crates/auths-id/src/resolve.rs` — builds ResolvedDid
- `crates/auths-radicle/src/identity.rs` — builds ResolvedDid from radicle_crypto::PublicKey

### Quick commands

```bash
cargo build -p auths-verifier --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10
```

## Acceptance

- [ ] `Ed25519PublicKey([u8; 32])` with custom hex serde
- [ ] `Ed25519KeyError` thiserror enum
- [ ] `Attestation.device_public_key` is `Ed25519PublicKey`
- [ ] `ResolvedDid.public_key` is `Ed25519PublicKey`
- [ ] `ResolvedIdentity.public_key` is `Ed25519PublicKey`
- [ ] `CanonicalAttestationData.device_public_key` stays `&[u8]`
- [ ] Hex round-trip: serialize → deserialize produces identical key
- [ ] Zero-value key used for unsigned org member attestations
- [ ] `cargo build -p auths-verifier --all-features` passes
- [ ] `cargo build -p auths-core --all-features` passes
- [ ] WASM target: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] `cargo nextest run --workspace` passes

## Done summary
Added Ed25519PublicKey([u8; 32]) newtype to auths-verifier/src/core.rs. Changed Attestation.device_public_key from Vec<u8> to Ed25519PublicKey. Updated ResolvedDid.public_key and ResolvedIdentity.public_key. Fixed 35 files across workspace including all tests. WASM target compiles clean.
## Evidence
- Commits:
- Tests:
- PRs:
