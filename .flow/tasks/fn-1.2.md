# fn-1.2 Attestation to/from bytes for RIP-X 2-blob format

## Description
Implement serialization/deserialization for the RIP-X 2-blob attestation format. RIP-X stores attestation signatures as two separate Git blobs (`did-key` containing the device signature, `did-keri` containing the identity signature), unlike auths' existing single-JSON `Attestation` struct.

### What to implement

1. Define `RadCanonicalPayload` struct: the signing payload is `(RID, other_did)` per RIP-X. This differs from the existing `CanonicalAttestationData` (14 fields) at `crates/auths-verifier/src/core.rs:444`. **JCS ordering**: Fields must be strictly ordered for JSON Canonicalization Scheme (RFC 8785) to ensure signature stability across different language implementations (Heartwood Rust, potential future Go/JS clients).
2. Add `RadAttestation` type in `crates/auths-radicle/src/` that represents the 2-blob format:
   - `device_signature: Vec<u8>` (contents of `did-key` blob)
   - `identity_signature: Vec<u8>` (contents of `did-keri` blob)
   - `canonical_payload: RadCanonicalPayload` (the signed data)
3. Implement:
   - `RadAttestation::to_blobs() -> (Vec<u8>, Vec<u8>)` — (did-key bytes, did-keri bytes)
   - `RadAttestation::from_blobs(did_key: &[u8], did_keri: &[u8], payload: RadCanonicalPayload) -> Self`
   - `RadAttestation::verify(&self, device_pubkey: &[u8; 32], identity_pubkey: &[u8; 32]) -> Result<(), VerifyError>` — verifies both signatures
4. The canonical payload for signing: `json_canon::to_string(&RadCanonicalPayload { rid, did })` — must match what Heartwood's fn-5.3 produces.

### Design note

Keeping `RadAttestation` separate from the core `Attestation` prevents the core from becoming a "God Object." The bridge converts between formats at the boundary.

### Key context

- The existing `Attestation` struct at `crates/auths-verifier/src/core.rs:330-381` will NOT be modified. `RadAttestation` is a separate type for the Radicle-specific format.
- Signature verification uses `ring::signature::UnparsedPublicKey::verify()` — same as existing auths crypto.
- The bridge will convert `RadAttestation` into an `Attestation`-compatible form for policy evaluation.
- `json_canon` crate is already used in auths for canonical serialization.

### Affected files
- New: `crates/auths-radicle/src/attestation.rs` (or add to existing module)
- Modified: `crates/auths-radicle/src/lib.rs` (export new module)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `RadCanonicalPayload` struct defined with `rid: String` and `did: String` fields
- [ ] `RadCanonicalPayload` field ordering is JCS-compliant (RFC 8785) — stable across implementations
- [ ] `RadAttestation::to_blobs()` produces two byte arrays (did-key, did-keri)
- [ ] `RadAttestation::from_blobs()` round-trips correctly
- [ ] `RadAttestation::verify()` validates both signatures against canonical payload
- [ ] Reject truncated/corrupt blobs with clear error
- [ ] Reject mismatched RID (tamper detection)
- [ ] Reject swapped did-key/did-keri blobs (signature mismatch)
- [ ] `cargo test -p auths-radicle` passes
- [ ] `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm` still passes (verifier not broken)
## Done summary
- Added `crates/auths-radicle/src/attestation.rs` with RadCanonicalPayload and RadAttestation
- JCS-compliant field ordering (did before rid)
- from_blobs/to_blobs round-trip, verify() with Ed25519
- 7 unit tests covering valid sigs, swapped blobs, tampered RID, truncated/empty blobs
## Evidence
- Commits: 9bf39a7
- Tests: cargo nextest run -p auths-radicle -E test(attestation)
- PRs:
