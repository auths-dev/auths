# Radicle Integration Cleanup & Type Safety Plan

## Objective
Enhance the integration between `auths` and `radicle` (Heartwood) by enforcing extreme type safety, centralizing Radicle-specific logic within the `auths-radicle` crate, and ensuring a seamless "just works" experience for Radicle users.

## 1. Extreme Type Safety & Architectural Alignment

### Problem
Current implementations in `auths-radicle` use generic types like `String` and `Vec<u8>` for domain-specific identifiers (DIDs, RIDs) and cryptographic keys. This increases the risk of runtime errors and makes the code less expressive compared to the `radicle` codebase.

### Proposed Changes
- **Dependency Integration**: Add the `radicle` crate (from Heartwood) as a dependency to `auths-radicle`. This allows direct use of established types.
- **Unified DID Type**: Replace `String` with `radicle::identity::Did` in:
    - `RadicleIdentity::primary_did`
    - `RadicleIdentityDocument::delegates`
    - `RadCanonicalPayload::did`
    - `RadAttestation::device_did`
- **Unified Repository ID (RID)**: Replace `String` with `radicle::identity::RepoId` in:
    - `RadCanonicalPayload::rid`
- **Stronger Key Types**: Use `radicle::crypto::PublicKey` instead of `Vec<u8>` or `[u8; 32]` where appropriate, ensuring alignment with Radicle's cryptographic expectations.
- **Document Alignment**: Consider using `radicle::identity::Doc` or a subset that is strictly compatible, instead of the simplified `RadicleIdentityDocument`.

## 2. Centralizing Radicle Logic in `auths-radicle`

### Problem
Radicle-specific logic (e.g., RIP-X ref paths, 2-blob attestation formats) should be contained within `auths-radicle` to keep the core `auths` crates (`auths-id`, `auths-verifier`) protocol-agnostic.

### Proposed Changes
- **Ref Path Isolation**: Ensure all RIP-X ref path construction (e.g., `refs/keri/kel`, `refs/keys/<nid>/signatures/did-key`) remains exclusively in `auths-radicle::refs`.
- **Bridge-Based Verification**: The `RadAttestation` type in `auths-radicle` should continue to act as the primary bridge, converting to the core `Attestation` type only when necessary for policy evaluation in `auths-verifier`.
- **Identity Resolution**: `RadicleIdentityResolver` should be the high-level entry point that abstracts away KERI/KEL complexities.

## 3. "Just Works" User Experience

### Goal
Radicle users should interact with high-level Radicle concepts without needing to understand the underlying KERI machinery.

### Proposed Changes
- **Abstract KERI Complexity**: The `RadicleIdentityResolver` should handle KEL discovery and replay internally. A user should simply "resolve a DID" and get back a verified identity.
- **Seamless Attestation**: Loading a `RadAttestation` from Git should automatically verify both the device and identity signatures if the necessary keys are available in the local repository or identity repo.
- **Unified Storage Access**: Use the `auths-radicle::refs` constants to ensure `auths` tools and `radicle` tools are always looking at the same Git refs.

## 4. Implementation Checklist

### Phase 1: Dependency & Type Refactoring
- [ ] Add `radicle = { path = "../../../../heartwood/crates/radicle" }` to `auths-radicle/Cargo.toml`.
- [ ] Update `crates/auths-radicle/src/identity.rs`:
    - Replace `primary_did: String` with `primary_did: Did`.
    - Replace `primary_public_key: Vec<u8>` with `primary_public_key: PublicKey`.
    - Update `RadicleIdentityDocument` to use `Did` and `RepoId`.
- [ ] Update `crates/auths-radicle/src/attestation.rs`:
    - Update `RadCanonicalPayload` to use `Did` and `RepoId`.
    - Update `RadAttestation` to use `Did` and `PublicKey`.

### Phase 2: Logic Audit & Cleanup
- [ ] Audit `auths-id` for any leaked Radicle logic (e.g., ref paths).
- [ ] Audit `auths-verifier` for Radicle-specific payload handling.
- [ ] Ensure `auths-radicle` is the only crate that knows about `refs/rad/id` or `refs/keri/kel`.

### Phase 3: Verification & UX
- [ ] Update existing tests in `auths-radicle` to use the new types.
- [ ] Add integration tests verifying that a Radicle `Doc` can be resolved via `RadicleIdentityResolver`.
- [ ] Ensure `cargo clippy` and `cargo test` pass across all crates.
