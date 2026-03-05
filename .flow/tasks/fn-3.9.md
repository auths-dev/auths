# fn-3.9 Write RIP-X specification document

## Description
Write the formal RIP-X specification document covering the `did:keri` delegate type, ref layout, attestation format, and multi-device lifecycle for Radicle.

## Problem

The Radicle integration requires a protocol-level change (adding `did:keri` as a delegate type). This needs a Radicle Improvement Proposal. Having a well-specified document in the auths repo serves as the basis for the upstream RIP submission.

## Content

Draft `docs/rip-x-multi-device-identity.md` covering:

1. **Abstract**: Multi-device identity for Radicle using KERI-inspired identity management
2. **Motivation**: Why single-key identity is limiting (device loss, multi-machine workflows)
3. **Specification**:
   - `did:keri` delegate type in identity documents
   - Identity repository layout (ref paths from `refs.rs`)
   - KEL format and commit chain structure at `refs/keri/kel`
   - Attestation format: 2-blob signatures at `refs/keys/<nid>/signatures/`
   - `RadCanonicalPayload` (JCS RFC 8785) for deterministic serialization
   - Threshold counting with identity deduplication
   - Mixed delegate sets (`did:key` + `did:keri`)
4. **Verification Pipeline**: How the bridge verifies signers during fetch
5. **Lifecycle Operations**: Creation, device linking, revocation, key rotation
6. **Migration**: Backward compatibility with existing `did:key`-only projects
7. **Security Considerations**: Duplicity detection, replay prevention, staleness handling

## Key References
- `crates/auths-radicle/src/refs.rs` -- canonical ref paths
- `crates/auths-radicle/src/bridge.rs` -- bridge interface
- `crates/auths-radicle/src/attestation.rs` -- attestation format
- `docs/plans/full_radicle_integration.md` -- existing planning doc
- [Radicle Protocol Guide](https://radicle.xyz/guides/protocol)
- [KERI IETF Draft](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [did:keri Method v0.1](https://identity.foundation/keri/did_methods/)

## Note
This is a specification document, not implementation code. It should be precise enough to implement from and serve as the basis for an upstream RIP submission to `radicle-dev/rips`.

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `docs/rip-x-multi-device-identity.md` exists
- [ ] Covers: abstract, motivation, specification, verification pipeline, lifecycle, migration, security
- [ ] Ref paths match `auths-radicle/src/refs.rs` constants exactly
- [ ] Attestation format matches `RadAttestation` / `RadCanonicalPayload`
- [ ] Threshold counting rules specify identity deduplication
- [ ] Mixed delegate backward compatibility addressed
- [ ] Security considerations cover: duplicity, replay, staleness, shallow clones
## Done summary
Wrote RIP-X specification document covering delegate types, identity repo layout, KEL format, attestation format, threshold counting (Person Rule), verification pipeline, enforcement modes, lifecycle operations, migration, and security considerations.
## Evidence
- Commits: 83a6975
- Tests:
- PRs:
