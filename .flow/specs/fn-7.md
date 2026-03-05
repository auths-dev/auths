# fn-7 Type Safety Audit: Replace stringly-typed fields with newtypes

## Overview

Pre-v0.1.0 type safety audit. Replace bare `String`, `Vec<u8>`, and `Vec<String>` fields with semantic newtypes across 20 locations in 7 crates. Prevents cross-field confusion, typo-based mismatches, and wrong-length bugs — especially at the Radicle/Heartwood integration boundary where auths-radicle is the single interface.

## Scope

20 type changes across auths-verifier, auths-core, auths-id, auths-sdk, auths-radicle, auths-storage, auths-policy. Full details in `docs/plans/typing_improvement.md`.

**In scope:** All 20 items from the plan.
**Out of scope:** ChainLink.issuer/subject typing (VerificationReport wire format), DidResolver trait parameter typing, WitnessKeyResolver parameter typing.

## Approach

### Execution order (dependency-driven)

1. Foundation types in auths-verifier (items 1-4): ResourceId, Role, Ed25519PublicKey, Ed25519Signature
2. auths-id internal types (items 5-7, 15-16): SealType, KeriSequence, GitRef/BlobName, Url, receipt fields
3. auths-radicle bridge types (items 14, 20): BridgeError, VerifyResult reason enums
4. SDK public API (items 8-10): Result DIDs, capabilities, ResolvedDid enum
5. Internal cleanup (items 11-13, 17-19): Remaining typed DIDs across structs

### Key design decisions

1. **CanonicalAttestationData stays `&str` / `&[u8]`**: Convert via `.as_str()` / `.as_bytes()` at boundary. This guarantees byte-identical canonical JSON, preserving all existing attestation signatures.

2. **Role serde**: `#[serde(rename_all = "lowercase")]` producing `"admin"`, `"member"`, `"readonly"`. Strict 3-variant enum. Unknown roles in stored JSON will fail deserialization — acceptable for pre-launch.

3. **Ed25519PublicKey/Signature serde**: Custom `Serialize`/`Deserialize` using `hex::serde` on the inner `[u8; N]` array. JSON output is identical hex string. Use `#[serde(default)]` + `Ed25519Signature::is_empty()` for skip_serializing_if on identity_signature.

4. **Policy engine stays string-based**: `EvalContext.role: Option<String>` unchanged. The adapter boundary converts `Role` to `String` via `.to_string()`. The policy crate does NOT import Role from auths-verifier.

5. **Newtypes use `#[serde(transparent)]`** for string wrappers (ResourceId, GitRef, BlobName): JSON output identical to bare String.

6. **Org member attestations**: Use `Ed25519PublicKey::from_bytes([0u8; 32])` and `Ed25519Signature::empty()` for unsigned org member attestations. Zero-value arrays represent "not set".

## Quick commands

- `cargo build -p auths-verifier --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths-core --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths-id --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths-sdk --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths-storage --all-features 2>&1 | grep "^error\[E" -A 10`
- `cargo build -p auths_cli --all-features 2>&1 | grep "^error\[E" -A 10`

## Risks

- **Canonical JSON stability**: Mitigated by keeping CanonicalAttestationData fields as `&str`/`&[u8]` and converting at boundary.
- **27 Attestation construction sites**: Each foundation type task (1-3) must update ALL sites or code won't compile. Mechanical but labor-intensive.
- **Ed25519Signature empty semantics**: `Vec::is_empty()` (len=0) differs from `Ed25519Signature::is_empty()` (all zeros). Acceptable for pre-launch.
- **DidResolver implementors**: ResolvedDid struct→enum affects all implementors. Known: auths-id resolve.rs, auths-radicle identity.rs.

## Acceptance

- [ ] All 20 type changes implemented per docs/plans/typing_improvement.md
- [ ] `cargo build -p <each-crate> --all-features` passes for all 7 crates
- [ ] No serde-breaking changes for canonical JSON (attestation signatures)
- [ ] Role serializes as lowercase strings matching existing convention
- [ ] Ed25519PublicKey/Signature hex round-trips correctly

## References

- `docs/plans/typing_improvement.md` — full details on each change
- Serde patterns: `#[serde(transparent)]` for string newtypes, custom Serialize/Deserialize for hex bytes
- Existing examples: `Capability` (try_from/into), `KeriDid` (try_from/into), `KeyAlias` (transparent), `SessionStatus` (rename_all lowercase)
