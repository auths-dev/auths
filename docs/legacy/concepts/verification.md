# Verification

Verification answers: **"Was this signed by an authorized device?"**

!!! note "You don't need to care about this unless..."
    You're integrating Auths verification into a server, CI pipeline, or custom tool. For checking commit signatures, just run `auths verify-commit`. This page explains what happens under the hood for people building on the verifier crate or SDKs.

## Two levels of verification

### Single attestation

Verify one attestation against an issuer's public key:

- Is the `identity_signature` valid?
- Is the `device_signature` valid?
- Is the attestation expired? Revoked?

This is done by `verify_with_keys()`.

### Chain verification

Verify a chain of attestations from root identity to leaf device:

- Does each link's `subject` match the next link's `issuer`?
- Are all individual signatures valid?
- Is the chain unbroken?

This is done by `verify_chain()`.

## Verification statuses

| Status | Meaning |
|--------|---------|
| `Valid` | All checks passed |
| `Expired` | The attestation's `expires_at` is in the past |
| `Revoked` | The attestation's `revoked` flag is true |
| `InvalidSignature` | A signature failed verification |
| `BrokenChain` | The chain has a gap (subject/issuer mismatch) |

## What verification does NOT do

- **Resolve DIDs over a network** -- Auths verification is purely local
- **Check a revocation server** -- Revocation is embedded in the attestation
- **Validate the issuer's authority** -- The caller provides the trusted root key
- **Fetch attestations from Git** -- The caller provides attestation data

Verification is a pure function: data in, result out.

## The verifier crate

`auths-verifier` is intentionally minimal:

- No `git2` dependency
- No network I/O
- No platform-specific code (except optional FFI/WASM)
- Suitable for embedding anywhere

This makes it safe to use in:

- CI pipelines
- Web browsers (via WASM)
- Mobile apps (via UniFFI/FFI)
- Backend servers
- Edge functions

## Clock skew

The verifier allows a 5-minute clock skew tolerance (`MAX_SKEW_SECS = 300`) for expiration checks. Attestations created slightly in the future (within the tolerance) are accepted. Systems with significantly wrong clocks may produce incorrect results.
