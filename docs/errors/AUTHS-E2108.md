# AUTHS-E2108

**Crate:** `auths-verifier`

**Type:** `CommitVerificationError::UnknownSigner`

## Message

signer identity is not trusted (no matching pinned root)

## Suggestion

The signer's identity is not trusted here. Pin it with `auths trust pin --did <did>`, or add it to .auths/roots.
