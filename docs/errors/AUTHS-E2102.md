# AUTHS-E2102

**Crate:** `auths-verifier`

**Type:** `CommitVerificationError::GpgNotSupported`

## Message

GPG signatures are not verified by Auths — use did:keri trailers via `auths init`

## Suggestion

Auths verifies its own did:keri commit trailers, not GPG or SSH signatures. Run `auths init` to enable Auths signing.
