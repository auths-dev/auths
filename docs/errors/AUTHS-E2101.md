# AUTHS-E2101

**Crate:** `auths-verifier`

**Type:** `CommitVerificationError::UnsignedCommit`

## Message

commit is unsigned

## Suggestion

This commit has no Auths-Id/Auths-Device trailer. Run `auths init` so the prepare-commit-msg hook signs future commits, or backfill with `auths sign <ref>`.
