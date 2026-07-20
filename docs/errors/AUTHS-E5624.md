# AUTHS-E5624

**Crate:** `auths-sdk`

**Type:** `OrgError::PolicyIntegrity`

## Message

org policy integrity failure: KEL committed hash '{expected}' but the stored blob hashes to '{actual}'

## Suggestion

The stored policy was modified after anchoring; re-anchor a trusted policy with `auths org policy set`
