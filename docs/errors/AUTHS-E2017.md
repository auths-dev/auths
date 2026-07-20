# AUTHS-E2017

**Crate:** `auths-verifier`

**Type:** `AttestationError::BundleExpired`

## Message

Bundle is {age_secs}s old (max {max_secs}s). Refresh with: auths id export-bundle

## Suggestion

Re-export the bundle: auths id export-bundle --alias <ALIAS> --output bundle.json --max-age-secs <SECS>
