# E2E Test Gap Report

## CLI Commands Missing --json Support

| Command | Current Output | Impact |
|---------|---------------|--------|
| `auths init` | Text only | Cannot validate init result programmatically |
| `auths status` | Text only (--json may not be implemented) | Must parse human-readable output |
| `auths device list` | Text only | Cannot extract device DIDs programmatically |
| `auths device link` | Text only | Cannot confirm attestation details |
| `auths device verify` | Text only | Cannot validate attestation structure |

## Exit Code Inconsistencies

| Command | Current | Expected | Notes |
|---------|---------|----------|-------|
| `auths init` (already initialized) | Unclear | Non-zero or --force flag | Second init behavior undefined |
| `auths verify` (unsigned commit) | Unclear | Non-zero | Should clearly distinguish unsigned vs invalid |

## Missing CLI Features

| Feature | Description | Priority |
|---------|-------------|----------|
| `auths id export-bundle` | May not be implemented | Medium |
| `auths device extend` | Re-issue attestation with new expiry | Low |
| `auths policy diff` | Compare two policy files | Low |
| OIDC bridge token exchange E2E | Requires full attestation chain creation | High |

## Test Limitations

| Test | Limitation | Workaround |
|------|-----------|------------|
| Device revoke tests | Cannot extract device DID from CLI output | Hardcoded test DID |
| OIDC token exchange | Requires attestation chain setup | Skipped, needs manual integration |
| OIDC expired attestation | Requires time manipulation | Skipped |
| Emergency freeze/unfreeze | May not be implemented | Skipped gracefully |
