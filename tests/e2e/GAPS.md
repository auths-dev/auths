# E2E Test Gap Report

## CLI Commands `--json` Support — RESOLVED

`init`, `status`, and the `device` subcommands honor the global `--json` flag and
emit a documented schema (see `docs/cli-json-output.md`). Human progress goes to
stderr so stdout is parseable JSON on its own.

| Command | Status |
|---------|--------|
| `auths init` | ✅ enveloped result; `--json` forces non-interactive |
| `auths status` | ✅ `StatusReport` object |
| `auths device list` | ✅ enveloped `{identity, devices[]}` |
| `auths device link` | ✅ enveloped `{device, attestation_id}` |
| `auths device verify` | ✅ verification-result object; nonzero exit on failure |

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
