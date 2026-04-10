# E2E Test Checklist: OIDC Machine Identity Commit Signing

## Overview

This checklist validates that the complete OIDC machine identity commit signing feature works end-to-end in GitHub Actions. Follow these steps to verify the feature is production-ready.

## Prerequisites

- [ ] Branch with commit verification and ephemeral signing changes is ready
- [ ] Workflow file (`.github/workflows/release.yml`) includes verify gate and ephemeral signing
- [ ] All code changes are committed
- [ ] Repository has write permissions for refs/auths/*

## Phase 1: Workflow Execution

### Trigger the Workflow

- [ ] Push to main branch or create PR that triggers `.github/workflows/release.yml`
- [ ] Workflow starts automatically in GitHub Actions
- [ ] No manual token configuration required (GitHub provides OIDC token automatically)

### Monitor Workflow Execution

Go to Actions tab in GitHub:

- [ ] Workflow job appears with correct name
- [ ] Job status shows "In Progress" or "Completed"
- [ ] No authentication errors or missing permissions

### Check Workflow Logs

Click into the workflow job and expand steps:

- [ ] `Checkout code` succeeds
- [ ] `Build auths-cli` succeeds
  - Should see cargo build output
- [ ] `Initialize auths (auto-detect OIDC)` step succeeds
  - Should see: `Detected GitHub Actions OIDC`
  - Should NOT ask for token manually
- [ ] `Sign commits` step succeeds for each commit
  - Should see attestation created
  - Should show OIDC binding detected
- [ ] `Push attestation refs` step succeeds
  - Should see refs/auths/commits/* pushed to origin

### Log Output Examples

Expected log messages:

```
Detected GitHub Actions OIDC
Token issuer: https://token.actions.githubusercontent.com
Machine identity created: did:key:z6Mk...
Creating attestation for: abc123def456...
OIDC binding: issuer=https://token.actions.githubusercontent.com, subject=repo:owner/repo:ref:refs/heads/main
Signature verified: OK
Attestation stored at: refs/auths/commits/abc123def456...
Pushing refs to origin...
Successfully pushed 1 attestation ref(s)
```

## Phase 2: Verify Attestations Exist

### Check Git Refs

In your local clone, fetch and list attestation refs:

```bash
git fetch origin 'refs/auths/commits/*:refs/auths/commits/*'
git show-ref | grep auths/commits
```

Expected output:
```
abc123def456... refs/auths/commits/abc123def456...
def789xyz123... refs/auths/commits/def789xyz123...
...
```

- [ ] At least one attestation ref exists for the signed commits
- [ ] Refs follow pattern: `refs/auths/commits/<commit-sha>`

### View Attestation Content

For each signed commit:

```bash
git show refs/auths/commits/<commit-sha>
```

Expected output: JSON attestation

- [ ] Output is valid JSON (not empty, no syntax errors)
- [ ] Attestation contains required fields:
  - `version`: should be `1`
  - `commit_sha`: matches the commit SHA
  - `issuer`: did:keri:... format
  - `subject`: did:key:... format
  - `timestamp`: ISO 8601 format
  - `identity_signature`: hex string (non-empty)

## Phase 3: Verify Attestation Structure

For each attestation, check these fields:

### Commit Metadata

- [ ] `commit_sha`: Matches the git commit SHA
- [ ] `commit_message`: Contains the git commit message
- [ ] `author`: Contains the commit author name
- [ ] `timestamp`: Is a recent ISO 8601 timestamp

### OIDC Binding

```bash
git show refs/auths/commits/<commit-sha> | jq '.oidc_binding'
```

- [ ] `oidc_binding` field exists (not null)
- [ ] `issuer`: `https://token.actions.githubusercontent.com`
- [ ] `subject`: Contains repo path (e.g., `repo:owner/repo:ref:refs/heads/main`)
- [ ] `audience`: `sigstore`
- [ ] `platform`: `github`
- [ ] `token_exp`: Unix timestamp in the future
- [ ] `jti`: Non-empty string (for replay detection)
- [ ] `normalized_claims`: Object containing:
  - `repo`: Repository path (owner/repo format)
  - `actor`: GitHub Actions actor/username
  - `run_id`: GitHub run ID

Example structure:
```json
{
  "oidc_binding": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main",
    "audience": "sigstore",
    "platform": "github",
    "token_exp": 1704067200,
    "jti": "abc123xyz789",
    "normalized_claims": {
      "repo": "owner/repo",
      "actor": "alice",
      "run_id": "12345"
    }
  }
}
```

- [ ] All fields are present and non-empty (except jti which may be null)
- [ ] No syntax errors or truncation in JSON

## Phase 4: Verify Signatures

### Cryptographic Verification

For each attestation:

```bash
auths verify-commit <commit-sha>
```

Expected output:
```
Commit abc123def456... verified: signed by did:keri:Eissuer (oidc: https://token.actions.githubusercontent.com)
```

- [ ] Command succeeds (exit code 0)
- [ ] Shows "verified: signed by"
- [ ] Displays OIDC issuer information
- [ ] No error messages

### JSON Output Verification

```bash
auths verify-commit --json <commit-sha>
```

- [ ] Valid JSON output
- [ ] `"valid": true`
- [ ] `"signer"` field present with DID
- [ ] `"oidc_binding"` field present with full structure
  - `issuer`, `subject`, `audience`, `platform` all present
  - `normalized_claims` contains `repo`, `actor`, `run_id`

### Multiple Commits

If multiple commits were signed:

```bash
auths verify-commit main..HEAD
```

- [ ] All commits show as verified
- [ ] Each commit shows correct OIDC binding

## Phase 5: Validate Integration

### Consistency Checks

- [ ] Attestation issuer DID matches verify output signer
- [ ] Commit SHA in attestation matches git log
- [ ] OIDC binding issuer is always `https://token.actions.githubusercontent.com`
- [ ] All attestations have same platform: `github`
- [ ] All attestations have normalized_claims with repo/actor/run_id

### Roundtrip Test

```bash
# Export attestation
git show refs/auths/commits/<sha> > attestation.json

# Verify it deserializes correctly
jq '.' attestation.json  # Pretty-print
jq '.oidc_binding' attestation.json  # Extract binding
```

- [ ] JSON is well-formed
- [ ] No truncation or corruption
- [ ] All required fields present after deserialization

## Phase 6: Document Results

### Success Criteria

- [ ] All workflow steps completed without errors
- [ ] At least one attestation ref exists
- [ ] Attestation JSON is valid and complete
- [ ] OIDC binding contains correct GitHub Actions context
- [ ] Signature verification succeeds
- [ ] Multiple commits are independently signed

### Failure Scenarios (if applicable)

If any step fails, document:

- [ ] Which step failed
- [ ] Error message from logs
- [ ] Environment information (branch, commit SHAs)
- [ ] Whether it's a one-time glitch or consistent failure

## Phase 7: Cleanup and Next Steps

- [ ] Save attestation samples for reference
- [ ] Merge feature branch to main
- [ ] Update team docs if needed
- [ ] Plan for post-launch monitoring

## Test Results Summary

| Item | Result | Notes |
|------|--------|-------|
| Workflow execution | PASS/FAIL | |
| Attestation refs created | PASS/FAIL | Count: ___ |
| JSON structure valid | PASS/FAIL | |
| OIDC binding complete | PASS/FAIL | |
| Signature verification | PASS/FAIL | |
| Multiple commits signed | PASS/FAIL | Count: ___ |

## Troubleshooting

### Common Issues

**Workflow doesn't trigger:**
- Check branch protection rules
- Verify `.github/workflows/release.yml` is on main

**OIDC token not acquired:**
- Check GitHub Actions OIDC issuer is configured
- Verify repository has OIDC trust relationship with GitHub

**Attestation refs not pushed:**
- Check workflow permissions (contents: write)
- Verify git push command is correct
- Check for merge conflicts or branch protection

**Signature verification fails:**
- Verify attestation JSON is not corrupted
- Check keypair is consistent between sign and verify
- Run `auths doctor` for diagnostics

## Sign-Off

- **Tested by**: ___________
- **Date**: ___________
- **Status**: ☐ READY FOR PRODUCTION ☐ NEEDS FIXES

---

For questions or issues, see [OIDC_COMMIT_SIGNING.md](./OIDC_COMMIT_SIGNING.md) for detailed documentation.
