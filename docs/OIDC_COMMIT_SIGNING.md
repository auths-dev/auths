# OIDC Machine Identity for Commit Signing

## Overview

The auths system can use machine identities created from OIDC tokens (typically from CI/CD platforms like GitHub Actions) to sign commits. This document explains how to use, verify, and extend this feature.

**Quick Summary**:
- CI/CD workflows can sign commits with ephemeral machine identities
- Commits are signed with a keypair derived from the OIDC token
- Attestations store the OIDC binding proof (issuer, subject, audience, claims)
- Verifiers can reconstruct the identity and validate without needing the private key

## User Guide: Verifying Signed Commits

### Verifying a Single Commit

To verify that a commit was signed with a machine identity:

```bash
auths verify-commit <commit-sha>
```

Example output:
```
Commit abc123def456... verified: signed by did:keri:Eissuer (oidc: https://token.actions.githubusercontent.com)
```

### Understanding the Output

When `auths verify-commit` displays OIDC binding information:

```json
{
  "commit": "abc123def456...",
  "valid": true,
  "signer": "did:keri:Eissuer",
  "oidc_binding": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main",
    "audience": "sigstore",
    "platform": "github",
    "normalized_claims": {
      "repo": "owner/repo",
      "actor": "alice",
      "run_id": "12345"
    }
  }
}
```

**What this means:**
- **issuer**: The OIDC token provider (GitHub, GitLab, etc.)
- **subject**: The unique workload identifier from the CI/CD platform
- **audience**: Who the token was issued for (typically "sigstore")
- **platform**: The CI/CD platform (github, gitlab, circleci)
- **normalized_claims**: Platform-specific metadata (repo, actor, run ID, etc.)

This proves the commit was signed by a specific CI/CD workload with known context.

### Verifying Multiple Commits

To verify a range of commits:

```bash
auths verify-commit main..HEAD
```

This shows verification status for all commits after `main` up to `HEAD`.

## Architecture: Signing and Verification Flow

### Signing Flow

When a commit is signed in CI/CD:

```
1. CI/CD detects OIDC token available
   ↓
2. auths init --profile ci
   - Auto-detects GitHub Actions, GitLab, etc.
   - Acquires OIDC token from platform
   - Creates machine identity from token
   ↓
3. auths sign-commit <sha>
   - Fetches commit SHA and metadata
   - Constructs attestation with:
     * Commit SHA
     * Commit message
     * Author info
     * OIDC binding (issuer, subject, audience, claims)
   ↓
4. Sign attestation with identity keypair
   ↓
5. Store attestation at refs/auths/commits/<sha>
   - This is a git ref, not visible in GitHub UI
   - Persists in your repository
   ↓
6. Push refs/auths/* back to origin
```

### Verification Flow

When a user verifies a commit:

```
1. auths verify-commit <sha>
   ↓
2. Load attestation from refs/auths/commits/<sha>
   ↓
3. Extract OIDC binding from attestation
   ↓
4. Validate signature against stored public key
   ↓
5. Display verification result with OIDC context
```

**Key Point**: Verifiers don't need the private key. The attestation proves:
- Who signed it (issuer DID)
- What CI/CD context it was signed in (OIDC binding)
- The signature is valid

### Attestation Structure

The attestation stored for a commit looks like:

```json
{
  "version": 1,
  "rid": "auths/commits/abc123def456...",
  "issuer": "did:keri:Eissuer",
  "subject": "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR",
  "device_public_key": "0102030405...",
  "identity_signature": "hex-encoded-signature",
  "device_signature": "",
  "timestamp": "2024-03-28T12:00:00Z",
  "commit_sha": "abc123def456...",
  "commit_message": "feat: add feature",
  "author": "Alice Developer",
  "oidc_binding": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main",
    "audience": "sigstore",
    "token_exp": 1704067200,
    "platform": "github",
    "jti": "unique-token-id",
    "normalized_claims": {
      "repo": "owner/repo",
      "actor": "alice",
      "run_id": "12345"
    }
  }
}
```

## GitHub UI Verification Gap

### Why Commits Don't Show as "Verified" in GitHub

GitHub only recognizes verification for commits signed with:
- **GPG keys** (traditional PGP signatures)
- **SSH keys** (SSH signature verification via allowed_signers)

GitHub does NOT recognize:
- Custom attestations (even if cryptographically valid)
- Refs stored in your repository

Our auths attestations are **not** GPG or SSH signatures, so GitHub's UI won't show them as verified.

### What You Can Do Instead

1. **Verify locally** with `auths verify-commit`
   - See the OIDC binding and attestation details
   - Cryptographically valid but custom format

2. **Register SSH keys** (future work)
   - If signed via auths, could export as SSH signature
   - Then GitHub would recognize it as verified
   - This is a planned enhancement

3. **Trust the attestation format**
   - Attestations are standard JSON with cryptographic signatures
   - Verifiers can inspect OIDC binding to see CI/CD context
   - Equivalent security to GPG/SSH for CI/CD workflows

### Why This Design?

- **Simplicity**: Auths attestations don't depend on external key registries
- **CI/CD Integration**: OIDC tokens are ephemeral and platform-native
- **Flexibility**: Easy to extend to other CI/CD platforms (GitLab, CircleCI, etc.)
- **Trust Transparency**: OIDC binding makes workload context explicit

## Developer Guide: Extending the Feature

### Adding Support for a New CI/CD Platform

To support a new platform (e.g., GitLab, CircleCI):

1. **Extend `auths-infra-http` module**
   - Add platform detection in `oidc_platforms.rs`
   - Add token claim normalization for the platform
   - Example: GitLab's `gl_runner_id`, `gl_project_path`, etc.

2. **Add platform-specific integration tests**
   - Mock OIDC tokens from the platform
   - Test claim extraction and normalization

3. **Document the binding structure**
   - Add to `OidcMachineIdentity` docs
   - Example normalized claims for the platform

### Testing Locally Without CI

To test commit signing without GitHub Actions:

```bash
# 1. Mock OIDC token (see test utils)
MOCK_OIDC_TOKEN=$(cat <<EOF
{
  "iss": "https://token.actions.githubusercontent.com",
  "sub": "repo:owner/repo:ref:refs/heads/main",
  "aud": "sigstore",
  "exp": 1704067200,
  "jti": "test-jti-123"
}
EOF
)

# 2. Create machine identity from mock token
# (See auths_sdk::workflows::machine_identity tests)

# 3. Sign a commit locally
auths sign-commit HEAD

# 4. Verify the attestation
auths verify-commit HEAD
```

### Modifying Attestation Structure

If you need to add fields to the attestation:

1. **Update `Attestation` struct** in `crates/auths-verifier/src/core.rs`
   - Add new field
   - Mark as optional (`Option<T>`)
   - Add serde skip_serializing_if for backward compat

2. **Update all Attestation initializers**
   - Production code: `auths-id/src/attestation/create.rs`, etc.
   - Test code: All test fixtures in `crates/auths-verifier/tests/`

3. **Update verification output**
   - `crates/auths-cli/src/commands/verify_commit.rs`
   - Add new field to `OidcBindingDisplay` if relevant

4. **Test serialization roundtrip**
   - Old attestations (without new field) should still deserialize
   - New attestations should serialize cleanly

## Related Documentation

- **[OIDC_INIT_INTEGRATION.md](./OIDC_INIT_INTEGRATION.md)** — How `auths init --profile ci` auto-detects and acquires tokens
- **[OIDC_MACHINE_IDENTITY.md](./OIDC_MACHINE_IDENTITY.md)** — Machine identity creation and signing workflow

## Glossary

- **Attestation**: A signed claim that includes commit metadata and OIDC binding
- **OIDC Binding**: Proof that a commit was signed in a specific CI/CD workload (issuer, subject, audience)
- **Machine Identity**: Ephemeral identity created from OIDC token (exists only for signing)
- **RID**: Resource Identifier, the git ref where the attestation is stored (`refs/auths/commits/<sha>`)
- **Normalized Claims**: Platform-specific claims extracted from OIDC token (repo, actor, run_id, etc.)
