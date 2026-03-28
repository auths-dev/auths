# OIDC Machine Identity: Ephemeral Keypairs for CI/CD

## Overview

Auths can now create cryptographically verifiable artifacts signed by ephemeral keys bound to OIDC tokens from CI/CD platforms (GitHub Actions, GitLab CI, CircleCI). This enables **zero long-lived secrets** in CI pipelines — keys are generated ephemeral, used once, then discarded.

## How It Works

### Workflow

1. **Auto-detect CI platform** from environment variables (GITHUB_ACTIONS, CI_JOB_JWT_V2, CIRCLE_OIDC_TOKEN)
2. **Acquire OIDC token** from the platform's token endpoint
3. **Validate token** signature via JWKS from the issuer (e.g., https://token.actions.githubusercontent.com)
4. **Generate ephemeral Ed25519 keypair** in-memory (never written to disk)
5. **Bind identity to OIDC token** by embedding issuer, subject, audience, and expiration in attestation
6. **Sign artifact** with ephemeral key
7. **Timestamp signature** via RFC 3161 TSA (optional, Sigstore by default)
8. **Discard ephemeral key** after signing

### Verification

Verifiers can reconstruct the CI identity from the OIDC binding without needing the ephemeral private key:

```rust
auths verify-commit --file attestation.json
// Verifier sees: "Signed by GitHub Actions job run-123 (identity bound to token exp: 2026-03-28T10:00:00Z)"
```

## Supported Platforms

### GitHub Actions

**Environment Detection:**
- `GITHUB_ACTIONS=true`
- `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` set

**Token Acquisition:**
```bash
curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r .token
```

**Claims Extracted:**
- `repository` — owner/repo
- `actor` — GitHub username
- `workflow` — workflow filename
- `job_workflow_ref` — workflow@branch reference
- `run_id` — GitHub Actions run ID
- `run_number` — sequential run number

**Issuer:** https://token.actions.githubusercontent.com
**Algorithm:** RS256

### GitLab CI

**Environment Detection:**
- `CI_JOB_JWT_V2` environment variable set

**Token Acquisition:**
Token is provided directly by GitLab in `CI_JOB_JWT_V2` variable.

**Claims Extracted:**
- `project_id` — GitLab project numeric ID
- `project_path` — group/project path
- `user_id` — GitLab user ID
- `user_login` — GitLab username
- `pipeline_id` — CI pipeline ID
- `job_id` — CI job ID

**Issuer:** Configured in GitLab instance (e.g., https://gitlab.example.com)
**Algorithms:** RS256, ES256

### CircleCI

**Environment Detection:**
- `CIRCLE_OIDC_TOKEN` environment variable set

**Token Acquisition:**
Token is provided directly by CircleCI in `CIRCLE_OIDC_TOKEN` variable.

**Claims Extracted:**
- `project_id` — CircleCI project ID
- `project_name` — project name
- `workflow_id` — workflow ID
- `job_number` — job number
- `org_id` — organization ID

**Issuer:** https://oidc.circleci.com
**Algorithm:** RS256

## API Usage

### Creating a Machine Identity from OIDC Token

```rust
use auths_sdk::workflows::machine_identity::{
    OidcMachineIdentityConfig, create_machine_identity_from_oidc_token
};
use auths_infra_http::{HttpJwtValidator, HttpJwksClient, HttpTimestampClient};
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

// Acquire token from platform
let token = github_actions_oidc_token().await?;

// Create configuration
let config = OidcMachineIdentityConfig {
    issuer: "https://token.actions.githubusercontent.com".to_string(),
    audience: "sigstore".to_string(),
    platform: "github".to_string(),
};

// Create clients
let jwt_validator = Arc::new(HttpJwtValidator::new(
    Arc::new(HttpJwksClient::with_default_ttl())
));
let jwks_client = Arc::new(HttpJwksClient::with_default_ttl());
let timestamp_client = Arc::new(HttpTimestampClient::new());

// Create machine identity
let identity = create_machine_identity_from_oidc_token(
    &token,
    config,
    jwt_validator,
    jwks_client,
    timestamp_client,
    Utc::now(),
).await?;

// Sign artifact with ephemeral key
let signature = sign_artifact(&data, &identity)?;
```

### CLI Integration

```bash
# auths init automatically detects CI platform and binds OIDC identity
auths init --profile ci

# auths sign automatically includes OIDC binding in attestation
auths sign --file artifact.bin

# Verify OIDC-bound attestation
auths verify-commit --file attestation.json
```

## Error Handling

### JWKS Fetch Failures

| Scenario | Error Code | Recovery |
|----------|-----------|----------|
| Network timeout | AUTHS-E8005 | Check network connectivity; JWKS endpoint caches for 1 hour |
| 404 Not Found | AUTHS-E8005 | Verify issuer URL is correct |
| Rate limiting | AUTHS-E8005 | Backoff and retry; cache prevents repeated requests |

### Token Expiry

| Scenario | Error Code | Recovery |
|----------|-----------|----------|
| Token expired | AUTHS-E8007 | Token lifetime is ~5-10 min; acquire fresh token and sign within window |
| Clock skew | AUTHS-E8007 | Increase tolerance (default 60s); check system clock sync |

### Token Replay

| Scenario | Error Code | Recovery |
|----------|-----------|----------|
| Same JTI used twice | AUTHS-E8008 | Each token is single-use; acquire fresh token |

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Ephemeral key compromise** | Keys exist only in memory; if process is compromised during signing, tokens are already minted and can't be revoked |
| **Token compromise** | Tokens are short-lived (5-10 min) and single-use (jti-tracked); minimal window for misuse |
| **JWKS endpoint compromise** | Timestamp from RFC 3161 TSA proves signature was created when token was valid |
| **Clock skew exploitation** | Configurable leeway (default 60s); timestamp authority proves absolute time |
| **Audience binding** | Tokens validated for specific audience (e.g., "sigstore"); prevents token reuse in different contexts |

### Best Practices

1. **Never log or print OIDC tokens** — they are bearer credentials
2. **Keep JWKS cache TTL reasonable** (default 1 hour) — balances freshness vs. request load
3. **Enable timestamp authority** in production — proves signature creation time
4. **Validate issuer explicitly** — don't accept tokens from unexpected OIDC providers
5. **Rotate revocation checks** — periodically validate issuer is not compromised

## Known Limitations (v1)

- ❌ **GitHub UI "Verified" badge**: Ephemeral keys will NOT show as "Verified" in GitHub UI. Commits are cryptographically verifiable via `auths verify-commit`, but GitHub UI only recognizes registered SSH/GPG keys. **Future work** (v1+1): auto-register ephemeral SSH key before signing to get UI badge.
- ❌ **AWS CodeBuild**: CodeBuild does not natively provide OIDC tokens. Requires IAM role assumption. Deferred to v1+2.
- ❌ **Custom OIDC providers**: Only GitHub Actions, GitLab CI, CircleCI supported in v1. Custom issuers deferred to v1+3.

## References

- [GitHub Actions OIDC](https://docs.github.com/en/actions/reference/security/openid-connect-reference)
- [GitLab CI ID Tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
- [CircleCI OIDC](https://circleci.com/docs/openid-connect-tokens/)
- [RFC 7519 (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 3161 (Timestamp Protocol)](https://datatracker.ietf.org/doc/html/rfc3161)
- [Sigstore Security Model](https://docs.sigstore.dev/about/security/)

## Roadmap

### v1+1: GitHub SSH Key Auto-Registration

Before signing, auto-register ephemeral SSH key with GitHub API (like fn-84), delete after. Gives users the "Verified" badge in GitHub UI.

### v1+2: AWS CodeBuild Support

Add OIDC token support when CodeBuild natively provides ID tokens.

### v1+3: Custom OIDC Providers

Parameterize issuer URL, JWKS endpoint, claim mappings.

### v1+4: Revocation Checking

Implement CRL/OCSP for OIDC provider certificate validation.
