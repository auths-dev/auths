# Init Integration for OIDC Machine Identity (fn-85.14)

## Overview

Extends `auths init --profile ci` to auto-detect CI platform and bind ephemeral identity to OIDC token.

## Implementation Notes

### Auto-Detection Flow

1. **Check environment variables** for CI platform detection:
   ```rust
   if std::env::var("GITHUB_ACTIONS").is_ok() {
       // GitHub Actions
   } else if std::env::var("CI_JOB_JWT_V2").is_ok() {
       // GitLab CI
   } else if std::env::var("CIRCLE_OIDC_TOKEN").is_ok() {
       // CircleCI
   }
   ```

2. **Acquire OIDC token** from platform endpoint:
   ```rust
   let token = match platform {
       "github" => github_actions_oidc_token().await?,
       "gitlab" => gitlab_ci_oidc_token().await?,
       "circleci" => circleci_oidc_token().await?,
   };
   ```

3. **Create machine identity** from token:
   ```rust
   let identity = create_machine_identity_from_oidc_token(
       &token,
       config,
       jwt_validator,
       jwks_client,
       timestamp_client,
       Utc::now(),
   ).await?;
   ```

4. **Store OIDC binding** in agent identity metadata:
   - `oidc_issuer`: Token issuer (e.g., "https://token.actions.githubusercontent.com")
   - `oidc_subject`: Token subject (unique workload identifier)
   - `oidc_audience`: Expected audience
   - `oidc_exp`: Token expiration
   - `oidc_normalized_claims`: Platform-specific claims (repository, actor, job_id, etc.)

### Graceful Degradation

If OIDC token acquisition fails:
- **Log warning** but continue
- **Create standard CI identity** without OIDC binding
- **Allow signing to proceed** without cryptographic proof of CI origin
- **Attestations lack OIDC binding** — verifiers can see identity is unsigned

```rust
match create_machine_identity_from_oidc_token(...).await {
    Ok(identity) => {
        // Store OIDC binding in agent metadata
        agent.metadata.insert("oidc_issuer".to_string(), identity.issuer);
        // ... other fields ...
    }
    Err(e) => {
        // Log warning but don't fail init
        warn!("Failed to bind OIDC identity: {}. Continuing without OIDC proof.", e);
        // Proceed with standard CI identity
    }
}
```

### CLI Changes (auths-cli/src/commands/init/mod.rs)

1. **Detect CI platform** during init:
   ```rust
   fn detect_ci_platform() -> Option<&'static str> {
       // Check environment variables
   }
   ```

2. **Conditionally acquire OIDC token**:
   ```rust
   if let Some(platform) = detect_ci_platform() {
       match acquire_oidc_token(platform).await {
           Ok(token) => {
               // Bind OIDC identity
           }
           Err(e) => {
               // Log and continue
           }
       }
   }
   ```

3. **No new user prompts** — OIDC binding is transparent and automatic

### Attestation Structure

Attestations created with OIDC binding include:

```json
{
  "version": 1,
  "rid": "did:keri:...",
  "issuer": "did:keri:...",
  "subject": "did:key:z...",
  "device_public_key": "...",
  "identity_signature": "...",
  "device_signature": "...",
  "capabilities": ["sign:commits"],
  "expires_at": "2026-03-28T10:00:00Z",
  "oidc_binding": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "github-user:run-123:job-456",
    "audience": "sigstore",
    "exp": 1711600000,
    "jti": "token-uuid-123",
    "normalized_claims": {
      "repository": "owner/repo",
      "actor": "github-user",
      "run_id": "123",
      "workflow": "test.yml"
    }
  }
}
```

## Testing Strategy (fn-85.15)

### Unit Tests

1. **Platform detection** — verify environment variable checking
2. **OIDC token acquisition** — mock platform endpoints
3. **Machine identity creation** — mock JWT validator + JWKS client
4. **Graceful degradation** — simulate token acquisition failures

### Integration Tests

1. **GitHub Actions** — real GitHub OIDC endpoint (read-only)
2. **GitLab CI** — mock GitLab OIDC claims
3. **CircleCI** — mock CircleCI OIDC claims
4. **Init flow** — verify agent stores OIDC binding

### E2E Tests (requires CI environment)

1. **GitHub Actions workflow** — `auths init --profile ci` + `auths sign`
2. **Attestation verification** — `auths verify-commit` confirms OIDC binding
3. **Token replay detection** — same JTI rejected on second use

## Known Issues & Mitigations

### Issue: GitHub UI "Verified" Badge

Ephemeral keys won't show as "Verified" in GitHub UI (GitHub only trusts its own GPG/SSH keys).

**Mitigation (v1):** Document this explicitly. Position feature as "cryptographically verifiable" (via auths), not "GitHub-verified" (UI limitation).

**Future (v1+1):** Auto-register ephemeral SSH key with GitHub API before signing (like fn-84).

### Issue: Token Window

OIDC token valid for ~5-10 minutes. User must sign within that window.

**Mitigation:** Acquire token as late as possible (during init, not before). Log token expiration time.

### Issue: Clock Skew

If system clock is far off, JWT validation fails.

**Mitigation:** Default 60s leeway. Suggest `ntpd` or `timedatectl` sync if errors occur.

## Links

- **Epic:** fn-85 (Machine Identity via OIDC)
- **Related Tasks:** fn-85.1 (Error types), fn-85.2-4 (HTTP clients), fn-85.5 (Claims), fn-85.11 (SDK workflow), fn-85.12 (Policy), fn-85.13 (JTI registry)
