# GitHub Actions OIDC

Use GitHub Actions workload identity alongside KERI attestation chains for two-factor proof.

## Overview

GitHub Actions can mint short-lived OIDC tokens for workflows. When combined with the Auths OIDC Bridge, this creates a **two-factor proof**: the request must originate from both (1) a valid KERI identity holder and (2) a specific GitHub Actions workflow.

## Workflow Example

```yaml
name: Deploy with Auths Identity
on:
  push:
    branches: [main]

permissions:
  id-token: write   # Required for OIDC token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Get GitHub OIDC token
        id: github-oidc
        uses: actions/github-script@v7
        with:
          script: |
            const token = await core.getIDToken('auths-bridge');
            core.setOutput('token', token);

      - name: Exchange for cloud credentials
        env:
          BRIDGE_URL: https://your-bridge.example.com
          GITHUB_OIDC_TOKEN: ${{ steps.github-oidc.outputs.token }}
        run: |
          # Exchange KERI chain + GitHub token for bridge JWT
          JWT=$(curl -s -X POST "$BRIDGE_URL/token" \
            -H "Content-Type: application/json" \
            -d "{
              \"attestation_chain\": $ATTESTATION_CHAIN,
              \"root_public_key\": \"$ROOT_PK\",
              \"github_oidc_token\": \"$GITHUB_OIDC_TOKEN\",
              \"github_actor\": \"$GITHUB_ACTOR\"
            }" | jq -r '.access_token')

          # Assume AWS role with the bridge JWT
          CREDS=$(aws sts assume-role-with-web-identity \
            --role-arn "$AWS_ROLE_ARN" \
            --role-session-name "gh-${GITHUB_RUN_ID}" \
            --web-identity-token "$JWT" \
            --output json)

          echo "AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')" >> $GITHUB_ENV
          echo "AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')" >> $GITHUB_ENV
          echo "AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')" >> $GITHUB_ENV
```

## How Cross-Referencing Works

When the bridge receives both a KERI attestation chain and a GitHub OIDC token:

1. Verifies the KERI attestation chain (Ed25519 signatures, chain continuity, expiration)
2. Fetches GitHub's public keys from their JWKS endpoint
3. Validates the GitHub token's RS256 signature, issuer, audience, and expiry
4. Cross-references the GitHub `actor` claim against the expected KERI identity
5. If both pass, mints a bridge JWT

If either verification fails, the exchange is rejected.

## Security Recommendations

1. **Set `id-token: write` permission** -- required for GitHub to issue OIDC tokens
2. **Use a custom audience** -- pass `'auths-bridge'` (or your bridge URL) to `core.getIDToken()` to prevent token reuse
3. **Pin action versions** -- use SHA-pinned action references, not tags
4. **Minimize workflow permissions** -- only grant `id-token: write` and `contents: read`
5. **Use environment protection rules** -- require reviewers for production deployments

## Without GitHub Cross-Reference

If you don't need the two-factor proof, you can use the bridge with KERI attestations alone. Omit the `github_oidc_token` and `github_actor` fields from the token exchange request. See [AWS Integration](aws-integration.md) for the KERI-only flow.
