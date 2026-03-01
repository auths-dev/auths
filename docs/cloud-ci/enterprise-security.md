# OIDC Bridge Enterprise Security Guide

## Overview

The `auths-oidc-bridge` is an OIDC Identity Provider (IdP) that translates KERI attestation chains into RS256 JWTs consumable by cloud provider IAM systems (AWS STS, GCP Workload Identity, Azure AD).

This document covers trust boundaries, cryptographic guarantees, threat modeling, key management, deployment, and integration guides for enterprise adoption.

## Trust Boundaries

### Bridge as Trust Anchor

The bridge's RSA signing key is the **sole trust anchor** for cloud IAM integration. Any entity possessing this key can mint JWTs that cloud providers will accept. Compromise of this key equals full workload identity impersonation.

```
KERI Identity Layer          auths-oidc-bridge           Cloud IAM Layer
(Ed25519, zero-trust)  -->  (RS256 translation)  -->  (AWS STS / GCP / Azure)
                                    ^
                          RSA signing key = trust anchor
```

### KERI Verification (Zero-Trust)

KERI attestation chain verification is performed locally within the bridge. No external service or network call is required. The bridge verifies:
- Ed25519 signatures on each attestation in the chain
- Canonical JSON serialization (json-canon) integrity
- Chain continuity (issuer → subject linkage)
- Expiration and revocation status
- Optional witness quorum (threshold-based multi-party verification)

### GitHub OIDC Cross-Reference (Defense-in-Depth)

When enabled (`github-oidc` feature), the bridge optionally verifies a GitHub Actions OIDC token alongside the KERI chain:
- Fetches GitHub's public keys from their JWKS endpoint
- Validates RS256 signature, issuer, audience, and expiry
- Cross-references the `actor` claim against the expected KERI identity

This creates a **two-factor proof**: the request must originate from both (1) a valid KERI identity holder and (2) a specific GitHub Actions workflow.

## Cryptographic Guarantees

| Layer | Algorithm | Key Size | Purpose |
|-------|-----------|----------|---------|
| KERI attestation chain | Ed25519 | 256-bit | Identity and delegation signatures |
| Attestation canonicalization | json-canon | N/A | Deterministic serialization for signing |
| Bridge JWT | RS256 (RSASSA-PKCS1-v1_5 + SHA-256) | 2048-bit minimum | Cloud-consumable identity token |
| GitHub OIDC token | RS256 | GitHub-managed | CI/CD environment proof |

## Threat Model (STRIDE)

### Spoofing

| Threat | Attack | Mitigation |
|--------|--------|------------|
| Stolen GitHub OIDC token | Attacker obtains a GitHub Actions OIDC token and presents it to the bridge | Audience validation prevents token reuse from other services. GitHub tokens have a 5-minute TTL. |
| Compromised KERI device key | Attacker compromises a device key and creates attestations | Chain verification requires the root identity key to sign. Device key alone is insufficient. Key rotation via KERI event log. |
| Spoofed bridge identity | Attacker creates a rogue bridge with a different signing key | AWS IAM OIDC provider registration binds a specific JWKS endpoint + issuer URL. Rogue bridges use different keys. |

### Tampering

| Threat | Attack | Mitigation |
|--------|--------|------------|
| Modified JWT claims in transit | Attacker intercepts and modifies JWT claims | RS256 signature verification at AWS STS. Any modification invalidates the signature. |
| Altered attestation chain | Attacker modifies attestation payloads | Ed25519 signatures + canonical JSON. Any byte change breaks verification. |

### Repudiation

| Threat | Attack | Mitigation |
|--------|--------|------------|
| Unaudited token issuance | Bridge issues JWTs without record | Structured tracing events for every exchange: `auths.exchange.github_cross_reference.success`, `.failure`, `keri_only`. AWS CloudTrail logs `AssumeRoleWithWebIdentity` calls. |

### Information Disclosure

| Threat | Attack | Mitigation |
|--------|--------|------------|
| JWT payload leakage via logs | Bridge logs contain full JWT payloads | Secure logging policy: only `sub`, `iss`, `kid` logged. Raw JWTs and attestation chains are never logged. |

### Denial of Service

| Threat | Attack | Mitigation |
|--------|--------|------------|
| Token endpoint flooding | Attacker floods `/token` with requests | Rate limiting recommended (not yet implemented). Consider deploying behind an API gateway with rate limiting. |
| JWKS endpoint flooding | Excessive JWKS requests from cloud providers | JWKS responses include `Cache-Control` headers. Cloud providers cache JWKS. |

### Elevation of Privilege

| Threat | Attack | Mitigation |
|--------|--------|------------|
| Confused deputy (token reuse) | GitHub token minted for service A used against service B | Audience validation: bridge rejects tokens where `aud` doesn't match `github_expected_audience`. |
| Overly broad IAM trust policy | Trust policy allows any `sub` to assume role | Document recommended conditions. Always condition on `sub` and `aud`. |

## Key Rotation

### Routine Rotation (90-Day Cadence)

1. **Generate new RSA key pair** (2048-bit minimum, 4096-bit recommended)
2. **Add new key to JWKS** — serve both old and new keys at `/.well-known/jwks.json`
3. **Start signing with new key** — update `AUTHS_OIDC_RSA_KEY_PATH` and restart bridge
4. **Wait for max JWT TTL + 24h grace** — AWS caches JWKS for up to 24 hours
5. **Remove old key from JWKS** — once all tokens signed with old key have expired

### Key Storage

| Environment | Storage | Notes |
|-------------|---------|-------|
| Development | Local PEM file | Set `AUTHS_OIDC_RSA_KEY_PATH` |
| Kubernetes | K8s Secret (mounted volume) | Rotate via Secret update + pod restart |
| AWS | AWS Secrets Manager / KMS | Consider KMS asymmetric signing for HSM-backed keys |

**WARNING**: Never use ephemeral keys in production. The bridge generates an ephemeral key if none is configured. After restart, AWS will still cache the old JWKS, causing all in-flight JWTs to become unverifiable.

## Key Compromise Incident Response ("Break Glass")

If the bridge's RSA private key is compromised:

| Step | Action | Command | RTO |
|------|--------|---------|-----|
| 1 | **Delete the IAM OIDC Provider** — immediately blocks all token acceptance | `aws iam delete-open-id-connect-provider --open-id-connect-provider-arn <ARN>` | < 2 min |
| 2 | **Remove compromised key from JWKS** — update bridge to serve empty or new-only JWKS | Restart bridge with new key | < 5 min |
| 3 | **Generate new RSA signing key** | `openssl genrsa -out new-key.pem 4096` | < 1 min |
| 4 | **Deploy bridge with new key** | Update `AUTHS_OIDC_RSA_KEY_PATH`, restart | < 5 min |
| 5 | **Re-create IAM OIDC Provider** with new JWKS thumbprint | `aws iam create-open-id-connect-provider ...` | < 2 min |
| 6 | **Update IAM role trust policies** if issuer URL changed | Update each role's trust policy | Varies |
| 7 | **Audit CloudTrail** for `AssumeRoleWithWebIdentity` calls during compromise window | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity` | < 30 min |

**Target recovery time: < 15 minutes** for Steps 1-5.

If root KERI identity compromise is suspected, additionally:
- Rotate KERI root keys via the KERI event log
- Revoke all attestations issued by the compromised root
- Re-issue attestations from the new root

## Deployment Topology

### Single-Instance (Simplest)

```
[Bridge] --- RSA key file (local PEM)
    |
    +--- /.well-known/jwks.json  <-- AWS IAM fetches this
    +--- /.well-known/openid-configuration
    +--- POST /token
```

### Multi-Instance (High Availability)

```
[Load Balancer]
    |
    +--- [Bridge 1] \
    +--- [Bridge 2]  }-- Shared RSA key (K8s Secret / Secrets Manager)
    +--- [Bridge N] /
```

All instances MUST serve the same JWKS (same RSA key). Use a shared secret store.

### Requirements

- JWKS endpoint MUST be publicly accessible over HTTPS
- TLS certificate must chain to a root CA trusted by AWS (or register thumbprint)
- Response time for JWKS: < 5 seconds (AWS timeout)
- Maximum 100 RSA keys in JWKS (AWS limit)

## AWS IAM Integration Guide

### Step 1: Create OIDC Identity Provider

```bash
# Get the TLS certificate thumbprint
THUMBPRINT=$(openssl s_client -connect your-bridge.example.com:443 < /dev/null 2>/dev/null \
  | openssl x509 -fingerprint -noout -sha1 \
  | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')

# Create the provider
aws iam create-open-id-connect-provider \
  --url https://your-bridge.example.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list "$THUMBPRINT"
```

### Step 2: Create IAM Role with Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/your-bridge.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "your-bridge.example.com:aud": "sts.amazonaws.com",
          "your-bridge.example.com:sub": "did:keri:EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        }
      }
    }
  ]
}
```

**Recommended conditions:**
- Always set `aud` condition to prevent confused deputy
- Set `sub` condition to restrict to specific KERI identities
- Use `StringLike` with wildcards cautiously (e.g., `did:keri:E*` allows any KERI identity)

### Step 3: Assume Role from CI/CD

```bash
# Exchange attestation chain for JWT
JWT=$(curl -s -X POST https://your-bridge.example.com/token \
  -H "Content-Type: application/json" \
  -d '{"attestation_chain": [...], "root_public_key": "..."}' \
  | jq -r '.access_token')

# Assume AWS role
CREDS=$(aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT:role/auths-ci \
  --role-session-name "build-$BUILD_ID" \
  --web-identity-token "$JWT" \
  --output json)

# Export credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')
```

### Common Mistakes

1. **Missing `aud` condition** — allows any OIDC provider with the same issuer URL
2. **Overly broad `sub`** — `StringLike: "did:keri:*"` allows any KERI identity
3. **Setting `azp` claim** — AWS uses `azp` as audience when present, ignoring `aud`
4. **Ephemeral bridge keys** — bridge restart invalidates all in-flight tokens

## Infrastructure-as-Code

### Terraform

```hcl
resource "aws_iam_openid_connect_provider" "auths_bridge" {
  url             = "https://your-bridge.example.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [var.bridge_tls_thumbprint]

  tags = {
    Name = "auths-oidc-bridge"
  }
}

resource "aws_iam_role" "auths_ci" {
  name = "auths-ci-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.auths_bridge.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${aws_iam_openid_connect_provider.auths_bridge.url}:aud" = "sts.amazonaws.com"
            "${aws_iam_openid_connect_provider.auths_bridge.url}:sub" = var.allowed_keri_did
          }
        }
      }
    ]
  })
}

variable "bridge_tls_thumbprint" {
  description = "SHA-1 thumbprint of the bridge TLS certificate"
  type        = string
}

variable "allowed_keri_did" {
  description = "KERI DID allowed to assume this role (e.g., did:keri:Eabc...)"
  type        = string
}
```

### CloudFormation

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Auths OIDC Bridge IAM resources

Parameters:
  BridgeUrl:
    Type: String
    Description: HTTPS URL of the auths-oidc-bridge
    Default: https://your-bridge.example.com
  BridgeTlsThumbprint:
    Type: String
    Description: SHA-1 thumbprint of the bridge TLS certificate
  AllowedKeriDid:
    Type: String
    Description: KERI DID allowed to assume the role

Resources:
  AuthsOidcProvider:
    Type: AWS::IAM::OIDCProvider
    Properties:
      Url: !Ref BridgeUrl
      ClientIdList:
        - sts.amazonaws.com
      ThumbprintList:
        - !Ref BridgeTlsThumbprint

  AuthsCiRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: auths-ci-role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Federated: !GetAtt AuthsOidcProvider.Arn
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                !Sub "${BridgeUrl}:aud": sts.amazonaws.com
                !Sub "${BridgeUrl}:sub": !Ref AllowedKeriDid

Outputs:
  OidcProviderArn:
    Value: !GetAtt AuthsOidcProvider.Arn
  RoleArn:
    Value: !GetAtt AuthsCiRole.Arn
```

## GitHub Actions Integration Guide

### Workflow Example

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

### Security Recommendations

1. **Set `id-token: write` permission** — required for GitHub to issue OIDC tokens
2. **Use a custom audience** — pass `'auths-bridge'` (or your bridge URL) to `core.getIDToken()` to prevent token reuse
3. **Pin action versions** — use SHA-pinned action references, not tags
4. **Minimize workflow permissions** — only grant `id-token: write` and `contents: read`
5. **Use environment protection rules** — require reviewers for production deployments
