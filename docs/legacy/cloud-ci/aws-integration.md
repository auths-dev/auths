# AWS Integration

Set up AWS IAM to trust the Auths OIDC Bridge for workload identity federation.

## Overview

AWS IAM can federate identity from any OIDC provider. By registering the Auths OIDC Bridge as an IAM OIDC provider, your CI pipelines and services can assume IAM roles using their KERI identity -- no long-lived access keys needed.

## Step 1: Create OIDC Identity Provider

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

## Step 2: Create IAM Role with Trust Policy

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

## Step 3: Assume Role from CI

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

## Common Mistakes

1. **Missing `aud` condition** -- allows any OIDC provider with the same issuer URL
2. **Overly broad `sub`** -- `StringLike: "did:keri:*"` allows any KERI identity
3. **Setting `azp` claim** -- AWS uses `azp` as audience when present, ignoring `aud`
4. **Ephemeral bridge keys** -- bridge restart invalidates all in-flight tokens
