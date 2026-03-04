# auths-oidc-bridge

OIDC bridge that exchanges KERI attestation chains for short-lived RS256 JWTs consumable by cloud providers (AWS STS, GCP Workload Identity, Azure AD).

## How it works

1. Client POSTs an attestation chain + root public key to `/token`
2. Bridge verifies the chain via `auths-verifier`
3. Bridge issues a signed RS256 JWT with OIDC-standard claims
4. Cloud provider validates the JWT against `/.well-known/jwks.json`

## Features

- Token exchange endpoint with attestation chain verification
- JWKS and OpenID Configuration discovery endpoints
- Key rotation with dual-key JWKS support
- Rate limiting per identity prefix
- Optional GitHub Actions OIDC cross-referencing (`github-oidc` feature)

## Feature flags

| Flag | Description |
|------|-------------|
| `github-oidc` | Enables GitHub Actions OIDC token verification and cross-referencing |

## License

Apache-2.0
