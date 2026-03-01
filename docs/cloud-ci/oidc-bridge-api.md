# OIDC Bridge API

The `auths-oidc-bridge` exposes three endpoints: OIDC discovery, JWKS, and token exchange.

## Endpoints

### OIDC Discovery

```
GET /.well-known/openid-configuration
```

Returns standard OIDC discovery metadata:

```json
{
  "issuer": "https://your-bridge.example.com",
  "token_endpoint": "https://your-bridge.example.com/token",
  "jwks_uri": "https://your-bridge.example.com/.well-known/jwks.json",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

### JWKS

```
GET /.well-known/jwks.json
```

Returns the bridge's RSA public keys in JWK Set format. Cloud providers fetch this to verify JWTs.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "<key-id>",
      "n": "<modulus>",
      "e": "AQAB"
    }
  ]
}
```

Responses include `Cache-Control` headers. Cloud providers (especially AWS) cache JWKS for up to 24 hours.

### Token Exchange

```
POST /token
Content-Type: application/json
```

**Request body:**

```json
{
  "attestation_chain": [
    { "version": 1, "rid": "...", "issuer": "did:keri:...", "subject": "did:key:...", ... }
  ],
  "root_public_key": "<hex-encoded Ed25519 public key>"
}
```

With GitHub OIDC cross-reference (optional):

```json
{
  "attestation_chain": [...],
  "root_public_key": "...",
  "github_oidc_token": "<GitHub Actions OIDC token>",
  "github_actor": "<GitHub username>"
}
```

**Response:**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Error responses:**

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `invalid_request` | Missing or malformed fields |
| 401 | `invalid_chain` | KERI attestation chain verification failed |
| 401 | `invalid_github_token` | GitHub OIDC token validation failed |
| 401 | `chain_expired` | Attestation chain has expired |
| 401 | `chain_revoked` | Attestation in chain has been revoked |

## JWT Claims

The minted JWT contains:

| Claim | Value | Description |
|-------|-------|-------------|
| `iss` | Bridge URL | The bridge's issuer URL |
| `sub` | KERI DID | The subject's `did:keri:...` identity |
| `aud` | `sts.amazonaws.com` | Audience (configurable) |
| `iat` | Unix timestamp | Issued-at time |
| `exp` | Unix timestamp | Expiration (configurable TTL, default 1 hour) |
| `kid` | Key ID | RSA key identifier |
| `azp` | (optional) | Authorized party, if GitHub cross-reference is used |

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `AUTHS_OIDC_RSA_KEY_PATH` | (none, generates ephemeral) | Path to RSA private key PEM file |
| `AUTHS_OIDC_ISSUER_URL` | `http://localhost:3000` | The bridge's public URL |
| `AUTHS_OIDC_TOKEN_TTL_SECS` | `3600` | JWT time-to-live in seconds |
| `AUTHS_OIDC_AUDIENCE` | `sts.amazonaws.com` | Default audience claim |
| `AUTHS_OIDC_BIND_ADDR` | `0.0.0.0:3000` | Listen address |

!!! warning
    Never use ephemeral keys in production. The bridge generates an ephemeral key if none is configured. After restart, AWS will still cache the old JWKS, causing all in-flight JWTs to become unverifiable.

## Structured Tracing

The bridge emits structured tracing events for every token exchange:

| Event | Fields | When |
|-------|--------|------|
| `auths.exchange.keri_only` | `sub`, `chain_length` | KERI-only exchange succeeded |
| `auths.exchange.github_cross_reference.success` | `sub`, `actor` | KERI + GitHub exchange succeeded |
| `auths.exchange.github_cross_reference.failure` | `sub`, `error` | GitHub token validation failed |
| `auths.exchange.chain_verification.failure` | `error` | KERI chain verification failed |
