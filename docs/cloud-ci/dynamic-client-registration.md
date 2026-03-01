# Dynamic Client Registration (RFC 7591)

The `auths-auth-server` implements RFC 7591 Dynamic Client Registration with KERI Capability Receipts as the Initial Access Token. This lets microservices self-register as OIDC clients by proving cryptographic identity via their KERI AID -- no manual client configuration needed.

## Endpoint

```
POST /connect/register
```

### Request

```json
{
  "client_name": "Invoicing Service",
  "redirect_uris": ["https://invoicing.internal.cluster/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks": { "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "..."}] },
  "keri_capability_receipt": {
    "attestation_chain": [{ "version": 1, "rid": "...", "issuer": "did:keri:...", "..." }],
    "root_public_key": "hex-encoded-ed25519-public-key"
  }
}
```

**Required fields:**

- `redirect_uris` -- at least one valid URL (HTTPS required in production)
- `keri_capability_receipt` -- KERI attestation chain proving the `oidc:client:register` capability

**Optional fields with defaults:**

- `grant_types` -- defaults to `["authorization_code"]`
- `response_types` -- defaults to `["code"]`
- `token_endpoint_auth_method` -- defaults to `client_secret_basic`
- `jwks` -- required when `token_endpoint_auth_method` is `private_key_jwt`

### Response (201 Created)

```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "base64url-encoded-secret",
  "client_name": "Invoicing Service",
  "redirect_uris": ["https://invoicing.internal.cluster/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "registration_access_token": "base64url-encoded-token",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0
}
```

`client_secret` is only present when the auth method is `client_secret_basic` or `client_secret_post`. For `private_key_jwt`, no secret is generated.

### Error Responses

| Status | Condition |
|--------|-----------|
| 400 | Malformed JSON, empty `redirect_uris`, `private_key_jwt` without `jwks` |
| 422 | Invalid KERI signature, missing `oidc:client:register` capability, non-HTTPS redirect URI |
| 500 | Internal error |

## KERI Capability Receipt

The `keri_capability_receipt` replaces the traditional Initial Access Token (RFC 7591 Section 1.2) with a KERI attestation chain.

### The `oidc:client:register` Capability

To register, the attestation chain must grant the `oidc:client:register` capability. This capability uses KERI's intersection semantics -- every link in the chain must include it.

Issue the capability by creating an attestation with:

```json
{
  "capabilities": ["oidc:client:register"],
  "..."
}
```

### Verification Pipeline

The server runs three checks on every registration request:

1. **Signature validity** -- `verify_chain()` verifies Ed25519 signatures across the attestation chain
2. **Capability compliance** -- `verify_chain_with_capability()` checks that `oidc:client:register` is granted through the entire chain (intersection semantics)
3. **Metadata validation** -- redirect URIs are valid URLs, HTTPS is enforced (configurable), JWKS is present for `private_key_jwt`

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `registration_enabled` | `true` | Enable/disable the `/connect/register` endpoint |
| `allow_http_redirects` | `false` | Allow HTTP redirect URIs (for development only) |
| `client_ttl_secs` | `86400` (24h) | Default client expiry. Set to `null` for no expiry |

## Client Lifecycle

### TTL-Based Expiry

All registered clients have an `expires_at` timestamp based on `client_ttl_secs`. Services must re-register periodically with a fresh KERI state.

### Re-Registration

A service can register again at any time with a valid KERI capability receipt. Each registration creates a new `client_id` -- the old one expires naturally.

### Revocation

If a KERI AID's keys are rotated, previously-registered clients remain valid until their TTL expires. Full automatic revocation on key rotation is planned for a future release.

## Security Considerations

- **Secret handling** -- `client_secret` is returned exactly once. Only the Argon2 hash is stored. The `registration_access_token` is also hashed before storage.
- **Ghost client prevention** -- TTL-based expiry ensures clients don't persist indefinitely. Background cleanup removes expired entries.
- **KERI as rate limiter** -- The requirement for a valid KERI capability receipt is a natural rate limiter. Attackers cannot register without a cryptographically valid attestation chain.
- **HTTPS enforcement** -- Redirect URIs must use HTTPS in production (`allow_http_redirects: false`). This prevents token interception via plaintext channels.
