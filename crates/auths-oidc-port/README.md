# auths-oidc-port

Port abstractions for OIDC token validation, JWKS resolution, and RFC 3161 timestamp authority operations.

This crate defines error types and trait abstractions for integrating OIDC-based machine identity into Auths.

## Components

### Error Types

- **OidcError**: Comprehensive error enum covering JWT decode, signature verification, claim validation, clock skew, and token replay scenarios.
  - Each variant has a unique error code (AUTHS-E8001 through AUTHS-E8008)
  - Implements `AuthsErrorInfo` for standardized error reporting

### Port Traits

- **JwtValidator**: Abstract JWT decoding, signature verification, and claims validation
- **JwksClient**: Abstract JWKS fetching and caching from OIDC providers
- **TimestampClient**: Abstract RFC 3161 timestamp authority integration (optional)

### Configuration

- **OidcValidationConfig**: Configuration for JWT validation (issuer, audience, algorithms, clock skew)
- **TimestampConfig**: Configuration for timestamp authority operations (URI, timeout, fallback behavior)

## Architecture

`auths-oidc-port` is a Layer 3 crate (per Auths architecture). It:
- Has zero dependencies on implementation details (no HTTP client, no JSON Web Token library)
- Provides pure abstraction for OIDC operations
- Is implemented by `auths-infra-http` (Layer 5) for production use

This isolation allows testing and alternative implementations without coupling to external libraries.
