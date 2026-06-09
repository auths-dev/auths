//! Typed errors for federation-as-attestor.

use thiserror::Error;

/// A federation attestation failure.
#[derive(Debug, Error)]
pub enum FederationError {
    /// The OIDC token failed signature/issuer/audience/expiry validation.
    #[error("OIDC token invalid: {0}")]
    TokenInvalid(String),
    /// The token carried no `nonce` claim to bind against the challenge.
    #[error("token is missing the nonce claim")]
    NonceMissing,
    /// The token's `nonce` did not match the expected challenge nonce (replay).
    #[error("token nonce does not match the expected challenge nonce")]
    NonceMismatch,
    /// The token carried no `iss` claim to identify the attestor.
    #[error("token is missing the issuer (iss) claim")]
    IssuerMissing,
    /// The attested lifecycle fact is not supported by the token's claims.
    #[error("attested claim not supported by the token: {0}")]
    ClaimNotInToken(String),
    /// A typed identifier (idp / group / nonce) was empty or malformed.
    #[error("invalid identifier: {0}")]
    InvalidId(String),
    /// The subject DID could not be parsed into a KEL prefix.
    #[error("invalid subject DID: {0}")]
    InvalidSubject(String),
    /// Anchoring the attestation into the subject's KEL failed.
    #[error("failed to anchor attestation into subject KEL: {0}")]
    AnchorFailed(String),
}
