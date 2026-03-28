use auths_crypto::error::AuthsErrorInfo;
use thiserror::Error;

/// Error type for OIDC operations with cryptographic and validation failures.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::OidcError;
///
/// let err = OidcError::JwtDecode("invalid token".to_string());
/// assert_eq!(err.error_code(), "AUTHS-E8001");
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OidcError {
    /// JWT token is malformed or has invalid encoding.
    #[error("JWT decode failed: {0}")]
    JwtDecode(String),

    /// JWKS signature verification failed for the JWT.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// OIDC claim validation failed (e.g., exp, iss, aud, sub).
    #[error("claim validation failed - {claim}: {reason}")]
    ClaimsValidationFailed { claim: String, reason: String },

    /// Key ID from JWT header not found in JWKS.
    #[error("unknown key ID: {0}")]
    UnknownKeyId(String),

    /// JWKS resolution/fetch failed due to network or other issues.
    #[error("JWKS resolution failed: {0}")]
    JwksResolutionFailed(String),

    /// JWT algorithm doesn't match expected algorithm.
    #[error("algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch { expected: String, got: String },

    /// Token has expired beyond the configured clock skew tolerance.
    #[error("token expired (exp: {token_exp}, now: {current_time}, leeway: {leeway}s)")]
    ClockSkewExceeded {
        token_exp: i64,
        current_time: i64,
        leeway: i64,
    },

    /// Token JTI (JWT ID) has already been used (replay detected).
    #[error("token replay detected (jti: {0})")]
    TokenReplayDetected(String),
}

impl AuthsErrorInfo for OidcError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::JwtDecode(_) => "AUTHS-E8001",
            Self::SignatureVerificationFailed => "AUTHS-E8002",
            Self::ClaimsValidationFailed { .. } => "AUTHS-E8003",
            Self::UnknownKeyId(_) => "AUTHS-E8004",
            Self::JwksResolutionFailed(_) => "AUTHS-E8005",
            Self::AlgorithmMismatch { .. } => "AUTHS-E8006",
            Self::ClockSkewExceeded { .. } => "AUTHS-E8007",
            Self::TokenReplayDetected(_) => "AUTHS-E8008",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::JwtDecode(_) => {
                Some("Verify the token format and ensure it is a valid JWT")
            }
            Self::SignatureVerificationFailed => {
                Some("Check that the JWKS endpoint is up-to-date and the token is from a trusted issuer")
            }
            Self::ClaimsValidationFailed { claim, .. } => {
                if claim == "exp" {
                    Some("The token has expired; acquire a new token from the OIDC provider")
                } else if claim == "iss" {
                    Some("Verify that the token issuer matches the configured trusted issuer")
                } else if claim == "aud" {
                    Some("Ensure the token audience matches the configured expected audience")
                } else {
                    Some("Check that the OIDC provider configuration matches the token claims")
                }
            }
            Self::UnknownKeyId(_) => {
                Some("The JWKS cache may be stale; refresh the JWKS from the issuer endpoint")
            }
            Self::JwksResolutionFailed(_) => {
                Some("Check network connectivity to the JWKS endpoint and ensure the issuer URL is correct")
            }
            Self::AlgorithmMismatch { .. } => {
                Some("Verify that the expected algorithm matches the algorithm used by the OIDC provider")
            }
            Self::ClockSkewExceeded { .. } => {
                Some("Synchronize the system clock or increase the configured clock skew tolerance")
            }
            Self::TokenReplayDetected(_) => {
                Some("A token with this ID has already been used; acquire a new token from the OIDC provider")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_decode_error_code() {
        let err = OidcError::JwtDecode("invalid format".to_string());
        assert_eq!(err.error_code(), "AUTHS-E8001");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_signature_verification_error_code() {
        let err = OidcError::SignatureVerificationFailed;
        assert_eq!(err.error_code(), "AUTHS-E8002");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_claims_validation_error_code() {
        let err = OidcError::ClaimsValidationFailed {
            claim: "exp".to_string(),
            reason: "token expired".to_string(),
        };
        assert_eq!(err.error_code(), "AUTHS-E8003");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_unknown_key_id_error_code() {
        let err = OidcError::UnknownKeyId("key-123".to_string());
        assert_eq!(err.error_code(), "AUTHS-E8004");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_jwks_resolution_error_code() {
        let err = OidcError::JwksResolutionFailed("connection timeout".to_string());
        assert_eq!(err.error_code(), "AUTHS-E8005");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_algorithm_mismatch_error_code() {
        let err = OidcError::AlgorithmMismatch {
            expected: "RS256".to_string(),
            got: "HS256".to_string(),
        };
        assert_eq!(err.error_code(), "AUTHS-E8006");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_clock_skew_exceeded_error_code() {
        let err = OidcError::ClockSkewExceeded {
            token_exp: 1000,
            current_time: 2000,
            leeway: 60,
        };
        assert_eq!(err.error_code(), "AUTHS-E8007");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_token_replay_detected_error_code() {
        let err = OidcError::TokenReplayDetected("jti-123".to_string());
        assert_eq!(err.error_code(), "AUTHS-E8008");
        assert!(err.suggestion().is_some());
    }

    #[test]
    fn test_all_error_codes_are_unique() {
        let errors = [
            OidcError::JwtDecode("".to_string()),
            OidcError::SignatureVerificationFailed,
            OidcError::ClaimsValidationFailed {
                claim: "exp".to_string(),
                reason: "".to_string(),
            },
            OidcError::UnknownKeyId("".to_string()),
            OidcError::JwksResolutionFailed("".to_string()),
            OidcError::AlgorithmMismatch {
                expected: "".to_string(),
                got: "".to_string(),
            },
            OidcError::ClockSkewExceeded {
                token_exp: 0,
                current_time: 0,
                leeway: 0,
            },
            OidcError::TokenReplayDetected("".to_string()),
        ];

        let mut codes: Vec<_> = errors.iter().map(|e| e.error_code()).collect();
        codes.sort();
        codes.dedup();

        assert_eq!(codes.len(), errors.len(), "All error codes must be unique");
    }
}
