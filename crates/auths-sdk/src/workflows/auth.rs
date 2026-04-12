use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Result of signing an authentication challenge.
///
/// Args:
/// * `signature_hex`: Hex-encoded Ed25519 signature over the canonical payload.
/// * `public_key_hex`: Hex-encoded Ed25519 public key.
/// * `did`: The identity's DID (e.g. `"did:keri:EPREFIX"`).
///
/// Usage:
/// ```ignore
/// let msg = build_auth_challenge_message("abc123", "auths.dev")?;
/// let (sig, pubkey, _curve) = sign_with_key(&keychain, &alias, &provider, msg.as_bytes())?;
/// let result = SignedAuthChallenge {
///     signature_hex: hex::encode(sig),
///     public_key_hex: hex::encode(pubkey),
///     did: "did:keri:E...".to_string(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SignedAuthChallenge {
    /// Hex-encoded Ed25519 signature over the canonical JSON payload.
    pub signature_hex: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key_hex: String,
    /// The signer's identity DID (e.g. `"did:keri:EPREFIX"`).
    pub did: String,
}

/// Errors from the auth challenge signing workflow.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthChallengeError {
    /// The nonce was empty.
    #[error("nonce must not be empty")]
    EmptyNonce,

    /// The domain was empty.
    #[error("domain must not be empty")]
    EmptyDomain,

    /// Canonical JSON serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Canonicalization(String),
}

impl AuthsErrorInfo for AuthChallengeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyNonce => "AUTHS-E6001",
            Self::EmptyDomain => "AUTHS-E6002",
            Self::Canonicalization(_) => "AUTHS-E6003",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::EmptyNonce => Some("Provide the nonce from the authentication challenge"),
            Self::EmptyDomain => Some("Provide the domain (e.g. auths.dev)"),
            Self::Canonicalization(_) => {
                Some("This is an internal error; please report it as a bug")
            }
        }
    }
}

/// Builds the canonical JSON message for an auth challenge signature.
///
/// The auth-server verifies the signature over exactly these bytes. Callers
/// that sign through a keychain (SE-safe) should use this helper to get the
/// message, then feed it into `keychain::sign_with_key`.
///
/// Args:
/// * `nonce`: The challenge nonce from the authentication server.
/// * `domain`: The domain requesting authentication (e.g. `"auths.dev"`).
///
/// Usage:
/// ```ignore
/// let msg = build_auth_challenge_message("abc123", "auths.dev")?;
/// let (sig, pubkey, _curve) = sign_with_key(&keychain, &alias, &provider, msg.as_bytes())?;
/// ```
pub fn build_auth_challenge_message(
    nonce: &str,
    domain: &str,
) -> Result<String, AuthChallengeError> {
    if nonce.is_empty() {
        return Err(AuthChallengeError::EmptyNonce);
    }
    if domain.is_empty() {
        return Err(AuthChallengeError::EmptyDomain);
    }
    let payload = serde_json::json!({
        "domain": domain,
        "nonce": nonce,
    });
    json_canon::to_string(&payload).map_err(|e| AuthChallengeError::Canonicalization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_alphabetically() {
        let payload = serde_json::json!({
            "nonce": "abc",
            "domain": "xyz",
        });
        let canonical = json_canon::to_string(&payload).expect("canonical");
        assert_eq!(canonical, r#"{"domain":"xyz","nonce":"abc"}"#);
    }

    #[test]
    fn build_auth_challenge_message_produces_canonical_json() {
        let msg = build_auth_challenge_message("abc123", "auths.dev").unwrap();
        assert_eq!(msg, r#"{"domain":"auths.dev","nonce":"abc123"}"#);
    }

    #[test]
    fn build_auth_challenge_message_rejects_empty_nonce() {
        let err = build_auth_challenge_message("", "auths.dev").unwrap_err();
        assert!(matches!(err, AuthChallengeError::EmptyNonce));
    }

    #[test]
    fn build_auth_challenge_message_rejects_empty_domain() {
        let err = build_auth_challenge_message("abc", "").unwrap_err();
        assert!(matches!(err, AuthChallengeError::EmptyDomain));
    }
}
