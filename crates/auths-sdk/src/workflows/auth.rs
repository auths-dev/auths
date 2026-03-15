use auths_core::crypto::provider_bridge;
use auths_core::crypto::ssh::SecureSeed;
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
/// let result = sign_auth_challenge("abc123", "auths.dev", &seed, "deadbeef...", "did:keri:E...")?;
/// println!("Signature: {}", result.signature_hex);
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

    /// The Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

impl AuthsErrorInfo for AuthChallengeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyNonce => "AUTHS-E6001",
            Self::EmptyDomain => "AUTHS-E6002",
            Self::Canonicalization(_) => "AUTHS-E6003",
            Self::SigningFailed(_) => "AUTHS-E6004",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::EmptyNonce => Some("Provide the nonce from the authentication challenge"),
            Self::EmptyDomain => Some("Provide the domain (e.g. auths.dev)"),
            Self::Canonicalization(_) => {
                Some("This is an internal error; please report it as a bug")
            }
            Self::SigningFailed(_) => {
                Some("Check that your identity key is accessible with `auths key list`")
            }
        }
    }
}

/// Signs an authentication challenge for DID-based login.
///
/// Constructs a canonical JSON payload `{"domain":"...","nonce":"..."}` and signs
/// it with Ed25519. The output matches the auth-server's expected `VerifyRequest` format.
///
/// Args:
/// * `nonce`: The challenge nonce from the authentication server.
/// * `domain`: The domain requesting authentication (e.g. `"auths.dev"`).
/// * `seed`: The Ed25519 signing seed.
/// * `public_key_hex`: Hex-encoded Ed25519 public key of the signer.
/// * `did`: The signer's identity DID.
///
/// Usage:
/// ```ignore
/// let result = sign_auth_challenge("abc123", "auths.dev", &seed, "deadbeef...", "did:keri:E...")?;
/// ```
pub fn sign_auth_challenge(
    nonce: &str,
    domain: &str,
    seed: &SecureSeed,
    public_key_hex: &str,
    did: &str,
) -> Result<SignedAuthChallenge, AuthChallengeError> {
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
    let canonical = json_canon::to_string(&payload)
        .map_err(|e| AuthChallengeError::Canonicalization(e.to_string()))?;

    let signature_bytes = provider_bridge::sign_ed25519_sync(seed, canonical.as_bytes())
        .map_err(|e| AuthChallengeError::SigningFailed(e.to_string()))?;

    Ok(SignedAuthChallenge {
        signature_hex: hex::encode(&signature_bytes),
        public_key_hex: public_key_hex.to_string(),
        did: did.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::crypto::provider_bridge;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let public_key_hex = hex::encode(pubkey_bytes);
        let did = "did:keri:Etest1234";

        let result = sign_auth_challenge("test-nonce-42", "auths.dev", &seed, &public_key_hex, did)
            .expect("signing should succeed");

        assert_eq!(result.public_key_hex, public_key_hex);
        assert_eq!(result.did, did);
        assert!(!result.signature_hex.is_empty());

        let canonical = json_canon::to_string(&serde_json::json!({
            "domain": "auths.dev",
            "nonce": "test-nonce-42",
        }))
        .expect("canonical JSON");

        let sig_bytes = hex::decode(&result.signature_hex).expect("valid hex");
        let verify_result =
            provider_bridge::verify_ed25519_sync(&pubkey_bytes, canonical.as_bytes(), &sig_bytes);
        assert!(verify_result.is_ok(), "signature should verify");
    }

    #[test]
    fn empty_nonce_rejected() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let result = sign_auth_challenge(
            "",
            "auths.dev",
            &seed,
            &hex::encode(pubkey_bytes),
            "did:keri:E1",
        );
        assert!(matches!(result, Err(AuthChallengeError::EmptyNonce)));
    }

    #[test]
    fn empty_domain_rejected() {
        let (seed, pubkey_bytes) =
            provider_bridge::generate_ed25519_keypair_sync().expect("keygen should succeed");
        let result = sign_auth_challenge(
            "nonce",
            "",
            &seed,
            &hex::encode(pubkey_bytes),
            "did:keri:E1",
        );
        assert!(matches!(result, Err(AuthChallengeError::EmptyDomain)));
    }

    #[test]
    fn canonical_json_sorts_keys_alphabetically() {
        let payload = serde_json::json!({
            "nonce": "abc",
            "domain": "xyz",
        });
        let canonical = json_canon::to_string(&payload).expect("canonical");
        assert_eq!(canonical, r#"{"domain":"xyz","nonce":"abc"}"#);
    }
}
