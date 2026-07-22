//! Local agent socket signature handler with biometric prompt enforcement (Issue #354).

use crate::error::DaemonError;
use serde::{Deserialize, Serialize};

/// Request payload sent to local pairing daemon socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// Key alias requested for signing
    pub key_alias: String,
    /// Hex-encoded payload to sign
    pub payload_hex: String,
}

/// Response payload from local pairing daemon socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    /// Hex-encoded signature bytes
    pub signature_hex: String,
}

/// Trait abstraction for platform biometric keychain signing.
pub trait KeychainBackend {
    /// Prompts user biometrically (Touch ID / Passkey) and signs payload.
    fn sign_with_biometric_prompt(
        &self,
        key_alias: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, DaemonError>;
}

/// Handles a signature request on local agent socket, forcing biometric re-authentication.
///
/// Args:
/// * `request`: The incoming signature request payload.
/// * `keychain`: Reference to platform keychain backend.
///
/// Usage:
/// ```ignore
/// let res = handle_signature_request(req, &keychain)?;
/// ```
pub fn handle_signature_request(
    request: SignRequest,
    keychain: &dyn KeychainBackend,
) -> Result<SignResponse, DaemonError> {
    let payload_bytes = hex::decode(&request.payload_hex)
        .map_err(|e| DaemonError::EntropyCheckFailed(format!("Invalid payload hex: {}", e)))?;

    let signature = keychain.sign_with_biometric_prompt(&request.key_alias, &payload_bytes)?;
    Ok(SignResponse {
        signature_hex: hex::encode(signature),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeychain {
        should_pass: bool,
    }

    impl KeychainBackend for MockKeychain {
        fn sign_with_biometric_prompt(
            &self,
            _key_alias: &str,
            payload: &[u8],
        ) -> Result<Vec<u8>, DaemonError> {
            if self.should_pass {
                Ok(payload.to_vec())
            } else {
                Err(DaemonError::InvalidToken(
                    "Biometric prompt canceled".into(),
                ))
            }
        }
    }

    #[test]
    fn test_signature_request_success() {
        let req = SignRequest {
            key_alias: "main".into(),
            payload_hex: "010203".into(),
        };
        let kc = MockKeychain { should_pass: true };
        let res = handle_signature_request(req, &kc);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().signature_hex, "010203");
    }

    #[test]
    fn test_signature_request_biometric_failure() {
        let req = SignRequest {
            key_alias: "main".into(),
            payload_hex: "010203".into(),
        };
        let kc = MockKeychain { should_pass: false };
        let res = handle_signature_request(req, &kc);
        assert!(res.is_err());
    }
}
