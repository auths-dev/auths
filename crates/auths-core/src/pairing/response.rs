//! Pairing response handling with X25519 ECDH key exchange.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use auths_crypto::SecureSeed;

use super::error::PairingError;
use super::token::PairingToken;

/// A response to a pairing request from the responding device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    /// The short code from the pairing token.
    pub short_code: String,
    /// Responder's ephemeral X25519 public key (base64url encoded).
    pub device_x25519_pubkey: String,
    /// Responder's Ed25519 signing public key (base64url encoded).
    pub device_signing_pubkey: String,
    /// Responder's DID (did:key:z6Mk...).
    pub device_did: String,
    /// Ed25519 signature over: short_code || initiator_x25519 || device_x25519
    pub signature: String,
    /// Optional friendly device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

impl PairingResponse {
    /// Create a new pairing response (responder side).
    ///
    /// Args:
    /// * `now` - Current time for expiry checking
    /// * `token` - The pairing token from the initiating device
    /// * `device_seed` - The responding device's Ed25519 seed
    /// * `device_pubkey` - The responding device's Ed25519 public key
    /// * `device_did` - The responding device's DID string
    /// * `device_name` - Optional friendly name for the device
    pub fn create(
        now: DateTime<Utc>,
        token: &PairingToken,
        device_seed: &SecureSeed,
        device_pubkey: &[u8; 32],
        device_did: String,
        device_name: Option<String>,
    ) -> Result<(Self, Zeroizing<[u8; 32]>), PairingError> {
        use crate::crypto::provider_bridge;

        if token.is_expired(now) {
            return Err(PairingError::Expired);
        }

        // Generate device X25519 ephemeral key
        let device_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let device_x25519_public = PublicKey::from(&device_x25519_secret);

        // Decode initiator's X25519 public key from token
        let initiator_x25519_bytes = token.ephemeral_pubkey_bytes()?;
        let initiator_x25519 = PublicKey::from(initiator_x25519_bytes);

        // Perform ECDH
        let shared = device_x25519_secret.diffie_hellman(&initiator_x25519);
        let shared_secret = Zeroizing::new(*shared.as_bytes());

        // Encode device Ed25519 public key
        let device_signing_pubkey = URL_SAFE_NO_PAD.encode(device_pubkey);

        // Encode device X25519 public key
        let device_x25519_pubkey_str = URL_SAFE_NO_PAD.encode(device_x25519_public.as_bytes());

        // Build the binding message: short_code || initiator_x25519 || device_x25519
        let mut message = Vec::new();
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_x25519_bytes);
        message.extend_from_slice(device_x25519_public.as_bytes());

        // Sign with Ed25519 via CryptoProvider
        let sig_bytes = provider_bridge::sign_ed25519_sync(device_seed, &message)
            .map_err(|_| PairingError::KeyGenFailed("Ed25519 signing failed".to_string()))?;
        let signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let response = PairingResponse {
            short_code: token.short_code.clone(),
            device_x25519_pubkey: device_x25519_pubkey_str,
            device_signing_pubkey,
            device_did,
            signature,
            device_name,
        };

        Ok((response, shared_secret))
    }

    /// Verify the response's Ed25519 signature.
    ///
    /// Args:
    /// * `now` - Current time for expiry checking
    /// * `token` - The pairing token to verify against
    pub fn verify(&self, now: DateTime<Utc>, token: &PairingToken) -> Result<(), PairingError> {
        use crate::crypto::provider_bridge;

        if token.is_expired(now) {
            return Err(PairingError::Expired);
        }

        // Decode keys
        let initiator_x25519_bytes = token.ephemeral_pubkey_bytes()?;
        let device_x25519_bytes = self.device_x25519_pubkey_bytes()?;
        let device_signing_bytes = self.device_signing_pubkey_bytes()?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| PairingError::InvalidSignature)?;

        // Reconstruct the binding message
        let mut message = Vec::new();
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_x25519_bytes);
        message.extend_from_slice(&device_x25519_bytes);

        // Verify Ed25519 signature via CryptoProvider
        provider_bridge::verify_ed25519_sync(&device_signing_bytes, &message, &signature_bytes)
            .map_err(|_| PairingError::InvalidSignature)?;

        Ok(())
    }

    /// Get the device X25519 public key as bytes.
    pub fn device_x25519_pubkey_bytes(&self) -> Result<[u8; 32], PairingError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.device_x25519_pubkey)
            .map_err(|_| PairingError::InvalidSignature)?;
        bytes.try_into().map_err(|_| {
            PairingError::KeyExchangeFailed("Invalid X25519 pubkey length".to_string())
        })
    }

    /// Get the device Ed25519 signing public key as bytes.
    pub fn device_signing_pubkey_bytes(&self) -> Result<Vec<u8>, PairingError> {
        URL_SAFE_NO_PAD
            .decode(&self.device_signing_pubkey)
            .map_err(|_| PairingError::InvalidSignature)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::crypto::provider_bridge;

    fn generate_test_seed_and_pubkey() -> (SecureSeed, [u8; 32]) {
        provider_bridge::generate_ed25519_keypair_sync().unwrap()
    }

    fn make_token() -> super::super::token::PairingSession {
        PairingToken::generate(
            chrono::Utc::now(),
            "did:keri:test123".to_string(),
            "http://localhost:3000".to_string(),
            vec!["sign_commit".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn test_create_and_verify_response() {
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, pubkey) = generate_test_seed_and_pubkey();

        let (response, _shared_secret) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            Some("Test Device".to_string()),
        )
        .unwrap();

        assert!(response.verify(now, &session.token).is_ok());
    }

    #[test]
    fn test_expired_token_rejected() {
        use chrono::Duration;

        let now = chrono::Utc::now();
        let session = PairingToken::generate_with_expiry(
            now,
            "did:keri:test".to_string(),
            "http://localhost:3000".to_string(),
            vec![],
            Duration::seconds(-1),
        )
        .unwrap();
        let (seed, pubkey) = generate_test_seed_and_pubkey();

        let result = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        );
        assert!(matches!(result, Err(PairingError::Expired)));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, pubkey) = generate_test_seed_and_pubkey();

        let (mut response, _) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        // Tamper with the signature
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        response.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let result = response.verify(now, &session.token);
        assert!(matches!(result, Err(PairingError::InvalidSignature)));
    }

    #[test]
    fn test_shared_secret_matches() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_test_seed_and_pubkey();

        let (response, responder_secret) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        // Initiator completes exchange
        let device_x25519_bytes = response.device_x25519_pubkey_bytes().unwrap();
        let initiator_secret = session.complete_exchange(&device_x25519_bytes).unwrap();

        // Both sides should derive the same shared secret
        assert_eq!(*initiator_secret, *responder_secret);
    }

    #[test]
    fn test_session_consumed_prevents_reuse() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_test_seed_and_pubkey();

        let (response, _) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        let device_x25519_bytes = response.device_x25519_pubkey_bytes().unwrap();

        // First exchange succeeds
        assert!(session.complete_exchange(&device_x25519_bytes).is_ok());

        // Second exchange fails
        let result = session.complete_exchange(&device_x25519_bytes);
        assert!(matches!(result, Err(PairingError::SessionConsumed)));
    }
}
