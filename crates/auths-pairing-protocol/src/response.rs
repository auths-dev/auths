use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use auths_crypto::SecureSeed;

use crate::error::ProtocolError;
use crate::token::PairingToken;

/// A response to a pairing request from the responding device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    pub short_code: String,
    pub device_x25519_pubkey: String,
    pub device_signing_pubkey: String,
    pub device_did: String,
    pub signature: String,
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
    ) -> Result<(Self, Zeroizing<[u8; 32]>), ProtocolError> {
        if token.is_expired(now) {
            return Err(ProtocolError::Expired);
        }

        let device_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let device_x25519_public = PublicKey::from(&device_x25519_secret);

        let initiator_x25519_bytes = token.ephemeral_pubkey_bytes()?;
        let initiator_x25519 = PublicKey::from(initiator_x25519_bytes);

        let shared = device_x25519_secret.diffie_hellman(&initiator_x25519);
        let shared_secret = Zeroizing::new(*shared.as_bytes());

        let device_signing_pubkey = URL_SAFE_NO_PAD.encode(device_pubkey);
        let device_x25519_pubkey_str = URL_SAFE_NO_PAD.encode(device_x25519_public.as_bytes());

        let mut message = Vec::new();
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_x25519_bytes);
        message.extend_from_slice(device_x25519_public.as_bytes());

        // Sign with Ed25519 via ring directly (no tokio needed)
        let sig_bytes = sign_ed25519_sync(device_seed, &message)?;
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
    pub fn verify(&self, now: DateTime<Utc>, token: &PairingToken) -> Result<(), ProtocolError> {
        if token.is_expired(now) {
            return Err(ProtocolError::Expired);
        }

        let initiator_x25519_bytes = token.ephemeral_pubkey_bytes()?;
        let device_x25519_bytes = self.device_x25519_pubkey_bytes()?;
        let device_signing_bytes = self.device_signing_pubkey_bytes()?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        let mut message = Vec::new();
        message.extend_from_slice(token.short_code.as_bytes());
        message.extend_from_slice(&initiator_x25519_bytes);
        message.extend_from_slice(&device_x25519_bytes);

        // dispatch on device-signing pubkey length (curve travels with bytes
        // at this boundary — the device DID encodes curve via multicodec, but the raw
        // bytes here come from the pairing response; length is safe because Ed25519=32
        // and P-256 compressed=33).
        match device_signing_bytes.len() {
            32 => {
                let peer = UnparsedPublicKey::new(&ED25519, &device_signing_bytes);
                peer.verify(&message, &signature_bytes)
                    .map_err(|_| ProtocolError::InvalidSignature)?;
            }
            33 | 65 => {
                auths_crypto::RingCryptoProvider::p256_verify(
                    &device_signing_bytes,
                    &message,
                    &signature_bytes,
                )
                .map_err(|_| ProtocolError::InvalidSignature)?;
            }
            _ => return Err(ProtocolError::InvalidSignature),
        }

        Ok(())
    }

    pub fn device_x25519_pubkey_bytes(&self) -> Result<[u8; 32], ProtocolError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.device_x25519_pubkey)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        bytes.try_into().map_err(|_| {
            ProtocolError::KeyExchangeFailed("Invalid X25519 pubkey length".to_string())
        })
    }

    pub fn device_signing_pubkey_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        URL_SAFE_NO_PAD
            .decode(&self.device_signing_pubkey)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

/// Sign a message with Ed25519 using ring directly (sync, no tokio).
fn sign_ed25519_sync(seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes())
        .map_err(|e| ProtocolError::KeyGenFailed(format!("{e}")))?;
    Ok(keypair.sign(message).as_ref().to_vec())
}

/// Generate a fresh Ed25519 keypair for tests via the curve-aware primitive.
///
/// fn-116.6: replaces the prior byte-slicing hack that extracted the seed from
/// ring's PKCS#8 v2 layout. Uses `auths_crypto::parse_key_material` which is
/// curve-detecting and doesn't depend on ring's internal DER layout.
#[cfg(test)]
fn generate_ed25519_keypair_sync() -> Result<(SecureSeed, [u8; 32]), ProtocolError> {
    use ring::rand::SystemRandom;

    let rng = SystemRandom::new();
    #[allow(clippy::disallowed_methods)] // test-only keypair generator; one-off helper
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| ProtocolError::KeyGenFailed("Key generation failed".to_string()))?;
    let parsed = auths_crypto::parse_key_material(pkcs8_doc.as_ref())
        .map_err(|e| ProtocolError::KeyGenFailed(format!("{e}")))?;
    let seed: [u8; 32] = *parsed.seed.as_bytes();
    let public_key: [u8; 32] = parsed
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::KeyGenFailed("Public key not 32 bytes".to_string()))?;
    Ok((SecureSeed::new(seed), public_key))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::token::PairingToken;

    fn make_token() -> crate::token::PairingSession {
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
        let (seed, pubkey) = generate_ed25519_keypair_sync().unwrap();

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
        let (seed, pubkey) = generate_ed25519_keypair_sync().unwrap();

        let result = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        );
        assert!(matches!(result, Err(ProtocolError::Expired)));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let now = chrono::Utc::now();
        let session = make_token();
        let (seed, pubkey) = generate_ed25519_keypair_sync().unwrap();

        let (mut response, _) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        let mut sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        response.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let result = response.verify(now, &session.token);
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }

    #[test]
    fn test_shared_secret_matches() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_ed25519_keypair_sync().unwrap();

        let (response, responder_secret) = PairingResponse::create(
            now,
            &session.token,
            &seed,
            &pubkey,
            "did:key:z6MkTest".to_string(),
            None,
        )
        .unwrap();

        let device_x25519_bytes = response.device_x25519_pubkey_bytes().unwrap();
        let initiator_secret = session.complete_exchange(&device_x25519_bytes).unwrap();

        assert_eq!(*initiator_secret, *responder_secret);
    }

    #[test]
    fn test_session_consumed_prevents_reuse() {
        let now = chrono::Utc::now();
        let mut session = make_token();
        let (seed, pubkey) = generate_ed25519_keypair_sync().unwrap();

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

        assert!(session.complete_exchange(&device_x25519_bytes).is_ok());

        let result = session.complete_exchange(&device_x25519_bytes);
        assert!(matches!(result, Err(ProtocolError::SessionConsumed)));
    }
}
