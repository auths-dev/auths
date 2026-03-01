//! secp256k1/BIP340 Schnorr signature support for Nostr integration.
//!
//! This module provides `Secp256k1KeyPair` for generating and using secp256k1 keys
//! with BIP340 Schnorr signatures, as required by the Nostr protocol.

use crate::error::AgentError;
use k256::schnorr::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Type alias for k256's FieldBytes (32 bytes)
type FieldBytes = k256::elliptic_curve::FieldBytes<k256::Secp256k1>;

/// A secp256k1 key pair for BIP340 Schnorr signatures.
///
/// Used primarily for Nostr event signing. The private key bytes are stored
/// in a `Zeroizing` wrapper for automatic secure memory cleanup.
pub struct Secp256k1KeyPair {
    /// Raw secret key bytes (32 bytes), zeroized on drop
    secret_key_bytes: Zeroizing<[u8; 32]>,
}

impl Secp256k1KeyPair {
    /// Generates a new random secp256k1 key pair using OS-provided randomness.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let bytes: [u8; 32] = signing_key.to_bytes().into();
        Self {
            secret_key_bytes: Zeroizing::new(bytes),
        }
    }

    /// Creates a key pair from raw secret key bytes (32 bytes).
    ///
    /// Returns an error if the bytes are not a valid secp256k1 secret key.
    pub fn from_bytes(secret_bytes: &[u8]) -> Result<Self, AgentError> {
        if secret_bytes.len() != 32 {
            return Err(AgentError::CryptoError(format!(
                "Invalid secret key length: expected 32, got {}",
                secret_bytes.len()
            )));
        }

        // Validate by trying to create a SigningKey
        let bytes_array: [u8; 32] = secret_bytes.try_into().unwrap();
        let field_bytes = FieldBytes::from_slice(&bytes_array);
        SigningKey::from_bytes(field_bytes)
            .map_err(|e| AgentError::CryptoError(format!("Invalid secp256k1 secret key: {}", e)))?;

        Ok(Self {
            secret_key_bytes: Zeroizing::new(bytes_array),
        })
    }

    /// Returns the raw secret key bytes (32 bytes).
    ///
    /// The returned bytes are wrapped in `Zeroizing` for secure memory cleanup.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret_key_bytes.to_vec())
    }

    /// Returns the public key bytes (32 bytes for x-only BIP340 format).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }

    /// Returns the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key().verifying_key()
    }

    /// Signs a message using BIP340 Schnorr signature scheme.
    ///
    /// The message is hashed internally according to BIP340 specification.
    /// Returns the 64-byte Schnorr signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AgentError> {
        let signing_key = self.signing_key();
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies a BIP340 Schnorr signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, AgentError> {
        let sig = k256::schnorr::Signature::try_from(signature)
            .map_err(|e| AgentError::CryptoError(format!("Invalid signature format: {}", e)))?;

        Ok(self.verifying_key().verify(message, &sig).is_ok())
    }

    /// Reconstructs the SigningKey from stored bytes.
    fn signing_key(&self) -> SigningKey {
        // This should never fail since we validated in from_bytes/generate
        let field_bytes = FieldBytes::from_slice(&*self.secret_key_bytes);
        SigningKey::from_bytes(field_bytes).expect("Stored key bytes should always be valid")
    }
}

impl Clone for Secp256k1KeyPair {
    fn clone(&self) -> Self {
        Self {
            secret_key_bytes: Zeroizing::new(*self.secret_key_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = Secp256k1KeyPair::generate();
        let public_key = keypair.public_key_bytes();

        // BIP340 x-only public keys are 32 bytes
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Secp256k1KeyPair::generate();
        let message = b"Hello, Nostr!";

        let signature = keypair.sign(message).expect("Signing should succeed");

        // BIP340 Schnorr signatures are 64 bytes
        assert_eq!(signature.len(), 64);

        // Verify the signature
        let valid = keypair
            .verify(message, &signature)
            .expect("Verification should succeed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn test_sign_different_messages() {
        let keypair = Secp256k1KeyPair::generate();
        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let sig1 = keypair.sign(message1).expect("Signing should succeed");
        let sig2 = keypair.sign(message2).expect("Signing should succeed");

        // Signatures should be different
        assert_ne!(sig1, sig2);

        // Each signature should verify against its message
        assert!(keypair.verify(message1, &sig1).unwrap());
        assert!(keypair.verify(message2, &sig2).unwrap());

        // Cross-verification should fail
        assert!(!keypair.verify(message1, &sig2).unwrap());
        assert!(!keypair.verify(message2, &sig1).unwrap());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let keypair = Secp256k1KeyPair::generate();
        let original_public = keypair.public_key_bytes();

        // Serialize secret key
        let secret_bytes = keypair.secret_bytes();
        assert_eq!(secret_bytes.len(), 32);

        // Reconstruct from bytes
        let restored =
            Secp256k1KeyPair::from_bytes(&secret_bytes).expect("Reconstruction should succeed");

        // Public keys should match
        assert_eq!(restored.public_key_bytes(), original_public);

        // Both should produce the same signature
        let message = b"Test message";
        let sig1 = keypair.sign(message).unwrap();
        let sig2 = restored.sign(message).unwrap();

        // Note: Schnorr signatures may include randomness, so we verify both work
        assert!(keypair.verify(message, &sig1).unwrap());
        assert!(keypair.verify(message, &sig2).unwrap());
        assert!(restored.verify(message, &sig1).unwrap());
        assert!(restored.verify(message, &sig2).unwrap());
    }

    #[test]
    fn test_invalid_secret_bytes() {
        // All zeros is not a valid secret key
        let invalid = [0u8; 32];
        let result = Secp256k1KeyPair::from_bytes(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_length() {
        // Wrong length
        let result = Secp256k1KeyPair::from_bytes(&[1u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_format() {
        let keypair = Secp256k1KeyPair::generate();
        let message = b"Test";

        // Too short signature
        let result = keypair.verify(message, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clone() {
        let keypair = Secp256k1KeyPair::generate();
        let cloned = keypair.clone();

        assert_eq!(keypair.public_key_bytes(), cloned.public_key_bytes());

        // Both should be able to sign
        let message = b"Clone test";
        let sig = keypair.sign(message).unwrap();
        assert!(cloned.verify(message, &sig).unwrap());
    }

    #[test]
    fn test_verifying_key_directly() {
        let keypair = Secp256k1KeyPair::generate();
        let message = b"Direct verify test";
        let signature = keypair.sign(message).unwrap();

        // Verify using k256's VerifyingKey directly
        let verifying_key = keypair.verifying_key();
        let sig = k256::schnorr::Signature::try_from(signature.as_slice()).unwrap();
        assert!(verifying_key.verify(message, &sig).is_ok());
    }
}
