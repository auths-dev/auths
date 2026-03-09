use crate::crypto::provider_bridge;
use crate::error::AgentError;
use auths_crypto::SecureSeed;
use log::error;
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

/// An in-memory registry of SSH keys used by the local agent.
/// Stores seeds securely using SecureSeed (zeroize-on-drop).
/// Note: Clone is intentionally NOT derived to prevent accidental copying of key material.
#[derive(Default)]
pub struct AgentCore {
    /// Maps public key bytes (`Vec<u8>`) to the corresponding SecureSeed.
    pub keys: HashMap<Vec<u8>, SecureSeed>,
}

impl fmt::Debug for AgentCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCore")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl AgentCore {
    /// Create a new `AgentState`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers decrypted PKCS#8 key bytes in memory.
    /// Extracts the seed and public key, validates them, and stores the seed.
    ///
    /// Args:
    /// * `pkcs8_bytes` - The raw, decrypted PKCS#8 bytes for the Ed25519 key, wrapped in `Zeroizing`.
    pub fn register_key(&mut self, pkcs8_bytes: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        let (seed, pubkey) = crate::crypto::signer::load_seed_and_pubkey(&pkcs8_bytes)?;
        self.keys.insert(pubkey.to_vec(), seed);
        Ok(())
    }

    /// Removes a key by its public key bytes. Returns error if key not found.
    pub fn unregister_key(&mut self, pubkey: &[u8]) -> Result<(), AgentError> {
        self.keys
            .remove(pubkey)
            .map(|_| ())
            .ok_or(AgentError::KeyNotFound)
    }

    /// Signs a message using the key associated with the given public key bytes.
    /// Routes through CryptoProvider via the sync bridge.
    pub fn sign(&self, pubkey_to_find: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        let seed = self
            .keys
            .get(pubkey_to_find)
            .ok_or(AgentError::KeyNotFound)?;

        provider_bridge::sign_ed25519_sync(seed, data).map_err(|e| {
            error!("CryptoProvider signing failed: {}", e);
            AgentError::CryptoError(format!("Ed25519 signing failed: {}", e))
        })
    }

    /// Returns all public key bytes currently registered.
    pub fn public_keys(&self) -> Vec<Vec<u8>> {
        self.keys.keys().cloned().collect()
    }

    /// Returns the number of keys currently loaded in the agent.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Removes all keys from the agent core.
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use zeroize::Zeroizing;

    fn generate_test_key_bytes() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate PKCS#8");
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let keypair =
            Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to parse generated PKCS#8");
        let pubkey_bytes = keypair.public_key().as_ref().to_vec();
        (pubkey_bytes, pkcs8_bytes)
    }

    fn core_with_two_keys() -> (AgentCore, Vec<u8>, Vec<u8>) {
        let (pubkey1, pkcs8_1) = generate_test_key_bytes();
        let (pubkey2, pkcs8_2) = generate_test_key_bytes();
        let mut core = AgentCore::default();
        core.register_key(Zeroizing::new(pkcs8_1)).unwrap();
        core.register_key(Zeroizing::new(pkcs8_2)).unwrap();
        (core, pubkey1, pubkey2)
    }

    #[test]
    fn register_keys_updates_count_and_listing() {
        let (core, pubkey1, pubkey2) = core_with_two_keys();
        assert_eq!(core.key_count(), 2);
        let mut keys = core.public_keys();
        keys.sort();
        let mut expected = vec![pubkey1, pubkey2];
        expected.sort();
        assert_eq!(keys, expected);
    }

    #[test]
    fn sign_produces_verifiable_signature() {
        let (core, pubkey1, _) = core_with_two_keys();
        let message = b"test message for agent core";
        let signature = core.sign(&pubkey1, message).unwrap();
        assert!(!signature.is_empty());
        let ring_key = UnparsedPublicKey::new(&ED25519, &pubkey1);
        assert!(ring_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn sign_with_different_keys_produces_different_signatures() {
        let (core, pubkey1, pubkey2) = core_with_two_keys();
        let message = b"test message";
        let sig1 = core.sign(&pubkey1, message).unwrap();
        let sig2 = core.sign(&pubkey2, message).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_with_nonexistent_key_returns_key_not_found() {
        let (core, _, _) = core_with_two_keys();
        let err = core.sign(&[99u8; 32], b"msg").unwrap_err();
        assert!(matches!(err, AgentError::KeyNotFound));
    }

    #[test]
    fn unregister_removes_key_and_prevents_signing() {
        let (mut core, pubkey1, pubkey2) = core_with_two_keys();
        core.unregister_key(&pubkey1).unwrap();
        assert_eq!(core.key_count(), 1);
        assert_eq!(core.public_keys(), vec![pubkey2.clone()]);
        assert!(matches!(
            core.sign(&pubkey1, b"msg").unwrap_err(),
            AgentError::KeyNotFound
        ));
        // Remaining key still works
        assert!(core.sign(&pubkey2, b"msg").is_ok());
    }

    #[test]
    fn clear_keys_removes_all() {
        let (mut core, pubkey1, _) = core_with_two_keys();
        core.clear_keys();
        assert_eq!(core.key_count(), 0);
        assert!(core.public_keys().is_empty());
        assert!(matches!(
            core.unregister_key(&pubkey1).unwrap_err(),
            AgentError::KeyNotFound
        ));
    }

    #[test]
    fn test_register_invalid_key() {
        let mut core = AgentCore::default();
        let invalid_bytes = vec![1, 2, 3, 4];
        let result = core.register_key(Zeroizing::new(invalid_bytes));
        assert!(result.is_err());
        assert_eq!(core.key_count(), 0);
    }
}
