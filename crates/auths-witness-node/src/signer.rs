//! The witness signing port.
//!
//! A signer exposes exactly `sign()` — never key export (I-DEPLOY-3). The
//! reference [`FileSigner`] holds an Ed25519 key derived from the node's
//! first-boot seed; production nodes back this with KMS or PKCS#11 adapters that
//! implement the same trait without ever surfacing the private key.

use ed25519_dalek::{Signer as DalekSigner, SigningKey};

/// A witness's cosigning identity. Ed25519, because witnesses cosign with
/// Ed25519 (the checkpoint/anchor cosignature curve).
pub trait Signer: Send + Sync {
    /// The witness name carried in cosignatures.
    fn witness_name(&self) -> &str;

    /// The 32-byte Ed25519 verifying key.
    fn public_key(&self) -> [u8; 32];

    /// Sign `message`, returning the 64-byte Ed25519 signature. The private key
    /// never leaves the signer.
    ///
    /// Args:
    /// * `message`: the exact bytes to sign (an anchor cosign message).
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// A file/seed-backed Ed25519 signer (development and single-host custody).
pub struct FileSigner {
    name: String,
    key: SigningKey,
}

impl FileSigner {
    /// Build a signer from a witness name and a 32-byte seed.
    ///
    /// Args:
    /// * `name`: the witness name.
    /// * `seed`: the 32-byte Ed25519 seed (the node's first-boot identity).
    ///
    /// Usage:
    /// ```
    /// # use auths_witness_node::{FileSigner, Signer};
    /// let signer = FileSigner::from_seed("us-west", [3u8; 32]);
    /// assert_eq!(signer.witness_name(), "us-west");
    /// ```
    pub fn from_seed(name: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            name: name.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }
}

impl Signer for FileSigner {
    fn witness_name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}
