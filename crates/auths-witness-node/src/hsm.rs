//! Cloud KMS & HSM Key Provider Trait for `auths-witness-node`.

use crate::error::WitnessNodeError;

/// Abstract hardware key provider for co-signing witness checkpoints via Cloud KMS.
pub trait WitnessKeyProvider: Send + Sync {
    /// Signs a checkpoint payload byte slice.
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Vec<u8>, WitnessNodeError>;

    /// Returns the active witness public key with CESR or did:key in-band curve prefix.
    fn tagged_public_key(&self) -> String;
}

/// AWS Cloud KMS witness key provider implementation.
pub struct AwsKmsWitnessKeyProvider {
    /// AWS KMS Key ARN
    pub key_arn: String,
}

impl WitnessKeyProvider for AwsKmsWitnessKeyProvider {
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Vec<u8>, WitnessNodeError> {
        if checkpoint_bytes.is_empty() {
            return Err(WitnessNodeError::InvalidCheckpoint(
                "Empty checkpoint payload".into(),
            ));
        }
        // Simulated AWS KMS ECDSA / Ed25519 signing result
        Ok(checkpoint_bytes.to_vec())
    }

    fn tagged_public_key(&self) -> String {
        let clean = self
            .key_arn
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();
        format!("did:key:zDnaKMS_{clean}")
    }
}
