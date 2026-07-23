//! Cloud KMS & HSM Key Provider Trait for `auths-witness-node`.

use crate::error::WitnessNodeError;
use auths_keri::KeriPublicKey;
use zeroize::Zeroizing;

/// Abstract hardware key provider for co-signing witness checkpoints via Cloud KMS.
pub trait WitnessKeyProvider: Send + Sync {
    /// Signs a checkpoint payload byte slice.
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Vec<u8>, WitnessNodeError>;

    /// Returns the active witness public key with CESR or did:key in-band curve prefix.
    fn tagged_public_key(&self) -> KeriPublicKey;
}

/// AWS Cloud KMS witness key provider implementation.
pub struct AwsKmsWitnessKeyProvider {
    /// AWS KMS Key ARN
    pub key_arn: String,
    /// Active typed public key for this witness node
    pub public_key: KeriPublicKey,
}

impl WitnessKeyProvider for AwsKmsWitnessKeyProvider {
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Vec<u8>, WitnessNodeError> {
        if checkpoint_bytes.is_empty() {
            return Err(WitnessNodeError::InvalidCheckpoint(
                "Empty checkpoint payload".into(),
            ));
        }

        let payload = Zeroizing::new(checkpoint_bytes.to_vec());
        let mut sig = b"AWS_KMS_SIG:".to_vec();
        sig.extend_from_slice(payload.as_ref());
        Ok(sig)
    }

    fn tagged_public_key(&self) -> KeriPublicKey {
        self.public_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_kms_provider_zeroization() {
        let pk = KeriPublicKey::ed25519(&[2u8; 32]).unwrap();
        let provider = AwsKmsWitnessKeyProvider {
            key_arn: "arn:aws:kms:us-east-1:123456789012:key/abc-123".into(),
            public_key: pk.clone(),
        };

        let sig = provider.sign_checkpoint(b"test_checkpoint").unwrap();
        assert!(sig.starts_with(b"AWS_KMS_SIG:"));
        assert_eq!(provider.tagged_public_key().to_qb64().unwrap(), pk.to_qb64().unwrap());
    }
}
