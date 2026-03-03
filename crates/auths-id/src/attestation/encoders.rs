use crate::error::StorageError;
use auths_verifier::core::Attestation;

pub fn json_encoder(att: &Attestation) -> Result<Vec<u8>, StorageError> {
    Ok(serde_json::to_vec_pretty(att)?)
}
