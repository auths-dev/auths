use anyhow::{Context, Result};
use auths_verifier::core::Attestation;

pub fn json_encoder(att: &Attestation) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(att).context("Failed to encode attestation to JSON")
}
