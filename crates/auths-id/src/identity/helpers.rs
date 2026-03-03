use crate::error::StorageError;
use git2::Repository;
use pkcs8::{
    AlgorithmIdentifierRef, PrivateKeyInfo,
    der::{Decode, Encode},
};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use crate::storage::{attestation::AttestationSource, git_refs::aggregate_canonical_refs};

use auths_core::storage::keychain::IdentityDID;
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;

const OID_ED25519: pkcs8::der::asn1::ObjectIdentifier =
    pkcs8::der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Debug, Clone)]
pub struct Identity {
    pub did: String,
    pub rid: String,
    pub device_dids: Vec<DeviceDID>,
}

impl Identity {
    pub fn fetch_attestations(
        &self,
        source: &dyn AttestationSource,
    ) -> Result<Vec<Attestation>, StorageError> {
        let mut all_attestations = Vec::new();
        for device_did in &self.device_dids {
            let device_attestations = source.load_attestations_for_device(device_did)?;
            all_attestations.extend(device_attestations);
        }
        Ok(all_attestations)
    }

    pub fn canonical_refs(
        &self,
        repo: &Repository,
    ) -> Result<HashMap<String, String>, StorageError> {
        aggregate_canonical_refs(repo, &self.device_dids)
    }
}

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("KERI error: {0}")]
    Keri(String),
    #[error("PKCS#8 encoding error: {0}")]
    Pkcs8EncodeError(String),
    #[error("PKCS#8 decoding error: {0}")]
    Pkcs8DecodeError(String),
    #[error("Passphrase required")]
    EmptyPassphrase,
    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("Key storage error: {0}")]
    KeyStorage(String),
    #[error("Key retrieval error: {0}")]
    KeyRetrieval(String),
    #[error("Ring crypto error: {0}")]
    RingError(String),
}

impl From<ring::error::Unspecified> for IdentityError {
    fn from(err: ring::error::Unspecified) -> Self {
        IdentityError::RingError(format!("Unspecified ring error: {err}"))
    }
}

impl From<ring::error::KeyRejected> for IdentityError {
    fn from(err: ring::error::KeyRejected) -> Self {
        IdentityError::RingError(format!("Ring key rejected: {err}"))
    }
}

impl From<pkcs8::der::Error> for IdentityError {
    fn from(err: pkcs8::der::Error) -> Self {
        IdentityError::Pkcs8DecodeError(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ManagedIdentity {
    pub controller_did: IdentityDID,
    pub storage_id: String,
    pub metadata: Option<Value>,
}

/// Extract the Ed25519 32-byte seed from PKCS#8-encoded key material.
pub fn extract_seed_bytes(pkcs8_bytes: &[u8]) -> Result<&[u8], IdentityError> {
    let pk_info = PrivateKeyInfo::from_der(pkcs8_bytes)?;
    match pk_info.private_key.len() {
        32 => Ok(pk_info.private_key),
        34 => Ok(&pk_info.private_key[2..]),
        other => Err(IdentityError::InvalidKeyLength(other)),
    }
}

/// Encodes the 32-byte Ed25519 seed as a DER-encoded PKCS#8 private key.
/// Ring expects the private key to be wrapped in an OCTET STRING (34 bytes: 04 20 + 32 bytes seed).
pub fn encode_seed_as_pkcs8(seed_bytes: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let mut wrapped_seed = Vec::with_capacity(34);
    wrapped_seed.push(0x04);
    wrapped_seed.push(0x20);
    wrapped_seed.extend_from_slice(seed_bytes);

    PrivateKeyInfo {
        algorithm: AlgorithmIdentifierRef {
            oid: OID_ED25519,
            parameters: None,
        },
        private_key: &wrapped_seed,
        public_key: None,
    }
    .to_der()
    .map_err(|e| IdentityError::Pkcs8EncodeError(e.to_string()))
}

/// Load an Ed25519 keypair from decrypted key bytes.
///
/// Uses [`auths_crypto::parse_ed25519_seed`] to extract the seed, then
/// builds a PKCS#8 document that ring can consume.
pub fn load_keypair_from_der_or_seed(bytes: &[u8]) -> Result<Ed25519KeyPair, IdentityError> {
    if let Ok(kp) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(bytes) {
        return Ok(kp);
    }

    let seed = auths_crypto::parse_ed25519_seed(bytes)
        .map_err(|e| IdentityError::Pkcs8DecodeError(format!("Cannot parse key data: {e}")))?;
    let pkcs8_bytes = encode_seed_as_pkcs8(seed.as_bytes())?;
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8_bytes)
        .map_err(|e| IdentityError::RingError(format!("Failed to load Ed25519 keypair: {e}")))
}

pub fn generate_keypair_with_seed(
    rng: &SystemRandom,
) -> Result<(Ed25519KeyPair, Vec<u8>), IdentityError> {
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(rng)?;
    let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)?;
    Ok((keypair, pkcs8_bytes))
}
