//! UniFFI bindings for auths-verifier
//!
//! This crate provides Swift and Kotlin bindings for the Auths attestation
//! verification library using Mozilla's UniFFI.

use ::auths_verifier::core::{Attestation, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE};
use ::auths_verifier::types::{
    ChainLink as RustChainLink,
    DeviceDID,
    VerificationReport as RustVerificationReport,
    VerificationStatus as RustVerificationStatus,
};
use ::auths_verifier::verify::{
    verify_chain as rust_verify_chain,
    verify_device_authorization as rust_verify_device_authorization,
    verify_with_keys,
};

// Use proc-macro based approach (no UDL)
uniffi::setup_scaffolding!();

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VerifierError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of a single attestation verification
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<String>,
}

/// Status of a verification operation
#[derive(Debug, Clone, uniffi::Enum)]
pub enum VerificationStatus {
    Valid,
    Expired { at: String },
    Revoked { at: Option<String> },
    InvalidSignature { step: u32 },
    BrokenChain { missing_link: String },
}

impl From<RustVerificationStatus> for VerificationStatus {
    fn from(status: RustVerificationStatus) -> Self {
        match status {
            RustVerificationStatus::Valid => VerificationStatus::Valid,
            RustVerificationStatus::Expired { at } => VerificationStatus::Expired {
                at: at.to_rfc3339(),
            },
            RustVerificationStatus::Revoked { at } => VerificationStatus::Revoked {
                at: at.map(|t| t.to_rfc3339()),
            },
            RustVerificationStatus::InvalidSignature { step } => {
                VerificationStatus::InvalidSignature { step: step as u32 }
            }
            RustVerificationStatus::BrokenChain { missing_link } => {
                VerificationStatus::BrokenChain { missing_link }
            }
        }
    }
}

/// A single link in the attestation chain
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChainLink {
    pub issuer: String,
    pub subject: String,
    pub valid: bool,
    pub error: Option<String>,
}

impl From<RustChainLink> for ChainLink {
    fn from(link: RustChainLink) -> Self {
        ChainLink {
            issuer: link.issuer,
            subject: link.subject,
            valid: link.valid,
            error: link.error,
        }
    }
}

/// Complete verification report for chain verification
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerificationReport {
    pub status: VerificationStatus,
    pub chain: Vec<ChainLink>,
    pub warnings: Vec<String>,
}

impl From<RustVerificationReport> for VerificationReport {
    fn from(report: RustVerificationReport) -> Self {
        VerificationReport {
            status: report.status.into(),
            chain: report.chain.into_iter().map(|l| l.into()).collect(),
            warnings: report.warnings,
        }
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Verify a single attestation against an issuer's public key.
///
/// # Arguments
/// * `attestation_json` - The attestation as a JSON string
/// * `issuer_pk_hex` - The issuer's Ed25519 public key in hex format (64 chars)
///
/// # Returns
/// VerificationResult with valid flag and optional error message
#[uniffi::export]
pub fn verify_attestation(attestation_json: String, issuer_pk_hex: String) -> VerificationResult {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return VerificationResult {
            valid: false,
            error: Some(format!(
                "Attestation JSON too large: {} bytes, max {}",
                attestation_json.len(), MAX_ATTESTATION_JSON_SIZE
            )),
        };
    }

    // Decode hex
    let issuer_pk_bytes = match hex::decode(&issuer_pk_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return VerificationResult {
                valid: false,
                error: Some(format!("Invalid issuer public key hex: {}", e)),
            };
        }
    };

    if issuer_pk_bytes.len() != 32 {
        return VerificationResult {
            valid: false,
            error: Some(format!(
                "Invalid issuer public key length: expected 32 bytes (64 hex chars), got {}",
                issuer_pk_bytes.len()
            )),
        };
    }

    // Parse attestation
    let att: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return VerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {}", e)),
            };
        }
    };

    // Verify
    match verify_with_keys(&att, &issuer_pk_bytes) {
        Ok(_verified) => VerificationResult {
            valid: true,
            error: None,
        },
        Err(e) => VerificationResult {
            valid: false,
            error: Some(e.to_string()),
        },
    }
}

/// Verify a chain of attestations from a root identity to a leaf device.
///
/// # Arguments
/// * `attestations_json` - List of attestation JSON strings
/// * `root_pk_hex` - The root identity's Ed25519 public key in hex format
///
/// # Returns
/// VerificationReport with status, chain details, and warnings
#[uniffi::export]
pub fn verify_chain(
    attestations_json: Vec<String>,
    root_pk_hex: String,
) -> Result<VerificationReport, VerifierError> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(VerifierError::InvalidInput(format!(
            "Total attestation JSON too large: {} bytes, max {}",
            total, MAX_JSON_BATCH_SIZE
        )));
    }

    // Decode hex
    let root_pk_bytes = hex::decode(&root_pk_hex)
        .map_err(|e| VerifierError::InvalidPublicKey(format!("Invalid hex: {}", e)))?;

    if root_pk_bytes.len() != 32 {
        return Err(VerifierError::InvalidPublicKey(format!(
            "Expected 32 bytes (64 hex chars), got {}",
            root_pk_bytes.len()
        )));
    }

    // Parse attestations
    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| VerifierError::ParseError(format!("Attestation {}: {}", i, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Verify chain
    match rust_verify_chain(&attestations, &root_pk_bytes) {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(VerifierError::VerificationFailed(format!(
            "Chain verification failed: {}",
            e
        ))),
    }
}

/// Full cryptographic verification that a device is authorized.
///
/// Unlike `is_device_listed()`, this function verifies cryptographic signatures
/// to ensure attestations have not been forged or tampered with.
///
/// # Arguments
/// * `identity_did` - The identity DID string
/// * `device_did` - The device DID string
/// * `attestations_json` - List of attestation JSON strings
/// * `identity_pk_hex` - The identity's Ed25519 public key in hex format (64 chars)
///
/// # Returns
/// VerificationReport with verification details
#[uniffi::export]
pub fn verify_device_authorization(
    identity_did: String,
    device_did: String,
    attestations_json: Vec<String>,
    identity_pk_hex: String,
) -> Result<VerificationReport, VerifierError> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(VerifierError::InvalidInput(format!(
            "Total attestation JSON too large: {} bytes, max {}",
            total, MAX_JSON_BATCH_SIZE
        )));
    }

    // Decode hex
    let identity_pk_bytes = hex::decode(&identity_pk_hex)
        .map_err(|e| VerifierError::InvalidPublicKey(format!("Invalid hex: {}", e)))?;

    if identity_pk_bytes.len() != 32 {
        return Err(VerifierError::InvalidPublicKey(format!(
            "Expected 32 bytes (64 hex chars), got {}",
            identity_pk_bytes.len()
        )));
    }

    // Parse attestations
    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| VerifierError::ParseError(format!("Attestation {}: {}", i, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let device = DeviceDID::parse(&device_did)
        .map_err(|e| VerifierError::InvalidInput(format!("Invalid device DID: {e}")))?;

    // Verify
    match rust_verify_device_authorization(&identity_did, &device, &attestations, &identity_pk_bytes) {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(VerifierError::VerificationFailed(format!(
            "Device authorization verification failed: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_attestation_invalid_hex() {
        let result = verify_attestation("{}".to_string(), "not-hex".to_string());
        assert!(!result.valid);
        assert!(result.error.as_ref().unwrap().contains("Invalid"));
    }

    #[test]
    fn test_verify_attestation_invalid_json() {
        let result = verify_attestation("not-json".to_string(), "0".repeat(64));
        assert!(!result.valid);
        assert!(result.error.as_ref().unwrap().contains("parse"));
    }

    #[test]
    fn test_verify_chain_empty() {
        let result = verify_chain(vec![], "0".repeat(64));
        assert!(result.is_ok());
        let report = result.unwrap();
        match report.status {
            VerificationStatus::BrokenChain { missing_link } => {
                assert_eq!(missing_link, "empty chain");
            }
            _ => panic!("Expected BrokenChain status"),
        }
    }
}
