use auths_crypto::CurveType;
use auths_verifier::DevicePublicKey;
use auths_verifier::types::{
    ChainLink as RustChainLink, VerificationReport as RustVerificationReport,
    VerificationStatus as RustVerificationStatus,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Parse hex-encoded public key bytes and infer curve from length.
///
/// This is the single length-based inference point at the FFI boundary where
/// callers pass hex strings without curve metadata.
pub fn validate_pk_hex(hex_str: &str) -> PyResult<(Vec<u8>, CurveType)> {
    let bytes =
        hex::decode(hex_str).map_err(|e| PyValueError::new_err(format!("Invalid hex: {e}")))?;
    let curve = match bytes.len() {
        32 => CurveType::Ed25519,
        33 | 65 => CurveType::P256,
        n => {
            return Err(PyValueError::new_err(format!(
                "Invalid public key length: expected 32 (Ed25519), 33/65 (P-256), got {n}"
            )));
        }
    };
    Ok((bytes, curve))
}

/// Parse a hex-encoded public key and wrap it into a curve-tagged `DevicePublicKey`.
pub fn device_public_key_from_hex(hex_str: &str, label: &str) -> PyResult<DevicePublicKey> {
    let (bytes, curve) = validate_pk_hex(hex_str)?;
    DevicePublicKey::try_new(curve, &bytes)
        .map_err(|e| PyValueError::new_err(format!("Invalid {label} public key: {e}")))
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct VerificationResult {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub error_code: Option<String>,
}

#[pymethods]
impl VerificationResult {
    fn __repr__(&self) -> String {
        if self.valid {
            "VerificationResult(valid=True)".to_string()
        } else if let Some(code) = &self.error_code {
            format!(
                "VerificationResult(valid=False, error={:?}, error_code={:?})",
                self.error.as_deref().unwrap_or("None"),
                code
            )
        } else {
            format!(
                "VerificationResult(valid=False, error={:?})",
                self.error.as_deref().unwrap_or("None")
            )
        }
    }

    fn __bool__(&self) -> bool {
        self.valid
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct VerificationStatus {
    #[pyo3(get)]
    pub status_type: String,
    #[pyo3(get)]
    pub at: Option<String>,
    #[pyo3(get)]
    pub step: Option<usize>,
    #[pyo3(get)]
    pub missing_link: Option<String>,
    #[pyo3(get)]
    pub required: Option<usize>,
    #[pyo3(get)]
    pub verified: Option<usize>,
}

#[pymethods]
impl VerificationStatus {
    fn __repr__(&self) -> String {
        format!("VerificationStatus(type='{}')", self.status_type)
    }

    fn is_valid(&self) -> bool {
        self.status_type == "Valid"
    }
}

impl From<RustVerificationStatus> for VerificationStatus {
    fn from(status: RustVerificationStatus) -> Self {
        match status {
            RustVerificationStatus::Valid => VerificationStatus {
                status_type: "Valid".to_string(),
                at: None,
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Expired { at } => VerificationStatus {
                status_type: "Expired".to_string(),
                at: Some(at.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Revoked { at } => VerificationStatus {
                status_type: "Revoked".to_string(),
                at: at.map(|t| t.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::InvalidSignature { step } => VerificationStatus {
                status_type: "InvalidSignature".to_string(),
                at: None,
                step: Some(step),
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::BrokenChain { missing_link } => VerificationStatus {
                status_type: "BrokenChain".to_string(),
                at: None,
                step: None,
                missing_link: Some(missing_link),
                required: None,
                verified: None,
            },
            RustVerificationStatus::InsufficientWitnesses { required, verified } => {
                VerificationStatus {
                    status_type: "InsufficientWitnesses".to_string(),
                    at: None,
                    step: None,
                    missing_link: None,
                    required: Some(required),
                    verified: Some(verified),
                }
            }
        }
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct ChainLink {
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl ChainLink {
    fn __repr__(&self) -> String {
        format!(
            "ChainLink(issuer='{}', subject='{}', valid={})",
            self.issuer, self.subject, self.valid
        )
    }
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

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct VerificationReport {
    #[pyo3(get)]
    pub status: VerificationStatus,
    #[pyo3(get)]
    pub chain: Vec<ChainLink>,
    #[pyo3(get)]
    pub warnings: Vec<String>,
}

#[pymethods]
impl VerificationReport {
    fn __repr__(&self) -> String {
        format!(
            "VerificationReport(status={}, chain_length={})",
            self.status.status_type,
            self.chain.len()
        )
    }

    fn is_valid(&self) -> bool {
        self.status.is_valid()
    }
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
