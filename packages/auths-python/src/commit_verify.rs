//! Python FFI bridge for native commit signature verification.

use auths_verifier::commit::verify_commit_signature;
use auths_verifier::commit_error::CommitVerificationError;
use auths_verifier::core::DevicePublicKey;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::runtime::runtime;

/// Result of native commit signature verification.
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyCommitVerificationResult {
    #[pyo3(get)]
    /// Whether the signature is valid.
    pub valid: bool,
    #[pyo3(get)]
    /// Hex-encoded signer public key (present on success).
    pub signer_hex: Option<String>,
    #[pyo3(get)]
    /// Error message (present on failure).
    pub error: Option<String>,
    #[pyo3(get)]
    /// Error code matching Python's ErrorCode values.
    pub error_code: Option<String>,
}

#[pymethods]
impl PyCommitVerificationResult {
    fn __repr__(&self) -> String {
        if self.valid {
            format!(
                "CommitVerificationResult(valid=True, signer='{}')",
                self.signer_hex.as_deref().unwrap_or("?")
            )
        } else {
            format!(
                "CommitVerificationResult(valid=False, error='{}', code='{}')",
                self.error.as_deref().unwrap_or("?"),
                self.error_code.as_deref().unwrap_or("?")
            )
        }
    }

    fn __bool__(&self) -> bool {
        self.valid
    }
}

fn error_to_code(err: &CommitVerificationError) -> &'static str {
    match err {
        CommitVerificationError::UnsignedCommit => "UNSIGNED",
        CommitVerificationError::GpgNotSupported => "GPG_NOT_SUPPORTED",
        CommitVerificationError::UnknownSigner => "UNKNOWN_SIGNER",
        CommitVerificationError::SignatureInvalid => "INVALID_SIGNATURE",
        CommitVerificationError::SshSigParseFailed(_) => "INVALID_SIGNATURE",
        CommitVerificationError::UnsupportedKeyType { .. } => "INVALID_SIGNATURE",
        CommitVerificationError::NamespaceMismatch { .. } => "INVALID_SIGNATURE",
        CommitVerificationError::HashAlgorithmUnsupported(_) => "INVALID_SIGNATURE",
        CommitVerificationError::CommitParseFailed(_) => "INVALID_SIGNATURE",
    }
}

/// Verify an SSH-signed git commit against allowed public keys.
///
/// Args:
/// * `commit_content`: Raw bytes from `git cat-file commit <sha>`.
/// * `allowed_keys_hex`: List of hex-encoded public keys (32 bytes Ed25519 or 33 bytes P-256).
///
/// Usage:
/// ```python
/// from auths._native import verify_commit_native
/// result = verify_commit_native(commit_bytes, ["aabbcc..."])
/// ```
#[pyfunction]
pub fn verify_commit_native(
    _py: Python<'_>,
    commit_content: &[u8],
    allowed_keys_hex: Vec<String>,
) -> PyResult<PyCommitVerificationResult> {
    let keys: Vec<DevicePublicKey> = allowed_keys_hex
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let (bytes, curve) = crate::types::validate_pk_hex(h)
                .map_err(|e| PyValueError::new_err(format!("invalid key at index {i}: {e}")))?;
            DevicePublicKey::try_new(curve, &bytes)
                .map_err(|e| PyValueError::new_err(format!("invalid public key at index {i}: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let content = commit_content.to_vec();
    {
        let provider = auths_crypto::RingCryptoProvider;
        let result = runtime().block_on(verify_commit_signature(&content, &keys, &provider, None));

        match result {
            Ok(verified) => Ok(PyCommitVerificationResult {
                valid: true,
                signer_hex: Some(hex::encode(verified.signer_key.as_bytes())),
                error: None,
                error_code: None,
            }),
            Err(err) => Ok(PyCommitVerificationResult {
                valid: false,
                signer_hex: None,
                error_code: Some(error_to_code(&err).to_string()),
                error: Some(err.to_string()),
            }),
        }
    }
}
