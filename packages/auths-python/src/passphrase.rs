use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// The minimum passphrase length the keychain enforces.
pub const PASSPHRASE_MIN_LEN: usize = 12;

/// Validate a keychain passphrase against the strength policy, up front.
///
/// The keychain requires at least 12 characters and at least 3 of 4 character
/// classes (lowercase, uppercase, digit, symbol). `create_agent`/`create` apply
/// the same rule at call time; this lets a caller fail fast instead of
/// discovering it by trial. Raises `ValueError` describing the shortfall when the
/// passphrase is too weak.
///
/// Args:
/// * `passphrase`: The passphrase to check.
///
/// Usage:
/// ```ignore
/// auths.validate_passphrase("Correct-Horse-Battery-9")
/// ```
#[pyfunction]
pub fn validate_passphrase(passphrase: &str) -> PyResult<()> {
    auths_core::crypto::encryption::validate_passphrase(passphrase)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}
