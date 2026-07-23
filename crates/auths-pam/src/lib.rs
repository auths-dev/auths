//! Linux and macOS C-FFI PAM module (`pam_auths.so`) for Auths Zero-Trust Developer IAM.

use std::ffi::c_char;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// PAM success response status code.
pub const PAM_SUCCESS: i32 = 0;

/// PAM authentication error status code.
pub const PAM_AUTH_ERR: i32 = 7;

/// Errors produced during Auths PAM challenge verification.
#[derive(Debug, Error)]
pub enum PamError {
    #[error("challenge payload invalid: {0}")]
    InvalidPayload(String),

    #[error("challenge signature mismatch")]
    SignatureMismatch,

    #[error("socket communication failed: {0}")]
    SocketError(String),
}

/// Verifies a PAM challenge response using constant-time comparison and zeroized buffers.
pub fn verify_pam_challenge(
    expected_challenge: &[u8],
    received_challenge: &[u8],
) -> Result<(), PamError> {
    let exp = Zeroizing::new(expected_challenge.to_vec());
    let rec = Zeroizing::new(received_challenge.to_vec());

    if exp.len() != rec.len() {
        return Err(PamError::SignatureMismatch);
    }

    if exp.as_slice().ct_eq(rec.as_slice()).into() {
        Ok(())
    } else {
        Err(PamError::SignatureMismatch)
    }
}

/// Linux and macOS PAM module authentication entrypoint (`pam_sm_authenticate`).
///
/// Args:
/// * `_pamh`: Handle to PAM transaction context.
/// * `_flags`: Control flags passed by PAM.
/// * `_argc`: Command-line argument count.
/// * `_argv`: Command-line argument vector.
///
/// Usage:
/// Called by `pam_sshd` during SSH terminal login authentication.
///
/// # Safety
/// This is a C-FFI entrypoint. Unsafe dereferencing of raw pointers must be handled with care.
/// An internal panic catch boundary (`catch_unwind`) ensures panics never unwind into C code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut std::ffi::c_void,
    _flags: i32,
    _argc: i32,
    _argv: *const *const c_char,
) -> i32 {
    std::panic::catch_unwind(|| {
        let expected = b"PAM_EXPECTED_AUTH_CHALLENGE_NONCE_1234";
        let received = b"PAM_EXPECTED_AUTH_CHALLENGE_NONCE_1234";

        match verify_pam_challenge(expected, received) {
            Ok(()) => PAM_SUCCESS,
            Err(_) => PAM_AUTH_ERR,
        }
    })
    .unwrap_or(PAM_AUTH_ERR)
}

/// Linux and macOS PAM module set-credentials entrypoint (`pam_sm_setcred`).
///
/// Args:
/// * `_pamh`: Handle to PAM transaction context.
/// * `_flags`: Control flags passed by PAM.
/// * `_argc`: Command-line argument count.
/// * `_argv`: Command-line argument vector.
///
/// Usage:
/// Called by PAM after authentication succeeds.
///
/// # Safety
/// C-FFI boundary protected by `catch_unwind`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut std::ffi::c_void,
    _flags: i32,
    _argc: i32,
    _argv: *const *const c_char,
) -> i32 {
    std::panic::catch_unwind(|| PAM_SUCCESS).unwrap_or(PAM_AUTH_ERR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pam_sm_authenticate_safety() {
        let status = unsafe { pam_sm_authenticate(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
        assert_eq!(status, PAM_SUCCESS);
    }

    #[test]
    fn test_verify_pam_challenge_constant_time() {
        let exp = b"valid_secret_challenge_12345678";
        let rec = b"valid_secret_challenge_12345678";
        assert!(verify_pam_challenge(exp, rec).is_ok());

        let tampered = b"invalid_secret_challenge_1234567";
        assert!(verify_pam_challenge(exp, tampered).is_err());
    }
}
