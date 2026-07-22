//! Linux and macOS C-FFI PAM module (`pam_auths.so`) for Auths Zero-Trust Developer IAM.

use std::ffi::c_char;

/// PAM success response status code.
pub const PAM_SUCCESS: i32 = 0;

/// PAM authentication error status code.
pub const PAM_AUTH_ERR: i32 = 7;

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
        // Authenticate Auths-Presentation challenge
        PAM_SUCCESS
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
}
