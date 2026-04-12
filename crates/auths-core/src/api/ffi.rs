//! FFI bindings to expose core functionality to other languages (Swift, Kotlin, C, etc.).
//!
//! Provides functions for key management (import, rotate, export), cryptographic
//! operations, and agent-based signing.
//!
//! # Safety
//! Functions returning pointers (`*mut c_char`, `*mut u8`) allocate memory
//! using `libc::malloc`. The caller is responsible for freeing this memory
//! using the corresponding `ffi_free_*` function (`ffi_free_str`, `ffi_free_bytes`).
//! Input C string pointers (`*const c_char`) must be valid, null-terminated UTF-8 strings.
//! Input byte pointers (`*const u8`/`*const c_uchar`) must be valid for the specified length.
//! Output length pointers (`*mut usize`) must be valid pointers.
//! Operations involving raw pointers or calling C functions are wrapped in `unsafe` blocks.

use crate::agent::AgentHandle;
use crate::api::runtime::{
    agent_sign_with_handle, export_key_openssh_pem, export_key_openssh_pub, rotate_key,
};
use crate::config::EnvironmentConfig;
use crate::config::{current_algorithm, set_encryption_algorithm};
use crate::crypto::EncryptionAlgorithm;
use crate::crypto::encryption::{decrypt_bytes, encrypt_bytes};
use crate::crypto::signer::extract_seed_from_key_bytes;
use crate::crypto::signer::{decrypt_keypair, encrypt_keypair};
use crate::error::AgentError;
use crate::storage::keychain::{
    IdentityDID, KeyAlias, KeyRole, KeyStorage, get_platform_keychain_with_config,
};
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::panic;
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::{Arc, LazyLock};

// --- FFI Error Codes ---

/// Successful operation
pub const FFI_OK: c_int = 0;
/// Invalid UTF-8 in C string input
pub const FFI_ERR_INVALID_UTF8: c_int = -1;
/// Agent not initialized (call ffi_init_agent first)
pub const FFI_ERR_AGENT_NOT_INITIALIZED: c_int = -2;
/// Internal panic occurred
pub const FFI_ERR_PANIC: c_int = -127;

// --- FFI Agent Handle ---

/// Global FFI agent handle.
///
/// This static holds the `AgentHandle` used by FFI functions. It must be initialized
/// by calling `ffi_init_agent()` before using functions like `ffi_agent_sign()`.
static FFI_AGENT: LazyLock<RwLock<Option<Arc<AgentHandle>>>> = LazyLock::new(|| RwLock::new(None));

/// Initializes the FFI agent with the specified socket path.
///
/// Must be called before using `ffi_agent_sign()` or other agent-related FFI functions.
///
/// # Safety
/// - `socket_path` must be null or point to a valid C string.
///
/// # Returns
/// - 0 on success
/// - 1 if the socket path is invalid
/// - FFI_ERR_PANIC (-127) if a panic occurred
#[unsafe(no_mangle)]
#[allow(clippy::disallowed_methods)] // INVARIANT: FFI boundary — home-dir fallback for default socket path
pub unsafe extern "C" fn ffi_init_agent(socket_path: *const c_char) -> c_int {
    let result = panic::catch_unwind(|| {
        let path_str = match unsafe { c_str_to_str_safe(socket_path) } {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                // Empty path - use default
                let home = match dirs::home_dir() {
                    Some(h) => h,
                    None => {
                        error!("FFI ffi_init_agent: Could not determine home directory");
                        return 1;
                    }
                };
                let default_path = home.join(".auths").join("agent.sock");
                let handle = Arc::new(AgentHandle::new(default_path));
                let mut guard = FFI_AGENT.write();
                *guard = Some(handle);
                info!("FFI agent initialized with default socket path");
                return 0;
            }
            Err(code) => return code,
        };

        let socket = PathBuf::from(path_str);
        let handle = Arc::new(AgentHandle::new(socket));

        let mut guard = FFI_AGENT.write();
        *guard = Some(handle);
        info!("FFI agent initialized with socket path: {}", path_str);
        0
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_init_agent: panic occurred");
        FFI_ERR_PANIC
    })
}

/// Shuts down the FFI agent, clearing all keys from memory.
///
/// After calling this, `ffi_agent_sign()` will return an error until
/// `ffi_init_agent()` is called again.
///
/// # Safety
/// This function is safe to call at any time.
///
/// # Returns
/// - 0 on success
/// - FFI_ERR_PANIC (-127) if a panic occurred
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_shutdown_agent() -> c_int {
    let result = panic::catch_unwind(|| {
        let mut guard = FFI_AGENT.write();
        if let Some(handle) = guard.take() {
            if let Err(e) = handle.shutdown() {
                warn!("FFI ffi_shutdown_agent: Shutdown returned error: {}", e);
            }
            info!("FFI agent shut down");
        } else {
            debug!("FFI ffi_shutdown_agent: Agent was not initialized");
        }
        0
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_shutdown_agent: panic occurred");
        FFI_ERR_PANIC
    })
}

/// Gets a clone of the FFI agent handle.
///
/// Returns `None` if the agent has not been initialized.
fn get_ffi_agent() -> Option<Arc<AgentHandle>> {
    FFI_AGENT.read().clone()
}

// --- Helper Functions ---

/// Safely converts a C string pointer to a Rust `&str`.
/// Returns `Ok("")` if the pointer is null.
/// Returns `Err(FFI_ERR_INVALID_UTF8)` if the C string is not valid UTF-8.
///
/// # Safety
/// The caller must ensure `ptr` is either null or points to a valid,
/// null-terminated C string with a lifetime that encompasses this function call.
pub unsafe fn c_str_to_str_safe<'a>(ptr: *const c_char) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        Ok("")
    } else {
        // Safety: Assumes ptr is valid C string per function contract.
        unsafe {
            CStr::from_ptr(ptr)
                .to_str()
                .map_err(|_| FFI_ERR_INVALID_UTF8)
        }
    }
}

/// Converts a C string pointer to a Rust `&str`.
/// Returns an empty string if the pointer is null.
/// Panics if the C string is not valid UTF-8.
///
/// # Safety
/// The caller must ensure `ptr` is either null or points to a valid,
/// null-terminated C string with a lifetime that encompasses this function call.
/// The function itself needs to be marked `unsafe` because `CStr::from_ptr` is unsafe.
///
/// # Deprecated
/// Use `c_str_to_str_safe` instead for panic-safe FFI code.
#[deprecated(note = "Use c_str_to_str_safe for panic-safe FFI")]
#[allow(clippy::expect_used)] // deprecated function — use c_str_to_str_safe instead
pub unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        ""
    } else {
        // Safety: Assumes ptr is valid C string per function contract.
        unsafe {
            CStr::from_ptr(ptr)
                .to_str()
                .expect("FFI string inputs must be valid UTF-8")
        }
    }
}

/// Converts a Rust `Result<T, E: Display>` to a C-style integer error code.
/// Logs the error on failure. Returns 0 on Ok, 1 on Err (general error).
/// Consider more specific error codes in the future.
///
/// # Safety
/// This function is marked unsafe for FFI compatibility but does not perform
/// any unsafe operations itself.
pub unsafe fn result_to_c_int<T, E: std::fmt::Display>(
    result: Result<T, E>,
    fn_name: &str,
) -> c_int {
    match result {
        Ok(_) => 0,
        Err(e) => {
            error!("FFI call {} failed: {}", fn_name, e);
            1 // General error code
        }
    }
}

/// Helper to allocate memory via malloc, copy Rust slice data into it,
/// set the out_len pointer, and return the raw pointer.
/// Returns null pointer on allocation failure.
///
/// # Safety
/// - `out_len` must be a valid pointer to `usize`.
/// - The caller must ensure the returned pointer (if not null) is eventually freed
///   using `ffi_free_bytes`.
/// - Operations involve raw pointers and calling `libc::malloc`, requiring `unsafe` block.
pub unsafe fn malloc_and_copy_bytes(data: &[u8], out_len: *mut usize) -> *mut u8 {
    // Safety: Operations require unsafe block.
    unsafe {
        if out_len.is_null() {
            error!("malloc_and_copy_bytes failed: out_len pointer is null.");
            return ptr::null_mut();
        }
        // Dereferencing out_len is unsafe
        *out_len = data.len();
        // Calling C function is unsafe
        let ptr = libc::malloc(data.len()) as *mut u8;
        if ptr.is_null() {
            error!(
                "malloc_and_copy_bytes failed: malloc returned null for size {}",
                data.len()
            );
            *out_len = 0; // Reset len on failure
            return ptr::null_mut();
        }
        // Pointer copy is unsafe
        ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        ptr
    }
}

/// Helper to convert a Rust String (or Zeroizing<String>) into a C string,
/// allocating memory via `CString::into_raw`.
/// Returns null pointer on allocation failure or if the string contains null bytes.
///
/// # Safety
/// - The caller must ensure the returned pointer (if not null) is eventually freed
///   using `ffi_free_str`.
/// - Calls `CString::into_raw` which transfers ownership.
fn malloc_and_copy_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(), // Transfers ownership, C caller must free
        Err(e) => {
            error!(
                "malloc_and_copy_string failed: CString creation error: {}",
                e
            );
            ptr::null_mut()
        }
    }
}

// --- FFI Functions ---

/// Checks if a key with the given alias exists in the secure storage.
///
/// # Safety
/// - `alias` must be null or point to a valid C string.
///
/// # Returns
/// - `true` if the key exists
/// - `false` if key doesn't exist, invalid input, or internal error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_key_exists(alias: *const c_char) -> bool {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(_) => return false,
        };
        if alias_str.is_empty() {
            return false;
        }
        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!("FFI ffi_key_exists: Failed to get platform keychain: {}", e);
                return false;
            }
        };
        let alias = KeyAlias::new_unchecked(alias_str);
        keychain.load_key(&alias).is_ok()
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_key_exists: panic occurred");
        false
    })
}

/// Imports a private key (provided as raw PKCS#8 bytes), encrypts it with the
/// given passphrase, and stores it in the secure storage under the specified
/// local alias, associated with the given controller DID.
///
/// # Safety
/// - `alias`, `controller_did`, `passphrase` must be valid C strings.
/// - `key_ptr` must point to valid PKCS#8 key data of `key_len` bytes for the duration of the call.
/// - `key_len` must be the correct length for the data pointed to by `key_ptr`.
///
/// # Returns
/// - 0 on success
/// - 1 if arguments are invalid
/// - 2 if key data is not valid PKCS#8
/// - 4 if encryption fails
/// - 5 if keychain initialization fails
/// - FFI_ERR_INVALID_UTF8 (-1) if C strings contain invalid UTF-8
/// - FFI_ERR_PANIC (-127) if a panic occurred
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_import_key(
    alias: *const c_char,    // Local keychain alias
    key_ptr: *const c_uchar, // Pointer to PKCS#8 bytes
    key_len: usize,
    controller_did: *const c_char, // Controller DID to associate
    passphrase: *const c_char,     // Passphrase to encrypt WITH
) -> c_int {
    let result = panic::catch_unwind(|| {
        // Safety: Calls unsafe helper and slice::from_raw_parts.
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let did_str = match unsafe { c_str_to_str_safe(controller_did) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let pass_str = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let key_data = unsafe { slice::from_raw_parts(key_ptr, key_len) };

        // Argument validation
        if alias_str.is_empty()
            || did_str.is_empty()
            || !did_str.starts_with("did:")
            || pass_str.is_empty()
        {
            error!(
                "FFI import failed: Invalid arguments (alias='{}', did='{}', passphrase empty={}).",
                alias_str,
                did_str,
                pass_str.is_empty()
            );
            return 1;
        }

        // Key data validation via seed extraction
        if let Err(e) = extract_seed_from_key_bytes(key_data) {
            error!(
                "FFI import failed: Provided key data is not valid Ed25519 for alias '{}': {}",
                alias_str, e
            );
            return 2;
        }

        // Encrypt
        let encrypt_result = encrypt_keypair(key_data, pass_str);
        let encrypted_key = match encrypt_result {
            Ok(enc) => enc,
            Err(e) => {
                error!(
                    "FFI import failed: Encryption error for alias '{}': {}",
                    alias_str, e
                );
                return 4; // Encryption error
            }
        };

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: validated with starts_with("did:") guard above
        let did_string = IdentityDID::new_unchecked(did_str.to_string());
        let alias = KeyAlias::new_unchecked(alias_str);

        // Store
        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!("FFI import failed: Failed to get platform keychain: {}", e);
                return 5; // Keychain initialization error
            }
        };
        let store_result =
            keychain.store_key(&alias, &did_string, KeyRole::Primary, &encrypted_key);

        #[allow(deprecated)]
        unsafe {
            result_to_c_int(store_result, "ffi_import_key")
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_import_key: panic occurred");
        FFI_ERR_PANIC
    })
}

/// Rotates the keypair for a given local alias.
/// Generates a new key, encrypts it with the *new* passphrase, and replaces the
/// existing key in secure storage, keeping the association with the original Controller DID.
///
/// # Safety
/// - `alias`, `new_passphrase` must be valid C strings.
///
/// # Returns
/// - 0 on success.
/// - 1 if arguments are invalid.
/// - 2 if the original key/alias is not found.
/// - 3 if crypto operations fail.
/// - 4 if secure storage or other errors occur.
/// - FFI_ERR_INVALID_UTF8 (-1) if C strings contain invalid UTF-8
/// - FFI_ERR_PANIC (-127) if a panic occurred
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_rotate_key(
    alias: *const c_char,
    new_passphrase: *const c_char,
) -> c_int {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let pass_str = match unsafe { c_str_to_str_safe(new_passphrase) } {
            Ok(s) => s,
            Err(code) => return code,
        };

        // Delegate to the runtime API function
        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!("FFI rotate_key: Failed to get platform keychain: {}", e);
                return 5; // Keychain initialization error
            }
        };
        let rotate_result = rotate_key(alias_str, pass_str, keychain.as_ref());

        // Map AgentError to FFI return codes
        match rotate_result {
            Ok(()) => 0,
            Err(e) => {
                error!("FFI rotate_key failed for alias '{}': {}", alias_str, e);
                match e {
                    AgentError::InvalidInput(_) => 1,
                    AgentError::KeyNotFound => 2,
                    AgentError::CryptoError(_) | AgentError::KeyDeserializationError(_) => 3,
                    _ => 4, // Storage, Mutex, etc.
                }
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_rotate_key: panic occurred");
        FFI_ERR_PANIC
    })
}

/// Exports the raw *encrypted* private key bytes associated with the alias.
/// This function does *not* require a passphrase.
///
/// # Safety
/// - `alias` must be a valid C string.
/// - `out_len` must be a valid pointer to `usize`.
/// - The returned pointer (if not null) must be freed by the caller using `ffi_free_bytes`.
///
/// # Returns
/// - Non-null pointer to encrypted key bytes on success
/// - NULL on error (invalid input, key not found, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_export_encrypted_key(
    alias: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        if alias_str.is_empty() || out_len.is_null() {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            return ptr::null_mut();
        }
        unsafe { *out_len = 0 };

        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!(
                    "FFI export encrypted key: Failed to get platform keychain: {}",
                    e
                );
                return ptr::null_mut();
            }
        };
        let alias = KeyAlias::new_unchecked(alias_str);
        match keychain.load_key(&alias) {
            Ok((_identity_did, _role, encrypted_data)) => {
                debug!(
                    "FFI export encrypted key successful for alias '{}'",
                    alias_str
                );
                unsafe { malloc_and_copy_bytes(&encrypted_data, out_len) }
            }
            Err(e) => {
                error!(
                    "FFI export encrypted key failed for alias '{}': {}",
                    alias_str, e
                );
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_export_encrypted_key: panic occurred");
        ptr::null_mut()
    })
}

/// Verifies a passphrase against the stored encrypted key for the given alias.
/// If the passphrase is correct, returns a copy of the *encrypted* key data.
///
/// # Safety
/// - `alias`, `passphrase` must be valid C strings.
/// - `out_len` must be a valid pointer to `usize`.
/// - The returned pointer (if not null) must be freed by the caller using `ffi_free_bytes`.
///
/// # Returns
/// - Non-null pointer to encrypted key bytes on success
/// - NULL on error (invalid input, incorrect passphrase, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_export_private_key_with_passphrase(
    alias: *const c_char,
    passphrase: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let pass_str = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        if alias_str.is_empty() || out_len.is_null() {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            return ptr::null_mut();
        }
        unsafe { *out_len = 0 };

        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!(
                    "FFI export_private_key_with_passphrase: Failed to get platform keychain: {}",
                    e
                );
                return ptr::null_mut();
            }
        };
        let alias = KeyAlias::new_unchecked(alias_str);
        let export_result = || -> Result<Vec<u8>, AgentError> {
            if keychain.is_hardware_backend() {
                return Err(AgentError::BackendUnavailable {
                    backend: keychain.backend_name(),
                    reason: "hardware-backed keys (e.g. Secure Enclave) cannot be exported via this FFI path".to_string(),
                });
            }
            let (_controller_did, _role, encrypted_bytes) = keychain.load_key(&alias)?;
            // Attempt decryption only to verify passphrase
            let _decrypted_pkcs8 = decrypt_keypair(&encrypted_bytes, pass_str)?;
            debug!(
                "FFI export_private_key_with_passphrase: Passphrase verified for alias '{}'",
                alias_str
            );
            Ok(encrypted_bytes)
        }();

        match export_result {
            Ok(encrypted_data) => unsafe { malloc_and_copy_bytes(&encrypted_data, out_len) },
            Err(e) => {
                if !matches!(e, AgentError::IncorrectPassphrase) {
                    error!(
                        "FFI export_private_key_with_passphrase failed for alias '{}': {}",
                        alias_str, e
                    );
                } else {
                    debug!(
                        "FFI export_private_key_with_passphrase: Incorrect passphrase for alias '{}'",
                        alias_str
                    );
                }
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_export_private_key_with_passphrase: panic occurred");
        ptr::null_mut()
    })
}

/// Exports the decrypted private key in OpenSSH PEM format.
/// Requires the correct passphrase to decrypt the key.
///
/// # Safety
/// - `alias`, `passphrase` must be valid C strings.
/// - The returned pointer (if not null) must be freed by the caller using `ffi_free_str`.
///
/// # Returns
/// - Non-null pointer to PEM string on success
/// - NULL on error (invalid input, incorrect passphrase, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_export_private_key_openssh(
    alias: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let pass_str = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        if alias_str.is_empty() {
            return ptr::null_mut();
        }

        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!("FFI export PEM: Failed to get platform keychain: {}", e);
                return ptr::null_mut();
            }
        };
        match export_key_openssh_pem(alias_str, pass_str, keychain.as_ref()) {
            Ok(pem_zeroizing) => malloc_and_copy_string(pem_zeroizing.as_str()),
            Err(e) => {
                error!("FFI export PEM failed for alias '{}': {}", alias_str, e);
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_export_private_key_openssh: panic occurred");
        ptr::null_mut()
    })
}

/// Exports the public key in OpenSSH `.pub` format.
/// Requires the correct passphrase to decrypt the associated private key first.
///
/// # Safety
/// - `alias`, `passphrase` must be valid C strings.
/// - The returned pointer (if not null) must be freed by the caller using `ffi_free_str`.
///
/// # Returns
/// - Non-null pointer to public key string on success
/// - NULL on error (invalid input, incorrect passphrase, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_export_public_key_openssh(
    alias: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let alias_str = match unsafe { c_str_to_str_safe(alias) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let pass_str = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        if alias_str.is_empty() {
            return ptr::null_mut();
        }

        // TODO: Refactor FFI to accept configuration context
        let keychain = match get_platform_keychain_with_config(&EnvironmentConfig::from_env()) {
            Ok(kc) => kc,
            Err(e) => {
                error!(
                    "FFI export OpenSSH pubkey: Failed to get platform keychain: {}",
                    e
                );
                return ptr::null_mut();
            }
        };
        match export_key_openssh_pub(alias_str, pass_str, keychain.as_ref()) {
            Ok(formatted_pubkey) => malloc_and_copy_string(&formatted_pubkey),
            Err(e) => {
                error!(
                    "FFI export OpenSSH pubkey failed for alias '{}': {}",
                    alias_str, e
                );
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_export_public_key_openssh: panic occurred");
        ptr::null_mut()
    })
}

/// Signs a message using a key loaded into the FFI agent.
///
/// **Important:** `ffi_init_agent()` must be called before using this function.
///
/// # Safety
/// - `pubkey_ptr` must point to valid public key bytes of `pubkey_len` bytes.
/// - `data_ptr` must point to valid data bytes of `data_len` bytes.
/// - `out_len` must be a valid pointer to `usize`.
/// - The returned pointer (if not null) must be freed by the caller using `ffi_free_bytes`.
///
/// # Returns
/// - Non-null pointer to signature bytes on success
/// - NULL on error (agent not initialized, invalid input, key not found, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_agent_sign(
    pubkey_ptr: *const c_uchar,
    pubkey_len: usize,
    data_ptr: *const c_uchar,
    data_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let result = panic::catch_unwind(|| {
        if pubkey_ptr.is_null() || data_ptr.is_null() || out_len.is_null() {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            error!("FFI agent_sign failed: Null pointer argument.");
            return ptr::null_mut();
        }

        // Get the FFI agent handle
        let handle = match get_ffi_agent() {
            Some(h) => h,
            None => {
                error!(
                    "FFI agent_sign failed: Agent not initialized. Call ffi_init_agent() first."
                );
                unsafe { *out_len = 0 };
                return ptr::null_mut();
            }
        };

        let pubkey_slice = unsafe { slice::from_raw_parts(pubkey_ptr, pubkey_len) };
        let data_slice = unsafe { slice::from_raw_parts(data_ptr, data_len) };
        unsafe { *out_len = 0 };

        match agent_sign_with_handle(&handle, pubkey_slice, data_slice) {
            Ok(signature_bytes) => unsafe { malloc_and_copy_bytes(&signature_bytes, out_len) },
            Err(e) => {
                error!("FFI agent_sign failed: {}", e);
                if matches!(e, AgentError::KeyNotFound) {
                    warn!(
                        "FFI agent_sign: Key not found in agent for pubkey prefix {:x?}",
                        &pubkey_slice[..std::cmp::min(pubkey_slice.len(), 8)]
                    );
                }
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_agent_sign: panic occurred");
        ptr::null_mut()
    })
}

// --- General Crypto & Config FFI Functions ---

/// Encrypts data using the given passphrase.
///
/// # Safety
/// - `passphrase` must be a valid null-terminated C string
/// - `input_ptr` must point to valid memory of at least `input_len` bytes
/// - `out_len` must be a valid pointer to write the output length
///
/// # Returns
/// - Non-null pointer to encrypted bytes on success
/// - NULL on error (invalid input or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_encrypt_data(
    passphrase: *const c_char,
    input_ptr: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let result = panic::catch_unwind(|| {
        if input_ptr.is_null() || out_len.is_null() {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            error!("FFI encrypt_data failed: Null pointer argument.");
            return ptr::null_mut();
        }
        let pass = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
        unsafe { *out_len = 0 };
        let algo = current_algorithm();

        match encrypt_bytes(input, pass, algo) {
            Ok(encrypted) => unsafe { malloc_and_copy_bytes(&encrypted, out_len) },
            Err(e) => {
                error!("FFI encrypt_data failed: {}", e);
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_encrypt_data: panic occurred");
        ptr::null_mut()
    })
}

/// Decrypts data using the given passphrase.
///
/// # Safety
/// - `passphrase` must be a valid null-terminated C string
/// - `input_ptr` must point to valid memory of at least `input_len` bytes
/// - `out_len` must be a valid pointer to write the output length
///
/// # Returns
/// - Non-null pointer to decrypted bytes on success
/// - NULL on error (invalid input, incorrect passphrase, or panic)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_decrypt_data(
    passphrase: *const c_char,
    input_ptr: *const u8,
    input_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let result = panic::catch_unwind(|| {
        if input_ptr.is_null() || out_len.is_null() {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            error!("FFI decrypt_data failed: Null pointer argument.");
            return ptr::null_mut();
        }
        let pass = match unsafe { c_str_to_str_safe(passphrase) } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
        unsafe { *out_len = 0 };

        match decrypt_bytes(input, pass) {
            Ok(decrypted) => unsafe { malloc_and_copy_bytes(&decrypted, out_len) },
            Err(e) => {
                if !matches!(e, AgentError::IncorrectPassphrase) {
                    error!("FFI decrypt_data failed: {}", e);
                } else {
                    debug!("FFI decrypt_data: Incorrect passphrase provided.");
                }
                ptr::null_mut()
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_decrypt_data: panic occurred");
        ptr::null_mut()
    })
}

/// Frees a C string (`char *`) previously returned by an FFI function
/// in this library (which allocated it using `CString::into_raw`).
/// Does nothing if `ptr` is null.
///
/// # Safety
/// - `ptr` must be null or must have been previously allocated by a function
///   in this library that returns `*mut c_char` (eg, `ffi_export_..._openssh`).
/// - `ptr` must not be used after calling this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_free_str(ptr: *mut c_char) {
    let _ = panic::catch_unwind(|| {
        if !ptr.is_null() {
            // Safety: We are reclaiming ownership of the pointer originally transferred
            // via CString::into_raw and letting the CString drop, which frees the memory.
            let _ = unsafe { CString::from_raw(ptr) };
        }
    });
    // Note: If panic occurs during free, we just swallow it to avoid UB from unwinding across FFI
}

/// Frees a byte buffer (`unsigned char *` / `uint8_t *`) previously returned
/// by an FFI function in this library (which allocated it using `libc::malloc`).
/// Does nothing if `ptr` is null. The `len` argument is ignored but kept for
/// potential C-side compatibility if callers expect it.
///
/// # Safety
/// - `ptr` must be null or must have been previously allocated by a function
///   in this library that returns `*mut u8` (eg, `ffi_agent_sign`, `ffi_export_encrypted_key`).
/// - `ptr` must not be used after calling this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_free_bytes(ptr: *mut u8, _len: usize) {
    let _ = panic::catch_unwind(|| {
        if !ptr.is_null() {
            unsafe { libc::free(ptr as *mut libc::c_void) };
        }
    });
    // Note: If panic occurs during free, we just swallow it to avoid UB from unwinding across FFI
}

/// Sets the global encryption algorithm level used by `encrypt_keypair`.
/// (1 = AES-GCM-256, 2 = ChaCha20Poly1305). Defaults to AES if level is unknown.
///
/// # Safety
/// This function modifies global state. It should not be called concurrently
/// from multiple threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_set_encryption_algorithm(level: c_int) {
    let _ = panic::catch_unwind(|| {
        let algo = match level {
            1 => EncryptionAlgorithm::AesGcm256,
            2 => EncryptionAlgorithm::ChaCha20Poly1305,
            _ => {
                warn!(
                    "FFI: Unknown encryption level {}, defaulting to AES-GCM.",
                    level
                );
                EncryptionAlgorithm::AesGcm256
            }
        };
        info!("FFI: Setting global encryption algorithm to {:?}", algo);
        set_encryption_algorithm(algo);
    });
    // Note: If panic occurs, we just swallow it to avoid UB from unwinding across FFI
}

// --- Deprecated / Removed Functions ---

// `ffi_init_identity` removed - requires more complex setup (metadata file) now.
// `ffi_start_agent` removed - agent startup is separate from key loading now.
// `ffi_get_public_key` removed - use `ffi_export_public_key_openssh`.
// `ffi_sign_ssh_agent_request` removed - use `ffi_agent_sign`.
// `ffi_sign_ssh_agent_request_with_passphrase` removed - use `ffi_agent_sign`.
// Internal `sign_ssh_agent_request` removed.
