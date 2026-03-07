use crate::core::{Attestation, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE};
use crate::error::{AttestationError, AuthsErrorInfo};
use crate::types::DeviceDID;
use crate::verifier::Verifier;
use crate::witness::{WitnessReceipt, WitnessVerifyConfig};
use auths_crypto::ED25519_PUBLIC_KEY_LEN;
use log::error;
use std::os::raw::c_int;
use std::panic;
use std::slice;

// INVARIANT: Tokio runtime creation is fatal at FFI boundary; cannot propagate Result across FFI
#[allow(clippy::expect_used)]
fn with_runtime<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("FFI: failed to create tokio runtime")
        .block_on(f)
}

/// Verification succeeded.
pub const VERIFY_SUCCESS: c_int = 0;
/// A required pointer argument was null.
pub const ERR_VERIFY_NULL_ARGUMENT: c_int = -1;
/// JSON deserialization failed.
pub const ERR_VERIFY_JSON_PARSE: c_int = -2;
/// Public key length was not 32 bytes.
pub const ERR_VERIFY_INVALID_PK_LEN: c_int = -3;
/// Issuer signature verification failed.
pub const ERR_VERIFY_ISSUER_SIG_FAIL: c_int = -4;
/// Device signature verification failed.
pub const ERR_VERIFY_DEVICE_SIG_FAIL: c_int = -5;
/// Attestation has expired.
pub const ERR_VERIFY_EXPIRED: c_int = -6;
/// Attestation has been revoked.
pub const ERR_VERIFY_REVOKED: c_int = -7;
/// Report serialization or output buffer error.
pub const ERR_VERIFY_SERIALIZATION: c_int = -8;
/// Witness quorum not met.
pub const ERR_VERIFY_INSUFFICIENT_WITNESSES: c_int = -9;
/// Witness receipt or key JSON parse error.
pub const ERR_VERIFY_WITNESS_PARSE: c_int = -10;
/// Input JSON exceeded size limit.
pub const ERR_VERIFY_INPUT_TOO_LARGE: c_int = -11;
/// Attestation timestamp is in the future (clock skew).
pub const ERR_VERIFY_FUTURE_TIMESTAMP: c_int = -12;
/// Unclassified verification error.
pub const ERR_VERIFY_OTHER: c_int = -99;
/// Internal panic occurred
pub const ERR_VERIFY_PANIC: c_int = -127;

fn attestation_error_to_code(e: &AttestationError) -> c_int {
    match e.error_code() {
        "AUTHS_ISSUER_SIG_FAILED" => ERR_VERIFY_ISSUER_SIG_FAIL,
        "AUTHS_DEVICE_SIG_FAILED" => ERR_VERIFY_DEVICE_SIG_FAIL,
        "AUTHS_ATTESTATION_EXPIRED" => ERR_VERIFY_EXPIRED,
        "AUTHS_ATTESTATION_REVOKED" => ERR_VERIFY_REVOKED,
        "AUTHS_TIMESTAMP_IN_FUTURE" => ERR_VERIFY_FUTURE_TIMESTAMP,
        "AUTHS_SERIALIZATION_ERROR" => ERR_VERIFY_SERIALIZATION,
        "AUTHS_INVALID_INPUT" => ERR_VERIFY_INVALID_PK_LEN,
        "AUTHS_INPUT_TOO_LARGE" => ERR_VERIFY_INPUT_TOO_LARGE,
        "AUTHS_BUNDLE_EXPIRED" => ERR_VERIFY_EXPIRED,
        _ => ERR_VERIFY_OTHER,
    }
}

fn check_batch_sizes(sizes: &[usize], caller: &str) -> Option<c_int> {
    for &size in sizes {
        if size > MAX_JSON_BATCH_SIZE {
            error!("FFI {}: JSON too large ({} bytes)", caller, size);
            return Some(ERR_VERIFY_INPUT_TOO_LARGE);
        }
    }
    None
}

#[derive(serde::Deserialize)]
struct WitnessKeyEntry {
    did: String,
    pk_hex: String,
}

type WitnessKeys = Vec<(String, Vec<u8>)>;

fn parse_witness_inputs(
    receipts_json: &[u8],
    witness_keys_json: &[u8],
) -> Result<(Vec<WitnessReceipt>, WitnessKeys), c_int> {
    let receipts: Vec<WitnessReceipt> = serde_json::from_slice(receipts_json).map_err(|e| {
        error!("FFI: receipts JSON parse error: {}", e);
        ERR_VERIFY_WITNESS_PARSE
    })?;

    let key_entries: Vec<WitnessKeyEntry> =
        serde_json::from_slice(witness_keys_json).map_err(|e| {
            error!("FFI: witness keys JSON parse error: {}", e);
            ERR_VERIFY_WITNESS_PARSE
        })?;

    let witness_keys: Vec<(String, Vec<u8>)> = key_entries
        .into_iter()
        .map(|e| {
            hex::decode(&e.pk_hex)
                .map(|pk| (e.did, pk))
                .map_err(|err| err.to_string())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!("FFI: witness key hex decode error: {}", e);
            ERR_VERIFY_WITNESS_PARSE
        })?;

    Ok((receipts, witness_keys))
}

/// Serialize a report and write it into the caller-provided output buffer.
///
/// # Safety
/// `result_ptr` must point to a buffer of at least `*result_len` bytes.
unsafe fn write_report_to_buffer(
    report: &impl serde::Serialize,
    result_ptr: *mut u8,
    result_len: *mut usize,
    caller: &str,
) -> c_int {
    let report_json = match serde_json::to_vec(report) {
        Ok(j) => j,
        Err(e) => {
            error!("FFI {}: serialization error: {}", caller, e);
            return ERR_VERIFY_SERIALIZATION;
        }
    };

    let max_len = unsafe { *result_len };
    if report_json.len() > max_len {
        error!("FFI {}: output buffer too small", caller);
        return ERR_VERIFY_SERIALIZATION;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(report_json.as_ptr(), result_ptr, report_json.len());
        *result_len = report_json.len();
    }

    VERIFY_SUCCESS
}

/// Verifies an attestation provided as JSON bytes against an explicit issuer public key.
///
/// # Arguments
/// * `attestation_json_ptr` - Pointer to the byte array containing the Attestation JSON data.
/// * `attestation_json_len` - Length of the Attestation JSON byte array.
/// * `issuer_pk_ptr` - Pointer to the byte array containing the raw 32-byte Ed25519 issuer public key.
/// * `issuer_pk_len` - Length of the issuer public key byte array (must be 32).
///
/// # Returns
/// * `0` (VERIFY_SUCCESS) on successful verification.
/// * Negative error code on failure (see ERR_VERIFY_* constants).
/// * ERR_VERIFY_PANIC (-127) if a panic occurred.
///
/// # Safety
/// * Callers must ensure that `attestation_json_ptr` points to valid memory containing `attestation_json_len` bytes.
/// * Callers must ensure that `issuer_pk_ptr` points to valid memory containing `issuer_pk_len` bytes.
/// * Pointers must be valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_verify_attestation_json(
    attestation_json_ptr: *const u8,
    attestation_json_len: usize,
    issuer_pk_ptr: *const u8,
    issuer_pk_len: usize,
) -> c_int {
    let result = panic::catch_unwind(|| {
        // --- Input Validation ---
        if attestation_json_ptr.is_null() || issuer_pk_ptr.is_null() {
            error!("FFI verify failed: Received null pointer argument.");
            return ERR_VERIFY_NULL_ARGUMENT;
        }
        // Check issuer public key length immediately
        if issuer_pk_len != ED25519_PUBLIC_KEY_LEN {
            error!(
                "FFI verify failed: Issuer PK length must be {}, got {}",
                ED25519_PUBLIC_KEY_LEN, issuer_pk_len
            );
            return ERR_VERIFY_INVALID_PK_LEN;
        }

        // --- Size check ---
        if attestation_json_len > MAX_ATTESTATION_JSON_SIZE {
            error!(
                "FFI verify failed: input too large ({} bytes, max {})",
                attestation_json_len, MAX_ATTESTATION_JSON_SIZE
            );
            return ERR_VERIFY_INPUT_TOO_LARGE;
        }

        // --- Create Slices ---
        // Safety: Pointers are checked for null; lengths are provided by caller.
        // Lifetimes are valid only within this function call.
        let attestation_json_slice =
            unsafe { slice::from_raw_parts(attestation_json_ptr, attestation_json_len) };
        let issuer_pk_slice = unsafe { slice::from_raw_parts(issuer_pk_ptr, issuer_pk_len) };

        // --- Deserialize Attestation ---
        let att: Attestation = match serde_json::from_slice(attestation_json_slice) {
            Ok(a) => a,
            Err(e) => {
                error!("FFI verify failed: JSON deserialization error: {}", e);
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        // --- Call Core Verification Logic ---
        let verifier = Verifier::native();
        match with_runtime(verifier.verify_with_keys(&att, issuer_pk_slice)) {
            Ok(_) => VERIFY_SUCCESS,
            Err(e) => {
                error!("FFI verify failed: Verification logic error: {}", e);
                attestation_error_to_code(&e)
            }
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_verify_attestation_json: panic occurred");
        ERR_VERIFY_PANIC
    })
}

/// Verifies a chain of attestations with witness quorum checking via FFI.
///
/// # Arguments
/// * `chain_json_ptr` / `chain_json_len` - JSON array of attestations
/// * `root_pk_ptr` / `root_pk_len` - 32-byte Ed25519 root public key
/// * `receipts_json_ptr` / `receipts_json_len` - JSON array of WitnessReceipt objects
/// * `witness_keys_json_ptr` / `witness_keys_json_len` - JSON array of `{"did": "...", "pk_hex": "..."}`
/// * `threshold` - Minimum number of valid witness receipts required
/// * `result_ptr` / `result_len` - Output buffer for JSON VerificationReport
///
/// # Returns
/// * `0` (VERIFY_SUCCESS) on success (report written to result_ptr)
/// * Negative error code on failure
///
/// # Safety
/// All pointers must be valid for the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_verify_chain_with_witnesses(
    chain_json_ptr: *const u8,
    chain_json_len: usize,
    root_pk_ptr: *const u8,
    root_pk_len: usize,
    receipts_json_ptr: *const u8,
    receipts_json_len: usize,
    witness_keys_json_ptr: *const u8,
    witness_keys_json_len: usize,
    threshold: u32,
    result_ptr: *mut u8,
    result_len: *mut usize,
) -> c_int {
    let result = panic::catch_unwind(|| {
        if chain_json_ptr.is_null()
            || root_pk_ptr.is_null()
            || receipts_json_ptr.is_null()
            || witness_keys_json_ptr.is_null()
            || result_ptr.is_null()
            || result_len.is_null()
        {
            error!("FFI verify_chain_with_witnesses: null pointer argument");
            return ERR_VERIFY_NULL_ARGUMENT;
        }

        if root_pk_len != ED25519_PUBLIC_KEY_LEN {
            error!("FFI verify_chain_with_witnesses: invalid root PK length");
            return ERR_VERIFY_INVALID_PK_LEN;
        }

        if let Some(code) = check_batch_sizes(
            &[chain_json_len, receipts_json_len, witness_keys_json_len],
            "verify_chain_with_witnesses",
        ) {
            return code;
        }

        let chain_json = unsafe { slice::from_raw_parts(chain_json_ptr, chain_json_len) };
        let root_pk = unsafe { slice::from_raw_parts(root_pk_ptr, root_pk_len) };
        let receipts_json = unsafe { slice::from_raw_parts(receipts_json_ptr, receipts_json_len) };
        let witness_keys_json =
            unsafe { slice::from_raw_parts(witness_keys_json_ptr, witness_keys_json_len) };

        let attestations: Vec<Attestation> = match serde_json::from_slice(chain_json) {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "FFI verify_chain_with_witnesses: chain JSON parse error: {}",
                    e
                );
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        let (receipts, witness_keys) = match parse_witness_inputs(receipts_json, witness_keys_json)
        {
            Ok(pair) => pair,
            Err(code) => return code,
        };

        let config = WitnessVerifyConfig {
            receipts: &receipts,
            witness_keys: &witness_keys,
            threshold: threshold as usize,
        };

        let verifier = Verifier::native();
        let report = match with_runtime(verifier.verify_chain_with_witnesses(
            &attestations,
            root_pk,
            &config,
        )) {
            Ok(r) => r,
            Err(e) => {
                error!("FFI verify_chain_with_witnesses: verification error: {}", e);
                return attestation_error_to_code(&e);
            }
        };

        unsafe {
            write_report_to_buffer(
                &report,
                result_ptr,
                result_len,
                "verify_chain_with_witnesses",
            )
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_verify_chain_with_witnesses: panic occurred");
        ERR_VERIFY_PANIC
    })
}

/// Verifies a chain of attestations via FFI (without witness quorum).
///
/// # Arguments
/// * `chain_json_ptr` / `chain_json_len` - JSON array of attestations
/// * `root_pk_ptr` / `root_pk_len` - 32-byte Ed25519 root public key
/// * `result_ptr` / `result_len` - Output buffer for JSON VerificationReport.
///   On entry, `*result_len` must hold the buffer capacity.
///   On success, `*result_len` is set to the bytes written.
///
/// # Returns
/// * `0` (VERIFY_SUCCESS) on success (report written to result_ptr)
/// * Negative error code on failure
///
/// # Safety
/// All pointers must be valid for the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_verify_chain_json(
    chain_json_ptr: *const u8,
    chain_json_len: usize,
    root_pk_ptr: *const u8,
    root_pk_len: usize,
    result_ptr: *mut u8,
    result_len: *mut usize,
) -> c_int {
    let result = panic::catch_unwind(|| {
        if chain_json_ptr.is_null()
            || root_pk_ptr.is_null()
            || result_ptr.is_null()
            || result_len.is_null()
        {
            error!("FFI verify_chain_json: null pointer argument");
            return ERR_VERIFY_NULL_ARGUMENT;
        }

        if root_pk_len != ED25519_PUBLIC_KEY_LEN {
            error!("FFI verify_chain_json: invalid root PK length");
            return ERR_VERIFY_INVALID_PK_LEN;
        }

        if chain_json_len > MAX_JSON_BATCH_SIZE {
            error!(
                "FFI verify_chain_json: chain JSON too large ({} bytes)",
                chain_json_len
            );
            return ERR_VERIFY_INPUT_TOO_LARGE;
        }

        let chain_json = unsafe { slice::from_raw_parts(chain_json_ptr, chain_json_len) };
        let root_pk = unsafe { slice::from_raw_parts(root_pk_ptr, root_pk_len) };

        let attestations: Vec<Attestation> = match serde_json::from_slice(chain_json) {
            Ok(a) => a,
            Err(e) => {
                error!("FFI verify_chain_json: chain JSON parse error: {}", e);
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        let verifier = Verifier::native();
        let report = match with_runtime(verifier.verify_chain(&attestations, root_pk)) {
            Ok(r) => r,
            Err(e) => {
                error!("FFI verify_chain_json: verification error: {}", e);
                return attestation_error_to_code(&e);
            }
        };

        unsafe { write_report_to_buffer(&report, result_ptr, result_len, "verify_chain_json") }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_verify_chain_json: panic occurred");
        ERR_VERIFY_PANIC
    })
}

/// Verifies that a device is authorized by a specific identity via FFI.
///
/// Checks if there is a valid attestation chain from the identity to the device.
///
/// # Arguments
/// * `identity_did_ptr` / `identity_did_len` - UTF-8 identity DID string
/// * `device_did_ptr` / `device_did_len` - UTF-8 device DID string
/// * `chain_json_ptr` / `chain_json_len` - JSON array of attestations
/// * `identity_pk_ptr` / `identity_pk_len` - 32-byte Ed25519 identity public key
/// * `result_ptr` / `result_len` - Output buffer for JSON VerificationReport.
///   On entry, `*result_len` must hold the buffer capacity.
///   On success, `*result_len` is set to the bytes written.
///
/// # Returns
/// * `0` (VERIFY_SUCCESS) on success (report written to result_ptr)
/// * Negative error code on failure
///
/// # Safety
/// All pointers must be valid for the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ffi_verify_device_authorization_json(
    identity_did_ptr: *const u8,
    identity_did_len: usize,
    device_did_ptr: *const u8,
    device_did_len: usize,
    chain_json_ptr: *const u8,
    chain_json_len: usize,
    identity_pk_ptr: *const u8,
    identity_pk_len: usize,
    result_ptr: *mut u8,
    result_len: *mut usize,
) -> c_int {
    let result = panic::catch_unwind(|| {
        if identity_did_ptr.is_null()
            || device_did_ptr.is_null()
            || chain_json_ptr.is_null()
            || identity_pk_ptr.is_null()
            || result_ptr.is_null()
            || result_len.is_null()
        {
            error!("FFI verify_device_authorization_json: null pointer argument");
            return ERR_VERIFY_NULL_ARGUMENT;
        }

        if identity_pk_len != ED25519_PUBLIC_KEY_LEN {
            error!("FFI verify_device_authorization_json: invalid identity PK length");
            return ERR_VERIFY_INVALID_PK_LEN;
        }

        if chain_json_len > MAX_JSON_BATCH_SIZE {
            error!(
                "FFI verify_device_authorization_json: chain JSON too large ({} bytes)",
                chain_json_len
            );
            return ERR_VERIFY_INPUT_TOO_LARGE;
        }

        let identity_did_bytes =
            unsafe { slice::from_raw_parts(identity_did_ptr, identity_did_len) };
        let device_did_bytes = unsafe { slice::from_raw_parts(device_did_ptr, device_did_len) };
        let chain_json = unsafe { slice::from_raw_parts(chain_json_ptr, chain_json_len) };
        let identity_pk = unsafe { slice::from_raw_parts(identity_pk_ptr, identity_pk_len) };

        let identity_did = match std::str::from_utf8(identity_did_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "FFI verify_device_authorization_json: invalid identity DID UTF-8: {}",
                    e
                );
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        let device_did_str = match std::str::from_utf8(device_did_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "FFI verify_device_authorization_json: invalid device DID UTF-8: {}",
                    e
                );
                return ERR_VERIFY_JSON_PARSE;
            }
        };
        let device_did = DeviceDID::new(device_did_str);

        let attestations: Vec<Attestation> = match serde_json::from_slice(chain_json) {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "FFI verify_device_authorization_json: chain JSON parse error: {}",
                    e
                );
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        let verifier = Verifier::native();
        let report = match with_runtime(verifier.verify_device_authorization(
            identity_did,
            &device_did,
            &attestations,
            identity_pk,
        )) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "FFI verify_device_authorization_json: verification error: {}",
                    e
                );
                return attestation_error_to_code(&e);
            }
        };

        unsafe {
            write_report_to_buffer(
                &report,
                result_ptr,
                result_len,
                "verify_device_authorization_json",
            )
        }
    });
    result.unwrap_or_else(|_| {
        error!("FFI ffi_verify_device_authorization_json: panic occurred");
        ERR_VERIFY_PANIC
    })
}
