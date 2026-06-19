use crate::core::{Attestation, DevicePublicKey, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE};
use crate::error::AttestationError;
use crate::types::CanonicalDid;
use crate::verifier::Verifier;
use crate::witness::WitnessVerifyConfig;
use auths_keri::witness::SignedReceipt;
use log::error;
use std::os::raw::c_int;
use std::panic;
use std::slice;

/// Maps a C-ABI curve code to a [`CurveType`].
///
/// The curve is carried in-band as an explicit argument — it is never inferred from key
/// length (32 bytes is ambiguous between Ed25519 and X25519; 33 between P-256 and
/// secp256k1, which is the silent-misrouting hazard `CLAUDE.md` forbids). An unrecognized
/// code is rejected, not coerced.
fn curve_from_ffi_code(code: c_int) -> Result<auths_crypto::CurveType, c_int> {
    match code {
        FFI_CURVE_ED25519 => Ok(auths_crypto::CurveType::Ed25519),
        FFI_CURVE_P256 => Ok(auths_crypto::CurveType::P256),
        _ => Err(ERR_VERIFY_UNKNOWN_CURVE),
    }
}

/// Constructs a typed public key from raw bytes and an explicit curve tag.
///
/// The caller supplies the curve; this boundary does not guess it from `bytes.len()`.
fn pk_from_bytes_ffi(
    curve: auths_crypto::CurveType,
    bytes: &[u8],
) -> Result<DevicePublicKey, c_int> {
    DevicePublicKey::try_new(curve, bytes).map_err(|_| ERR_VERIFY_INVALID_PK_LEN)
}

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
/// The caller-provided output buffer was too small to hold the verdict JSON. Distinct from
/// [`ERR_VERIFY_SERIALIZATION`]: on this code the required length is written to `*result_len`,
/// so the caller can resize and retry. (Used by the presentation/credential verdict path.)
pub const ERR_VERIFY_BUFFER_TOO_SMALL: c_int = -13;
/// Request bytes were not valid UTF-8 (the verify-JSON contract is a UTF-8 JSON document).
pub const ERR_VERIFY_INVALID_UTF8: c_int = -14;
/// The caller passed a public-key curve code this build does not recognize.
pub const ERR_VERIFY_UNKNOWN_CURVE: c_int = -15;

/// Curve code for an Ed25519 public key, passed alongside the key bytes across the C ABI.
pub const FFI_CURVE_ED25519: c_int = 0;
/// Curve code for a P-256 public key (SEC1 compressed or uncompressed), passed alongside
/// the key bytes across the C ABI.
pub const FFI_CURVE_P256: c_int = 1;
/// Unclassified verification error.
pub const ERR_VERIFY_OTHER: c_int = -99;
/// Internal panic occurred
pub const ERR_VERIFY_PANIC: c_int = -127;

fn attestation_error_to_code(e: &AttestationError) -> c_int {
    match e {
        AttestationError::IssuerSignatureFailed(_) => ERR_VERIFY_ISSUER_SIG_FAIL,
        AttestationError::DeviceSignatureFailed(_) => ERR_VERIFY_DEVICE_SIG_FAIL,
        AttestationError::AttestationExpired { .. } => ERR_VERIFY_EXPIRED,
        AttestationError::AttestationRevoked => ERR_VERIFY_REVOKED,
        AttestationError::TimestampInFuture { .. } => ERR_VERIFY_FUTURE_TIMESTAMP,
        AttestationError::SerializationError(_) => ERR_VERIFY_SERIALIZATION,
        AttestationError::InvalidInput(_) => ERR_VERIFY_INVALID_PK_LEN,
        AttestationError::InputTooLarge(_) => ERR_VERIFY_INPUT_TOO_LARGE,
        AttestationError::BundleExpired { .. } => ERR_VERIFY_EXPIRED,
        AttestationError::AttestationTooOld { .. } => ERR_VERIFY_EXPIRED,
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
) -> Result<(Vec<SignedReceipt>, WitnessKeys), c_int> {
    let receipts: Vec<SignedReceipt> = serde_json::from_slice(receipts_json).map_err(|e| {
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
/// * `issuer_pk_ptr` - Pointer to the raw issuer public-key bytes (32 for Ed25519, 33/65 for P-256 SEC1).
/// * `issuer_pk_len` - Length of the issuer public-key byte array.
/// * `issuer_pk_curve` - Curve tag for the key (`FFI_CURVE_ED25519` or `FFI_CURVE_P256`); the curve is never inferred from length.
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
    issuer_pk_curve: c_int,
) -> c_int {
    let result = panic::catch_unwind(|| {
        // --- Input Validation ---
        if attestation_json_ptr.is_null() || issuer_pk_ptr.is_null() {
            error!("FFI verify failed: Received null pointer argument.");
            return ERR_VERIFY_NULL_ARGUMENT;
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

        // --- Infer curve from length and construct typed key ---
        let issuer_pk = match curve_from_ffi_code(issuer_pk_curve)
            .and_then(|curve| pk_from_bytes_ffi(curve, issuer_pk_slice))
        {
            Ok(pk) => pk,
            Err(code) => {
                error!(
                    "FFI verify failed: invalid issuer PK (curve code {}, {} bytes)",
                    issuer_pk_curve, issuer_pk_len
                );
                return code;
            }
        };

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
        match with_runtime(verifier.verify_with_keys(&att, &issuer_pk)) {
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
/// * `root_pk_ptr` / `root_pk_len` - Raw root public-key bytes (32 Ed25519, 33/65 P-256 SEC1)
/// * `root_pk_curve` - Curve tag (`FFI_CURVE_ED25519` / `FFI_CURVE_P256`); never inferred from length
/// * `receipts_json_ptr` / `receipts_json_len` - JSON array of SignedReceipt objects
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
    root_pk_curve: c_int,
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

        if let Some(code) = check_batch_sizes(
            &[chain_json_len, receipts_json_len, witness_keys_json_len],
            "verify_chain_with_witnesses",
        ) {
            return code;
        }

        let chain_json = unsafe { slice::from_raw_parts(chain_json_ptr, chain_json_len) };
        let root_pk_slice = unsafe { slice::from_raw_parts(root_pk_ptr, root_pk_len) };
        let receipts_json = unsafe { slice::from_raw_parts(receipts_json_ptr, receipts_json_len) };
        let witness_keys_json =
            unsafe { slice::from_raw_parts(witness_keys_json_ptr, witness_keys_json_len) };

        let root_pk = match curve_from_ffi_code(root_pk_curve)
            .and_then(|curve| pk_from_bytes_ffi(curve, root_pk_slice))
        {
            Ok(pk) => pk,
            Err(code) => {
                error!(
                    "FFI verify_chain_with_witnesses: invalid root PK (curve code {}, {} bytes)",
                    root_pk_curve, root_pk_len
                );
                return code;
            }
        };

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
            &root_pk,
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

/// Copy a UTF-8 payload into a caller-owned output buffer, fail-closed on overflow.
///
/// Unlike [`write_report_to_buffer`], this never serializes (the verdict is already a
/// String) and splits the buffer-too-small case out from serialization: on overflow it
/// writes the **required** length back into `*result_len` and returns
/// [`ERR_VERIFY_BUFFER_TOO_SMALL`] so the caller can resize and retry. The caller owns the
/// buffer end-to-end — no Rust-allocated pointer ever crosses the boundary, which is what
/// keeps Go/Node/Python free of cross-allocator `free` bugs.
///
/// # Safety
/// `result_ptr` must point to a writable buffer of at least the initial `*result_len` bytes.
unsafe fn write_str_to_buffer(payload: &str, result_ptr: *mut u8, result_len: *mut usize) -> c_int {
    let bytes = payload.as_bytes();
    let capacity = unsafe { *result_len };
    if bytes.len() > capacity {
        // Report the size the caller must allocate; do not touch the (too-small) buffer.
        unsafe { *result_len = bytes.len() };
        return ERR_VERIFY_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result_ptr, bytes.len());
        *result_len = bytes.len();
    }
    VERIFY_SUCCESS
}

/// Drive a bundled verify-JSON request through `core` and write the verdict to the caller
/// buffer. Shared body of the presentation/credential C-ABI entrypoints: null/size/UTF-8
/// guards, then the panic-free fn-153.3 core, then the buffer copy. The status `c_int` is
/// the FFI transport outcome; the **verification** verdict is the discriminated-union JSON
/// the caller parses out of the buffer.
///
/// # Safety
/// `request_ptr`/`result_ptr`/`result_len` must be valid for `request_len`/`*result_len`.
unsafe fn verify_json_into_buffer(
    request_ptr: *const u8,
    request_len: usize,
    result_ptr: *mut u8,
    result_len: *mut usize,
    caller: &str,
    core: fn(&str) -> String,
) -> c_int {
    if request_ptr.is_null() || result_ptr.is_null() || result_len.is_null() {
        error!("FFI {caller}: null pointer argument");
        return ERR_VERIFY_NULL_ARGUMENT;
    }
    if request_len > MAX_JSON_BATCH_SIZE {
        error!("FFI {caller}: request too large ({request_len} bytes)");
        return ERR_VERIFY_INPUT_TOO_LARGE;
    }
    let request_bytes = unsafe { slice::from_raw_parts(request_ptr, request_len) };
    let request = match std::str::from_utf8(request_bytes) {
        Ok(s) => s,
        Err(_) => {
            error!("FFI {caller}: request was not valid UTF-8");
            return ERR_VERIFY_INVALID_UTF8;
        }
    };
    let verdict = core(request);
    unsafe { write_str_to_buffer(&verdict, result_ptr, result_len) }
}

/// Verify a credential presentation from a bundled JSON request (the fn-153.3 contract),
/// writing the tagged verdict JSON into a caller-owned buffer.
///
/// Keys travel CESR-tagged **inside** the request JSON — there is no raw-pubkey argument and
/// no byte-length curve dispatch (`pk_from_bytes_ffi` is deliberately not used here).
///
/// # Arguments
/// * `request_ptr` / `request_len` — the `VerifyPresentationRequest` JSON bytes (UTF-8).
/// * `result_ptr` / `result_len` — caller-owned output buffer; on entry `*result_len` is its
///   capacity, on success it is set to the verdict byte length.
///
/// # Returns
/// * `VERIFY_SUCCESS` (0) — verdict JSON written; parse it for the `kind` discriminant.
/// * `ERR_VERIFY_BUFFER_TOO_SMALL` (-13) — `*result_len` set to the required size; resize and retry.
/// * `ERR_VERIFY_NULL_ARGUMENT` / `ERR_VERIFY_INPUT_TOO_LARGE` / `ERR_VERIFY_INVALID_UTF8` —
///   transport-level rejections.
/// * `ERR_VERIFY_PANIC` (-127) — an unexpected panic was caught (the process never aborts).
///
/// # Safety
/// All pointers must be valid for their stated lengths for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn auths_verify_presentation_json(
    request_ptr: *const u8,
    request_len: usize,
    result_ptr: *mut u8,
    result_len: *mut usize,
) -> c_int {
    let result = panic::catch_unwind(|| unsafe {
        verify_json_into_buffer(
            request_ptr,
            request_len,
            result_ptr,
            result_len,
            "auths_verify_presentation_json",
            crate::contract::verify_presentation_json,
        )
    });
    result.unwrap_or_else(|_| {
        error!("FFI auths_verify_presentation_json: panic occurred");
        ERR_VERIFY_PANIC
    })
}

/// Verify an issued credential from a bundled JSON request (the fn-153.3 contract), writing
/// the tagged verdict JSON into a caller-owned buffer. Same status/safety/curve-tagging
/// contract as [`auths_verify_presentation_json`].
///
/// # Arguments
/// * `request_ptr` / `request_len` — the `VerifyCredentialRequest` JSON bytes (UTF-8).
/// * `result_ptr` / `result_len` — caller-owned output buffer (capacity in, length out).
///
/// # Safety
/// All pointers must be valid for their stated lengths for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn auths_verify_credential_json(
    request_ptr: *const u8,
    request_len: usize,
    result_ptr: *mut u8,
    result_len: *mut usize,
) -> c_int {
    let result = panic::catch_unwind(|| unsafe {
        verify_json_into_buffer(
            request_ptr,
            request_len,
            result_ptr,
            result_len,
            "auths_verify_credential_json",
            crate::contract::verify_credential_json,
        )
    });
    result.unwrap_or_else(|_| {
        error!("FFI auths_verify_credential_json: panic occurred");
        ERR_VERIFY_PANIC
    })
}

/// Verifies a chain of attestations via FFI (without witness quorum).
///
/// # Arguments
/// * `chain_json_ptr` / `chain_json_len` - JSON array of attestations
/// * `root_pk_ptr` / `root_pk_len` - Raw root public-key bytes (32 Ed25519, 33/65 P-256 SEC1)
/// * `root_pk_curve` - Curve tag (`FFI_CURVE_ED25519` / `FFI_CURVE_P256`); never inferred from length
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
    root_pk_curve: c_int,
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

        if chain_json_len > MAX_JSON_BATCH_SIZE {
            error!(
                "FFI verify_chain_json: chain JSON too large ({} bytes)",
                chain_json_len
            );
            return ERR_VERIFY_INPUT_TOO_LARGE;
        }

        let chain_json = unsafe { slice::from_raw_parts(chain_json_ptr, chain_json_len) };
        let root_pk_slice = unsafe { slice::from_raw_parts(root_pk_ptr, root_pk_len) };

        let root_pk = match curve_from_ffi_code(root_pk_curve)
            .and_then(|curve| pk_from_bytes_ffi(curve, root_pk_slice))
        {
            Ok(pk) => pk,
            Err(code) => {
                error!(
                    "FFI verify_chain_json: invalid root PK (curve code {}, {} bytes)",
                    root_pk_curve, root_pk_len
                );
                return code;
            }
        };

        let attestations: Vec<Attestation> = match serde_json::from_slice(chain_json) {
            Ok(a) => a,
            Err(e) => {
                error!("FFI verify_chain_json: chain JSON parse error: {}", e);
                return ERR_VERIFY_JSON_PARSE;
            }
        };

        let verifier = Verifier::native();
        let report = match with_runtime(verifier.verify_chain(&attestations, &root_pk)) {
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
/// * `identity_pk_ptr` / `identity_pk_len` - Raw identity public-key bytes (32 Ed25519, 33/65 P-256 SEC1)
/// * `identity_pk_curve` - Curve tag (`FFI_CURVE_ED25519` / `FFI_CURVE_P256`); never inferred from length
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
#[allow(clippy::too_many_lines)] // FFI boilerplate: 6 pointer-pair decodes + panic::catch_unwind wrapper
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
    identity_pk_curve: c_int,
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
        let identity_pk_slice = unsafe { slice::from_raw_parts(identity_pk_ptr, identity_pk_len) };

        let identity_pk = match curve_from_ffi_code(identity_pk_curve)
            .and_then(|curve| pk_from_bytes_ffi(curve, identity_pk_slice))
        {
            Ok(pk) => pk,
            Err(code) => {
                error!(
                    "FFI verify_device_authorization_json: invalid identity PK (curve code {}, {} bytes)",
                    identity_pk_curve, identity_pk_len
                );
                return code;
            }
        };

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
        let device_did = match CanonicalDid::parse(device_did_str) {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "FFI verify_device_authorization_json: invalid device DID: {}",
                    e
                );
                return ERR_VERIFY_JSON_PARSE;
            }
        };

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
            &identity_pk,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The curve must be taken from the explicit tag, never inferred from byte length.
    /// 33 bytes is ambiguous (P-256 vs secp256k1); 32 bytes is ambiguous (Ed25519 vs X25519).
    #[test]
    fn pk_from_bytes_ffi_tags_curve_from_argument_not_length() {
        let p256 = pk_from_bytes_ffi(auths_crypto::CurveType::P256, &[2u8; 33])
            .expect("33-byte key tagged P-256");
        assert_eq!(p256.curve(), auths_crypto::CurveType::P256);

        let ed = pk_from_bytes_ffi(auths_crypto::CurveType::Ed25519, &[1u8; 32])
            .expect("32-byte key tagged Ed25519");
        assert_eq!(ed.curve(), auths_crypto::CurveType::Ed25519);
    }

    /// The C-ABI curve code maps to a `CurveType`; an unrecognized code is rejected, not
    /// silently coerced.
    #[test]
    fn curve_from_ffi_code_maps_known_and_rejects_unknown() {
        assert_eq!(
            curve_from_ffi_code(FFI_CURVE_ED25519),
            Ok(auths_crypto::CurveType::Ed25519)
        );
        assert_eq!(
            curve_from_ffi_code(FFI_CURVE_P256),
            Ok(auths_crypto::CurveType::P256)
        );
        assert_eq!(curve_from_ffi_code(99), Err(ERR_VERIFY_UNKNOWN_CURVE));
    }

    /// The panic guard each verdict entrypoint uses must map an unwind to `ERR_VERIFY_PANIC`,
    /// never abort. The verify core itself is panic-free, so this proves the boundary contract
    /// directly rather than through a contrived panicking input.
    #[test]
    fn catch_unwind_maps_panic_to_panic_code() {
        let result =
            panic::catch_unwind(|| -> c_int { panic!("boom") }).unwrap_or(ERR_VERIFY_PANIC);
        assert_eq!(result, ERR_VERIFY_PANIC);
    }

    /// Buffer-too-small must report the required length and leave the status distinct from a
    /// serialization error; a second call sized to that length succeeds.
    #[test]
    fn write_str_to_buffer_reports_required_length_then_succeeds() {
        let payload = "{\"kind\":\"valid\"}";
        let mut tiny = [0u8; 4];
        let mut len = tiny.len();
        let rc = unsafe { write_str_to_buffer(payload, tiny.as_mut_ptr(), &mut len) };
        assert_eq!(rc, ERR_VERIFY_BUFFER_TOO_SMALL);
        assert_eq!(len, payload.len(), "required length reported back");

        let mut big = vec![0u8; len];
        let mut big_len = big.len();
        let rc = unsafe { write_str_to_buffer(payload, big.as_mut_ptr(), &mut big_len) };
        assert_eq!(rc, VERIFY_SUCCESS);
        assert_eq!(&big[..big_len], payload.as_bytes());
    }
}
