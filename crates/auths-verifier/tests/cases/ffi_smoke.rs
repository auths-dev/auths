use auths_verifier::ffi::*;
use std::ptr;

// Same fixture as wasm_bindings.rs — generated with deterministic ring keypairs.
const FIXTURE_ISSUER_PK_HEX: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const FIXTURE_ATTESTATION_JSON: &str = r#"{"version":1,"rid":"test-rid","issuer":"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX","subject":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","device_public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","identity_signature":"1690dee2371b2bd586e696c6f891c509140ff808b82cda8c83ecfa0ea396cb3e295006ad2e6498389b5e3b1ff9d089a9ab654c30adb68d55bde04a64d7e80208","device_signature":"df199539fd0367b3684fef8b484f829c679c1d02373acf9787150032a573a3e79c878e3c4c403dfeffc25f5d4695aecb64ea67a286068ed7ca4a51f042adfc08","timestamp":null}"#;

const FIXTURE_ISSUER_DID: &str = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX";
const FIXTURE_SUBJECT_DID: &str = "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH";

fn issuer_pk_bytes() -> Vec<u8> {
    hex::decode(FIXTURE_ISSUER_PK_HEX).unwrap()
}

fn chain_json() -> Vec<u8> {
    format!("[{}]", FIXTURE_ATTESTATION_JSON).into_bytes()
}

// ---- ffi_verify_attestation_json ----

#[test]
fn attestation_happy_path() {
    let json = FIXTURE_ATTESTATION_JSON.as_bytes();
    let pk = issuer_pk_bytes();
    let rc =
        unsafe { ffi_verify_attestation_json(json.as_ptr(), json.len(), pk.as_ptr(), pk.len()) };
    assert_eq!(rc, VERIFY_SUCCESS);
}

#[test]
fn attestation_null_json_ptr() {
    let pk = issuer_pk_bytes();
    let rc = unsafe { ffi_verify_attestation_json(ptr::null(), 0, pk.as_ptr(), pk.len()) };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn attestation_null_pk_ptr() {
    let json = FIXTURE_ATTESTATION_JSON.as_bytes();
    let rc = unsafe { ffi_verify_attestation_json(json.as_ptr(), json.len(), ptr::null(), 32) };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn attestation_invalid_pk_len() {
    let json = FIXTURE_ATTESTATION_JSON.as_bytes();
    let short_pk = [0u8; 16];
    let rc = unsafe {
        ffi_verify_attestation_json(json.as_ptr(), json.len(), short_pk.as_ptr(), short_pk.len())
    };
    assert_eq!(rc, ERR_VERIFY_INVALID_PK_LEN);
}

#[test]
fn attestation_malformed_json() {
    let bad_json = b"not valid json {{{{";
    let pk = issuer_pk_bytes();
    let rc = unsafe {
        ffi_verify_attestation_json(bad_json.as_ptr(), bad_json.len(), pk.as_ptr(), pk.len())
    };
    assert_eq!(rc, ERR_VERIFY_JSON_PARSE);
}

#[test]
fn attestation_wrong_pk_returns_sig_fail() {
    let json = FIXTURE_ATTESTATION_JSON.as_bytes();
    let wrong_pk = [0u8; 32];
    let rc = unsafe {
        ffi_verify_attestation_json(json.as_ptr(), json.len(), wrong_pk.as_ptr(), wrong_pk.len())
    };
    assert!(rc < 0, "expected negative error code, got {}", rc);
}

// ---- ffi_verify_chain_json ----

#[test]
fn chain_happy_path() {
    let chain = chain_json();
    let pk = issuer_pk_bytes();
    let mut buf = vec![0u8; 16384];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_json(
            chain.as_ptr(),
            chain.len(),
            pk.as_ptr(),
            pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, VERIFY_SUCCESS);
    assert!(buf_len > 0, "report should be non-empty");

    let report: serde_json::Value = serde_json::from_slice(&buf[..buf_len]).unwrap();
    assert_eq!(report["status"]["type"], "Valid");
}

#[test]
fn chain_null_chain_ptr() {
    let pk = issuer_pk_bytes();
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_json(
            ptr::null(),
            0,
            pk.as_ptr(),
            pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn chain_null_result_ptr() {
    let chain = chain_json();
    let pk = issuer_pk_bytes();
    let mut buf_len: usize = 4096;
    let rc = unsafe {
        ffi_verify_chain_json(
            chain.as_ptr(),
            chain.len(),
            pk.as_ptr(),
            pk.len(),
            ptr::null_mut(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn chain_malformed_json() {
    let bad = b"[not json";
    let pk = issuer_pk_bytes();
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_json(
            bad.as_ptr(),
            bad.len(),
            pk.as_ptr(),
            pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_JSON_PARSE);
}

#[test]
fn chain_invalid_pk_len() {
    let chain = chain_json();
    let short_pk = [0u8; 16];
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_json(
            chain.as_ptr(),
            chain.len(),
            short_pk.as_ptr(),
            short_pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_INVALID_PK_LEN);
}

// ---- ffi_verify_device_authorization_json ----

#[test]
fn device_auth_happy_path() {
    let identity_did = FIXTURE_ISSUER_DID.as_bytes();
    let device_did = FIXTURE_SUBJECT_DID.as_bytes();
    let chain = chain_json();
    let pk = issuer_pk_bytes();
    let mut buf = vec![0u8; 16384];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_device_authorization_json(
            identity_did.as_ptr(),
            identity_did.len(),
            device_did.as_ptr(),
            device_did.len(),
            chain.as_ptr(),
            chain.len(),
            pk.as_ptr(),
            pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, VERIFY_SUCCESS);
    assert!(buf_len > 0);

    let report: serde_json::Value = serde_json::from_slice(&buf[..buf_len]).unwrap();
    assert_eq!(report["status"]["type"], "Valid");
}

#[test]
fn device_auth_null_identity_did() {
    let device_did = FIXTURE_SUBJECT_DID.as_bytes();
    let chain = chain_json();
    let pk = issuer_pk_bytes();
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_device_authorization_json(
            ptr::null(),
            0,
            device_did.as_ptr(),
            device_did.len(),
            chain.as_ptr(),
            chain.len(),
            pk.as_ptr(),
            pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn device_auth_invalid_pk_len() {
    let identity_did = FIXTURE_ISSUER_DID.as_bytes();
    let device_did = FIXTURE_SUBJECT_DID.as_bytes();
    let chain = chain_json();
    let short_pk = [0u8; 16];
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_device_authorization_json(
            identity_did.as_ptr(),
            identity_did.len(),
            device_did.as_ptr(),
            device_did.len(),
            chain.as_ptr(),
            chain.len(),
            short_pk.as_ptr(),
            short_pk.len(),
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_INVALID_PK_LEN);
}

// ---- ffi_verify_chain_with_witnesses ----

#[test]
fn chain_with_witnesses_null_chain_ptr() {
    let pk = issuer_pk_bytes();
    let receipts = b"[]";
    let keys = b"[]";
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_with_witnesses(
            ptr::null(),
            0,
            pk.as_ptr(),
            pk.len(),
            receipts.as_ptr(),
            receipts.len(),
            keys.as_ptr(),
            keys.len(),
            0,
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_NULL_ARGUMENT);
}

#[test]
fn chain_with_witnesses_invalid_pk_len() {
    let chain = chain_json();
    let short_pk = [0u8; 16];
    let receipts = b"[]";
    let keys = b"[]";
    let mut buf = vec![0u8; 4096];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_with_witnesses(
            chain.as_ptr(),
            chain.len(),
            short_pk.as_ptr(),
            short_pk.len(),
            receipts.as_ptr(),
            receipts.len(),
            keys.as_ptr(),
            keys.len(),
            0,
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, ERR_VERIFY_INVALID_PK_LEN);
}

#[test]
fn chain_with_witnesses_happy_path_zero_threshold() {
    let chain = chain_json();
    let pk = issuer_pk_bytes();
    let receipts = b"[]";
    let keys = b"[]";
    let mut buf = vec![0u8; 16384];
    let mut buf_len: usize = buf.len();
    let rc = unsafe {
        ffi_verify_chain_with_witnesses(
            chain.as_ptr(),
            chain.len(),
            pk.as_ptr(),
            pk.len(),
            receipts.as_ptr(),
            receipts.len(),
            keys.as_ptr(),
            keys.len(),
            0,
            buf.as_mut_ptr(),
            &mut buf_len,
        )
    };
    assert_eq!(rc, VERIFY_SUCCESS);
    assert!(buf_len > 0);
}
