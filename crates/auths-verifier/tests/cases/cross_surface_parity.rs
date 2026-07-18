//! One forged input, refused identically on every binding surface.
//!
//! The native verdict is the reference; the FFI surface re-wraps it across the C ABI and
//! the WASM surface across wasm-bindgen. Both delegate to the *same* verify core, so a
//! forgery the native path refuses must be refused — byte-for-byte for the JSON verdict
//! path — by the others. This battery feeds one fixture set {valid; wrong-key; tampered;
//! malformed/truncated; forged presentation + credential} through native and FFI and
//! asserts they agree, then pins the one place the surfaces differ *by design*: an absent
//! curve tag defaults to P-256 on the string-typed WASM wire, whereas an unknown integer
//! curve *code* is rejected at the FFI boundary. The WASM leg of the same fixtures runs on
//! the wasm32 target in `tests/wasm_bindings.rs`.

use super::parity_cases::{
    CREDENTIAL_VALID, FIXTURE_ATTESTATION_JSON, FIXTURE_ISSUER_PK_HEX, PRESENTATION_VALID,
    credential_cases, kind, presentation_cases,
};
use auths_crypto::CurveType;
use auths_verifier::core::{Attestation, DevicePublicKey};
use auths_verifier::ffi::{
    ERR_VERIFY_UNKNOWN_CURVE, FFI_CURVE_ED25519, VERIFY_SUCCESS, auths_verify_credential_json,
    auths_verify_presentation_json, ffi_verify_attestation_json,
};
use auths_verifier::{Verifier, verify_credential_json, verify_presentation_json};
use core::ffi::c_int;

type JsonVerifyFn = unsafe extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> c_int;

/// Drive a JSON-verdict FFI entrypoint and return the verdict string it writes. The verdict
/// path always produces a string (even for malformed input), so a transport error here is a
/// genuine failure, not an expected refusal.
fn ffi_verdict(request: &str, f: JsonVerifyFn) -> String {
    let bytes = request.as_bytes();
    let mut buf = vec![0u8; 64 * 1024];
    let mut len = buf.len();
    let rc = unsafe { f(bytes.as_ptr(), bytes.len(), buf.as_mut_ptr(), &mut len) };
    assert_eq!(
        rc, VERIFY_SUCCESS,
        "the JSON verdict path returns a verdict string, never a transport error code"
    );
    String::from_utf8(buf[..len].to_vec()).expect("verdict bytes are UTF-8")
}

#[test]
fn presentation_verdicts_are_byte_identical_native_and_ffi() {
    for case in presentation_cases() {
        let native = verify_presentation_json(&case.request);
        let ffi = ffi_verdict(&case.request, auths_verify_presentation_json);
        assert_eq!(
            native, ffi,
            "native and FFI must return the identical presentation verdict for {}",
            case.label
        );
        assert_eq!(kind(&native), case.expected_kind, "{}", case.label);
    }
}

#[test]
fn credential_verdicts_are_byte_identical_native_and_ffi() {
    for case in credential_cases() {
        let native = verify_credential_json(&case.request);
        let ffi = ffi_verdict(&case.request, auths_verify_credential_json);
        assert_eq!(
            native, ffi,
            "native and FFI must return the identical credential verdict for {}",
            case.label
        );
        assert_eq!(kind(&native), case.expected_kind, "{}", case.label);
    }
}

/// The positive JSON verdict names its freshness on the FFI surface too, not just natively
/// (invariant #6 in lockstep). The byte-identical checks above already pin native == FFI; this
/// asserts the surfaced field is actually present on the FFI verdict, so a regression that drops
/// freshness from the wire is caught on the embeddable surface, not only in the native test.
#[test]
fn ffi_valid_verdicts_name_freshness() {
    for (request, f) in [
        (
            PRESENTATION_VALID,
            auths_verify_presentation_json as JsonVerifyFn,
        ),
        (
            CREDENTIAL_VALID,
            auths_verify_credential_json as JsonVerifyFn,
        ),
    ] {
        let verdict: serde_json::Value =
            serde_json::from_str(&ffi_verdict(request, f)).expect("verdict json");
        assert_eq!(verdict["kind"], "valid", "fixture must be a valid verdict");
        assert!(
            verdict.get("freshness").and_then(|v| v.as_str()).is_some(),
            "the FFI valid verdict must name its freshness, got {verdict}"
        );
    }
}

/// The raw-key attestation surface (the curve carried as an out-of-band tag, not in-band
/// CESR) must accept/reject in lockstep across native and FFI for the whole fixture set.
/// Both sides decode the *same* hex key under the *same* curve, so any divergence is a
/// real wrapper bug, not a fixture mismatch. Driven on a plain thread (not `#[tokio::test]`)
/// because the FFI entrypoint builds its own runtime — calling it from inside one panics.
#[test]
fn attestation_accept_reject_agrees_native_and_ffi() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    let verifier = Verifier::native();
    let tampered_att = FIXTURE_ATTESTATION_JSON.replacen("df199539", "ef199539", 1);
    let wrong_pk_hex = "00".repeat(32);

    // (label, attestation json, pk hex, expected acceptance)
    let cases: [(&str, &str, &str, bool); 4] = [
        (
            "valid",
            FIXTURE_ATTESTATION_JSON,
            FIXTURE_ISSUER_PK_HEX,
            true,
        ),
        ("wrong-key", FIXTURE_ATTESTATION_JSON, &wrong_pk_hex, false),
        ("tampered", &tampered_att, FIXTURE_ISSUER_PK_HEX, false),
        ("malformed", "[not json", FIXTURE_ISSUER_PK_HEX, false),
    ];

    for (label, json, pk_hex, expected) in cases {
        let native = match (
            hex::decode(pk_hex)
                .ok()
                .and_then(|b| DevicePublicKey::try_new(CurveType::Ed25519, &b).ok()),
            serde_json::from_str::<Attestation>(json).ok(),
        ) {
            (Some(pk), Some(att)) => runtime
                .block_on(verifier.verify_with_keys(&att, &pk))
                .is_ok(),
            _ => false,
        };

        let json_b = json.as_bytes();
        let pk = hex::decode(pk_hex).unwrap_or_default();
        let ffi = unsafe {
            ffi_verify_attestation_json(
                json_b.as_ptr(),
                json_b.len(),
                pk.as_ptr(),
                pk.len(),
                FFI_CURVE_ED25519,
            )
        } == VERIFY_SUCCESS;

        assert_eq!(
            native, ffi,
            "native/FFI attestation acceptance must agree on the {label} case"
        );
        assert_eq!(native, expected, "{label} acceptance");
    }
}

/// The intentional curve-dispatch difference, pinned so it cannot silently drift: the FFI
/// boundary rejects an unknown integer curve code (it never guesses), while the WASM wire's
/// absent-tag→P-256 default is pinned on the wasm32 side (`wasm_bindings.rs`).
#[test]
fn ffi_rejects_unknown_curve_code() {
    let json = FIXTURE_ATTESTATION_JSON.as_bytes();
    let pk = hex::decode(FIXTURE_ISSUER_PK_HEX).expect("pk");
    let rc = unsafe {
        ffi_verify_attestation_json(json.as_ptr(), json.len(), pk.as_ptr(), pk.len(), 99)
    };
    assert_eq!(
        rc, ERR_VERIFY_UNKNOWN_CURVE,
        "an unknown curve code is rejected, never defaulted"
    );
}
