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

use auths_crypto::CurveType;
use auths_verifier::core::{Attestation, DevicePublicKey};
use auths_verifier::ffi::{
    ERR_VERIFY_UNKNOWN_CURVE, FFI_CURVE_ED25519, VERIFY_SUCCESS, auths_verify_credential_json,
    auths_verify_presentation_json, ffi_verify_attestation_json,
};
use auths_verifier::{Verifier, verify_credential_json, verify_presentation_json};
use core::ffi::c_int;

const PRESENTATION_VALID: &str = include_str!("../fixtures/presentation_valid.json");
const CREDENTIAL_VALID: &str = include_str!("../fixtures/credential_valid.json");
const CREDENTIAL_REVOKED: &str = include_str!("../fixtures/credential_revoked.json");

// Deterministic Ed25519 attestation fixture (shared with `ffi_smoke` / `wasm_bindings`).
const FIXTURE_ISSUER_PK_HEX: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const FIXTURE_ATTESTATION_JSON: &str = r#"{"version":1,"rid":"test-rid","issuer":"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX","subject":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","device_public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","identity_signature":"1690dee2371b2bd586e696c6f891c509140ff808b82cda8c83ecfa0ea396cb3e295006ad2e6498389b5e3b1ff9d089a9ab654c30adb68d55bde04a64d7e80208","device_signature":"df199539fd0367b3684fef8b484f829c679c1d02373acf9787150032a573a3e79c878e3c4c403dfeffc25f5d4695aecb64ea67a286068ed7ca4a51f042adfc08","timestamp":null}"#;

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

/// Re-serialize a fixture after mutating one field — the forgery builder.
fn tampered(fixture: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value: serde_json::Value = serde_json::from_str(fixture).expect("fixture is JSON");
    mutate(&mut value);
    serde_json::to_string(&value).expect("re-serialize")
}

fn zero_sig_b64() -> serde_json::Value {
    use base64::Engine as _;
    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode([0u8; 64]))
}

fn kind(verdict_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(verdict_json).expect("verdict JSON");
    v["kind"].as_str().expect("kind discriminant").to_string()
}

#[test]
fn presentation_verdicts_are_byte_identical_native_and_ffi() {
    let truncated = &PRESENTATION_VALID[..PRESENTATION_VALID.len() / 2];
    let zeroed = tampered(PRESENTATION_VALID, |v| {
        v["envelope"]["signatureB64"] = zero_sig_b64();
    });
    let wrong_audience = tampered(PRESENTATION_VALID, |v| {
        v["audience"] = serde_json::Value::String("evil.example".to_string());
    });

    let cases: [(&str, &str); 4] = [
        (PRESENTATION_VALID, "valid"),
        (&zeroed, "holderNotCurrentKey"),
        (&wrong_audience, "wrongAudience"),
        (truncated, "malformedRequest"),
    ];

    for (request, expected_kind) in cases {
        let native = verify_presentation_json(request);
        let ffi = ffi_verdict(request, auths_verify_presentation_json);
        assert_eq!(
            native, ffi,
            "native and FFI must return the identical presentation verdict for {expected_kind}"
        );
        assert_eq!(kind(&native), expected_kind);
    }
}

#[test]
fn credential_verdicts_are_byte_identical_native_and_ffi() {
    let zeroed = tampered(CREDENTIAL_VALID, |v| {
        v["credential"]["signatureB64"] = zero_sig_b64();
    });
    let truncated = &CREDENTIAL_VALID[..CREDENTIAL_VALID.len() / 2];

    let cases: [(&str, &str); 4] = [
        (CREDENTIAL_VALID, "valid"),
        (CREDENTIAL_REVOKED, "credentialRevoked"),
        (&zeroed, "issuerSignatureInvalid"),
        (truncated, "malformedRequest"),
    ];

    for (request, expected_kind) in cases {
        let native = verify_credential_json(request);
        let ffi = ffi_verdict(request, auths_verify_credential_json);
        assert_eq!(
            native, ffi,
            "native and FFI must return the identical credential verdict for {expected_kind}"
        );
        assert_eq!(kind(&native), expected_kind);
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
