#![cfg(target_arch = "wasm32")]

//! Executes the WASM verdict path under Node — the same surface the browser ships.
//!
//! These run on `wasm32-unknown-unknown` through `wasm-bindgen-test-runner` in its
//! default (Node) mode, so CI exercises the *real* compiled WASM verdict, not just a
//! `wasm-pack build` that proves it links. The synchronous verdict entrypoints
//! (`verifyPresentationJson` / `verifyCredentialJson`) verify through the in-crate
//! pure-Rust `software_verify` core, so a forged input produces the same refusal here
//! that the native and FFI surfaces produce — the lockstep the cross-surface parity
//! suite then asserts directly. The async attestation/artifact entrypoints additionally
//! drive the Web Crypto Ed25519 path that only exists on this target.

use auths_verifier::wasm::{
    wasm_verify_artifact_signature, wasm_verify_attestation_json, wasm_verify_credential_json,
    wasm_verify_presentation_json,
};
use wasm_bindgen_test::*;

// The cross-surface forgery battery + fixtures, shared verbatim with the native/FFI parity
// suite (`cases/cross_surface_parity.rs`). Driving the *same* cases here is the third leg of
// the §3.8 lockstep: a forgery the native and FFI surfaces refuse must be refused — with the
// identical verdict kind — by the compiled WASM verdict too.
#[path = "cases/parity_cases.rs"]
mod parity_cases;
use parity_cases::{
    CREDENTIAL_REVOKED, CREDENTIAL_VALID, FIXTURE_ATTESTATION_JSON, FIXTURE_ISSUER_PK_HEX,
    PRESENTATION_VALID, credential_cases, kind, presentation_cases,
};

// RFC 8032 Section 7.1, Test Vector 2 — used for artifact signature tests.
const RFC8032_PUBKEY_HEX: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

const RFC8032_MESSAGE_HEX: &str = "72";

const RFC8032_SIGNATURE_HEX: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/// Parse a verdict JSON string into the `kind`-tagged envelope, asserting it is a
/// well-formed object (the verdict surface is always string-typed, never a panic).
fn verdict(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("verdict is always valid JSON")
}

/// Re-serialize `fixture_json` after applying `mutate` — the building block for the
/// negative cases (forge a field, then confirm the verdict path refuses it).
fn tampered(fixture_json: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(fixture_json).expect("fixture is valid JSON");
    mutate(&mut value);
    serde_json::to_string(&value).expect("re-serialize")
}

// ---- cross-surface parity battery (same cases as native/FFI) ----

#[wasm_bindgen_test]
fn presentation_battery_kinds_match_native_and_ffi() {
    for case in presentation_cases() {
        let v = wasm_verify_presentation_json(&case.request);
        assert_eq!(
            kind(&v),
            case.expected_kind,
            "WASM presentation verdict must match the native/FFI kind for {}",
            case.label
        );
    }
}

#[wasm_bindgen_test]
fn credential_battery_kinds_match_native_and_ffi() {
    for case in credential_cases() {
        let v = wasm_verify_credential_json(&case.request);
        assert_eq!(
            kind(&v),
            case.expected_kind,
            "WASM credential verdict must match the native/FFI kind for {}",
            case.label
        );
    }
}

// ---- verifyPresentationJson (synchronous, pure-Rust verdict path) ----

#[wasm_bindgen_test]
fn presentation_valid_fixture_is_honored() {
    let v = verdict(&wasm_verify_presentation_json(PRESENTATION_VALID));
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["kind"], "valid", "valid presentation fixture must verify");
    assert!(
        v["subject"]
            .as_str()
            .is_some_and(|s| s.starts_with("did:keri:")),
        "honored verdict carries the holder subject DID"
    );
}

#[wasm_bindgen_test]
fn presentation_with_zeroed_signature_is_refused() {
    // A possessor who cannot produce the subject's signature: the verdict path must
    // refuse, never return `valid`.
    let forged = tampered(PRESENTATION_VALID, |v| {
        let b64 = base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        v["envelope"]["signatureB64"] = serde_json::Value::String(b64.encode([0u8; 64]));
    });
    let v = verdict(&wasm_verify_presentation_json(&forged));
    assert_eq!(
        v["kind"], "holderNotCurrentKey",
        "a zeroed presentation signature is not current control"
    );
}

#[wasm_bindgen_test]
fn presentation_for_wrong_audience_is_refused() {
    let forged = tampered(PRESENTATION_VALID, |v| {
        v["audience"] = serde_json::Value::String("evil.example".to_string());
    });
    let v = verdict(&wasm_verify_presentation_json(&forged));
    assert_eq!(
        v["kind"], "wrongAudience",
        "a presentation bound to a different audience is refused"
    );
}

#[wasm_bindgen_test]
fn malformed_presentation_request_is_typed_error() {
    let v = verdict(&wasm_verify_presentation_json("{not json"));
    assert_eq!(
        v["kind"], "malformedRequest",
        "garbage input yields a typed error verdict, never a panic"
    );
}

// ---- verifyCredentialJson (synchronous, pure-Rust verdict path) ----

#[wasm_bindgen_test]
fn credential_valid_fixture_is_honored() {
    let v = verdict(&wasm_verify_credential_json(CREDENTIAL_VALID));
    assert_eq!(v["kind"], "valid", "valid credential fixture must verify");
}

#[wasm_bindgen_test]
fn credential_revoked_fixture_is_refused() {
    let v = verdict(&wasm_verify_credential_json(CREDENTIAL_REVOKED));
    assert_eq!(
        v["kind"], "credentialRevoked",
        "a revoked credential must not verify"
    );
}

#[wasm_bindgen_test]
fn credential_with_tampered_signature_is_refused() {
    let forged = tampered(CREDENTIAL_VALID, |v| {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        v["credential"]["signatureB64"] = serde_json::Value::String(b64.encode([0u8; 64]));
    });
    let v = verdict(&wasm_verify_credential_json(&forged));
    assert_ne!(
        v["kind"], "valid",
        "a credential with a forged issuer signature must not verify"
    );
}

// ---- wasm_verify_attestation_json (async Web Crypto Ed25519 path) ----

#[wasm_bindgen_test]
async fn attestation_json_happy_path() {
    wasm_verify_attestation_json(
        FIXTURE_ATTESTATION_JSON,
        FIXTURE_ISSUER_PK_HEX,
        Some("ed25519".to_string()),
    )
    .await
    .unwrap();
}

#[wasm_bindgen_test]
async fn attestation_json_wrong_issuer_key_is_refused() {
    // The same forgery the native and FFI surfaces reject: a valid attestation against
    // the wrong issuer key. WASM must refuse it too.
    let result = wasm_verify_attestation_json(
        FIXTURE_ATTESTATION_JSON,
        &"00".repeat(32),
        Some("ed25519".to_string()),
    )
    .await;
    assert!(result.is_err(), "wrong issuer key must not verify on WASM");
}

#[wasm_bindgen_test]
async fn attestation_json_malformed_json() {
    let result = wasm_verify_attestation_json(
        "not valid json {{{{",
        FIXTURE_ISSUER_PK_HEX,
        Some("ed25519".to_string()),
    )
    .await;
    assert!(result.is_err());
}

#[wasm_bindgen_test]
async fn attestation_json_invalid_hex_pubkey() {
    let result = wasm_verify_attestation_json(
        FIXTURE_ATTESTATION_JSON,
        "not-hex!@#$",
        Some("ed25519".to_string()),
    )
    .await;
    assert!(result.is_err());
}

// ---- wasm_verify_artifact_signature (async Web Crypto Ed25519 path) ----

#[wasm_bindgen_test]
async fn artifact_signature_happy_path() {
    let valid = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        RFC8032_PUBKEY_HEX,
        Some("ed25519".to_string()),
    )
    .await;
    assert!(valid);
}

#[wasm_bindgen_test]
async fn artifact_signature_invalid_signature() {
    let invalid = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        &"00".repeat(64),
        RFC8032_PUBKEY_HEX,
        Some("ed25519".to_string()),
    )
    .await;
    assert!(!invalid);
}

#[wasm_bindgen_test]
async fn artifact_signature_wrong_pubkey() {
    let wrong = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        &"00".repeat(32),
        Some("ed25519".to_string()),
    )
    .await;
    assert!(!wrong);
}

#[wasm_bindgen_test]
async fn artifact_absent_curve_defaults_to_p256_not_ed25519() {
    // The WASM wire rule: an absent curve tag defaults to P-256, never Ed25519. Pinned via
    // the asymmetry on the *same* Ed25519 vector — tagged `ed25519` it verifies, but with
    // the tag omitted the 32-byte key is read as a (malformed) P-256 key and rejected. This
    // is the counterpart to the FFI surface rejecting an unknown integer curve code, so the
    // two surfaces cannot silently converge on a curve default.
    let tagged = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        RFC8032_PUBKEY_HEX,
        Some("ed25519".to_string()),
    )
    .await;
    assert!(tagged, "an Ed25519-tagged vector verifies");

    let absent = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        RFC8032_PUBKEY_HEX,
        None,
    )
    .await;
    assert!(
        !absent,
        "an absent curve tag defaults to P-256, which rejects a 32-byte Ed25519 key"
    );
}
