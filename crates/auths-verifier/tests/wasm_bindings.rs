#![cfg(target_arch = "wasm32")]

use auths_verifier::wasm::{wasm_verify_artifact_signature, wasm_verify_attestation_json};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Pre-computed fixture: valid attestation JSON signed with deterministic test keypairs.
// Generated via `cargo run --example gen_wasm_fixture -p auths-verifier`.
const FIXTURE_ISSUER_PK_HEX: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const FIXTURE_ATTESTATION_JSON: &str = r#"{"version":1,"rid":"test-rid","issuer":"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX","subject":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","device_public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","identity_signature":"1690dee2371b2bd586e696c6f891c509140ff808b82cda8c83ecfa0ea396cb3e295006ad2e6498389b5e3b1ff9d089a9ab654c30adb68d55bde04a64d7e80208","device_signature":"df199539fd0367b3684fef8b484f829c679c1d02373acf9787150032a573a3e79c878e3c4c403dfeffc25f5d4695aecb64ea67a286068ed7ca4a51f042adfc08","timestamp":null}"#;

// RFC 8032 Section 7.1, Test Vector 2 — used for artifact signature tests.
const RFC8032_PUBKEY_HEX: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

const RFC8032_MESSAGE_HEX: &str = "72";

const RFC8032_SIGNATURE_HEX: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e159c7e94e7c3650c95b39a2dd9e44b5be7cc205fd3c1b57d52d3c19";

// ---- wasm_verify_attestation_json ----

#[wasm_bindgen_test]
async fn attestation_json_happy_path() {
    wasm_verify_attestation_json(FIXTURE_ATTESTATION_JSON, FIXTURE_ISSUER_PK_HEX)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn attestation_json_malformed_json() {
    let result = wasm_verify_attestation_json("not valid json {{{{", FIXTURE_ISSUER_PK_HEX).await;
    assert!(result.is_err());
}

#[wasm_bindgen_test]
async fn attestation_json_invalid_hex_pubkey() {
    let result = wasm_verify_attestation_json(FIXTURE_ATTESTATION_JSON, "not-hex!@#$").await;
    assert!(result.is_err());
}

// ---- wasm_verify_artifact_signature ----

#[wasm_bindgen_test]
async fn artifact_signature_happy_path() {
    let valid = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        RFC8032_PUBKEY_HEX,
    )
    .await;
    assert!(valid);
}

#[wasm_bindgen_test]
async fn artifact_signature_invalid_signature() {
    let invalid =
        wasm_verify_artifact_signature(RFC8032_MESSAGE_HEX, &"00".repeat(64), RFC8032_PUBKEY_HEX)
            .await;
    assert!(!invalid);
}

#[wasm_bindgen_test]
async fn artifact_signature_wrong_pubkey() {
    let wrong = wasm_verify_artifact_signature(
        RFC8032_MESSAGE_HEX,
        RFC8032_SIGNATURE_HEX,
        &"00".repeat(32),
    )
    .await;
    assert!(!wrong);
}
