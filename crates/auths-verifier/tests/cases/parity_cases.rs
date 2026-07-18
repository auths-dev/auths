//! Shared cross-surface parity battery: one forgery set, fed identically through the
//! native, FFI, and WASM verdict surfaces (`cross_surface_parity.rs` drives native+FFI;
//! `tests/wasm_bindings.rs` `#[path]`-includes this and drives the wasm32 surface). Holding
//! the fixtures, the forgery builder, and the case list here is the single source of truth —
//! the surface-specific drivers (the C-ABI shim, the wasm-bindgen shim) live with their tests.

#![allow(dead_code)]

pub const PRESENTATION_VALID: &str = include_str!("../fixtures/presentation_valid.json");
pub const CREDENTIAL_VALID: &str = include_str!("../fixtures/credential_valid.json");
pub const CREDENTIAL_REVOKED: &str = include_str!("../fixtures/credential_revoked.json");

/// Deterministic Ed25519 attestation fixture (raw-key surface; shared with `ffi_smoke`).
pub const FIXTURE_ISSUER_PK_HEX: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
pub const FIXTURE_ATTESTATION_JSON: &str = r#"{"version":1,"rid":"test-rid","issuer":"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX","subject":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","device_public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","identity_signature":"1690dee2371b2bd586e696c6f891c509140ff808b82cda8c83ecfa0ea396cb3e295006ad2e6498389b5e3b1ff9d089a9ab654c30adb68d55bde04a64d7e80208","device_signature":"df199539fd0367b3684fef8b484f829c679c1d02373acf9787150032a573a3e79c878e3c4c403dfeffc25f5d4695aecb64ea67a286068ed7ca4a51f042adfc08","timestamp":null}"#;

/// Re-serialize a fixture after mutating one field — the forgery builder.
pub fn tampered(fixture: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value: serde_json::Value = serde_json::from_str(fixture).expect("fixture is JSON");
    mutate(&mut value);
    serde_json::to_string(&value).expect("re-serialize")
}

/// A base64 all-zero 64-byte signature — a possessor who cannot produce the real signature.
pub fn zero_sig_b64() -> serde_json::Value {
    use base64::Engine as _;
    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode([0u8; 64]))
}

/// The `kind` discriminant of a verdict JSON string.
pub fn kind(verdict_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(verdict_json).expect("verdict JSON");
    v["kind"].as_str().expect("kind discriminant").to_string()
}

/// One parity case: a label, the request JSON, and the verdict `kind` every surface must
/// return for it.
pub struct Case {
    pub label: &'static str,
    pub request: String,
    pub expected_kind: &'static str,
}

/// The presentation forgery battery — each forged field maps to a distinct verdict kind.
pub fn presentation_cases() -> Vec<Case> {
    let c = |label, request, expected_kind| Case {
        label,
        request,
        expected_kind,
    };
    vec![
        c("valid", PRESENTATION_VALID.to_string(), "valid"),
        c(
            "zeroed-binding-sig",
            tampered(PRESENTATION_VALID, |v| {
                v["envelope"]["signatureB64"] = zero_sig_b64();
            }),
            "holderNotCurrentKey",
        ),
        c(
            "wrong-audience",
            tampered(PRESENTATION_VALID, |v| {
                v["envelope"]["audience"] = serde_json::Value::String("evil.example".into());
            }),
            "wrongAudience",
        ),
        c(
            "tampered-nonce",
            tampered(PRESENTATION_VALID, |v| {
                v["envelope"]["binding"]["nonceB64"] = zero_sig_b64();
            }),
            "nonceMismatchOrConsumed",
        ),
        c(
            "unsupported-schema-version",
            tampered(PRESENTATION_VALID, |v| {
                v["schemaVersion"] = serde_json::Value::from(9999);
            }),
            "unsupportedSchemaVersion",
        ),
        c(
            "tampered-credential-said",
            tampered(PRESENTATION_VALID, |v| {
                v["credential"]["acdc"]["d"] = serde_json::Value::String(
                    "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                );
            }),
            "credentialNotValid",
        ),
        c(
            "forged-subject-kel-attachment",
            tampered(PRESENTATION_VALID, |v| {
                v["subjectKelAttachmentsB64"][0] = zero_sig_b64();
            }),
            "kelUnauthenticated",
        ),
        c(
            "forged-issuer-kel-attachment",
            tampered(PRESENTATION_VALID, |v| {
                v["issuerKelAttachmentsB64"][0] = zero_sig_b64();
            }),
            "kelUnauthenticated",
        ),
        c(
            "stripped-subject-kel-attachments",
            tampered(PRESENTATION_VALID, |v| {
                v["subjectKelAttachmentsB64"] = serde_json::json!([]);
            }),
            "kelUnauthenticated",
        ),
        c(
            "truncated",
            PRESENTATION_VALID[..PRESENTATION_VALID.len() / 2].to_string(),
            "malformedRequest",
        ),
    ]
}

/// The credential forgery battery.
pub fn credential_cases() -> Vec<Case> {
    let c = |label, request, expected_kind| Case {
        label,
        request,
        expected_kind,
    };
    vec![
        c("valid", CREDENTIAL_VALID.to_string(), "valid"),
        c(
            "revoked",
            CREDENTIAL_REVOKED.to_string(),
            "credentialRevoked",
        ),
        c(
            "zeroed-issuer-sig",
            tampered(CREDENTIAL_VALID, |v| {
                v["credential"]["signatureB64"] = zero_sig_b64();
            }),
            "issuerSignatureInvalid",
        ),
        c(
            "tampered-said",
            tampered(CREDENTIAL_VALID, |v| {
                v["credential"]["acdc"]["d"] = serde_json::Value::String(
                    "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                );
            }),
            "saidMismatch",
        ),
        c(
            "privilege-escalated-capability",
            tampered(CREDENTIAL_VALID, |v| {
                v["credential"]["acdc"]["a"]["capability"] =
                    serde_json::Value::String("admin".into());
            }),
            "saidMismatch",
        ),
        c(
            "forged-issuer-kel-attachment",
            tampered(CREDENTIAL_VALID, |v| {
                v["issuerKelAttachmentsB64"][0] = zero_sig_b64();
            }),
            "kelUnauthenticated",
        ),
        c(
            "stripped-issuer-kel-attachments",
            tampered(CREDENTIAL_VALID, |v| {
                v["issuerKelAttachmentsB64"] = serde_json::json!([]);
            }),
            "kelUnauthenticated",
        ),
        c(
            "truncated",
            CREDENTIAL_VALID[..CREDENTIAL_VALID.len() / 2].to_string(),
            "malformedRequest",
        ),
    ]
}
