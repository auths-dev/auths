//! Signature-injection FFI for the "Login with Auths" challenge flow.
//!
//! Replaces the legacy `sign_auth_challenge(pkcs8_hex, did, input)` entry
//! point with the build/assemble dance that never surfaces private key
//! material in Rust:
//!
//! 1. [`build_auth_challenge_signing_payload`] — the caller parses the
//!    QR-encoded challenge URI and hands over the device's public key.
//!    The FFI builds the canonical challenge JSON and returns an opaque
//!    [`AuthChallengeContext`] containing the exact bytes the SE must sign.
//!
//! 2. [`assemble_auth_challenge_response`] — the caller returns the SE's
//!    signature. The FFI verifies it locally, then emits the JSON body to
//!    POST to the auth server.
//!
//! Wire formats (per ADRs 002 / 003):
//! - Pubkey input: 33 B compressed / 65 B uncompressed / SPKI DER, normalized
//!   to 33 B compressed on the wire.
//! - Signature input: raw r‖s or X9.62 DER, normalized to raw on the wire.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};

use crate::MobileError;

// Re-use the normalizers and did:key derivation from the pairing module —
// they're identical pieces of wire-format logic for P-256.
use crate::pairing_context::{
    derive_device_did_public, normalize_p256_pubkey_to_compressed_public,
    normalize_p256_signature_to_raw_public,
};

// ---------------------------------------------------------------------------
// Opaque UniFFI Object
// ---------------------------------------------------------------------------

/// Per-login-challenge state between [`build_auth_challenge_signing_payload`]
/// and [`assemble_auth_challenge_response`].
#[derive(Debug, uniffi::Object)]
pub struct AuthChallengeContext {
    /// Canonical JSON bytes the Secure Enclave must sign. Matches the
    /// on-wire canonicalization used by the auth server's verifier
    /// (`json_canon::to_string(&{"domain", "nonce"})`).
    signing_payload: Vec<u8>,

    /// Session ID from the challenge URI (URL path parameter on POST).
    session_id: String,

    /// Hex-encoded challenge nonce.
    nonce: String,

    /// Domain the challenge is bound to (anti-phishing).
    domain: String,

    /// Auth server endpoint URL (POST target).
    auth_server_url: String,

    /// Device's P-256 signing pubkey in compressed SEC1 form (33 B),
    /// pre-normalized from the caller's input shape.
    device_signing_pubkey_compressed: Vec<u8>,
}

#[uniffi::export]
impl AuthChallengeContext {
    /// The exact bytes the Secure Enclave must sign.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.signing_payload.clone()
    }

    /// Session ID from the challenge URI. The auth server uses this on
    /// its `POST /v1/auth/sessions/{id}/respond` path.
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Domain the challenge is bound to (display to the user for
    /// anti-phishing confirmation).
    pub fn domain(&self) -> String {
        self.domain.clone()
    }

    /// Auth server endpoint URL (POST target).
    pub fn auth_server_url(&self) -> String {
        self.auth_server_url.clone()
    }

    /// Base64url-no-pad-encoded 33-byte compressed SEC1 pubkey.
    pub fn device_signing_pubkey(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.device_signing_pubkey_compressed)
    }

    /// Hex-encoded challenge nonce (for user display or debug).
    pub fn nonce(&self) -> String {
        self.nonce.clone()
    }
}

// ---------------------------------------------------------------------------
// Wire-format body
// ---------------------------------------------------------------------------

/// JSON body posted to the auth server.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthChallengeResponseBody {
    session_id: String,
    nonce: String,
    domain: String,
    device_did: String,
    device_signing_pubkey: String,
    /// Per ADR 003 / CLAUDE.md §4 — curve carried in-band so verifiers
    /// never infer curve from pubkey byte length.
    curve: String,
    signature: String,
}

// ---------------------------------------------------------------------------
// Public FFI surface
// ---------------------------------------------------------------------------

/// Build the signing payload for an auth (login) challenge.
///
/// Args:
/// * `challenge_uri`: The full `auths://auth?id=...&c=...&d=...&e=...` URI
///   from the QR code.
/// * `device_signing_pubkey_der`: The device's P-256 public key. Accepted in
///   33 B compressed SEC1, 65 B uncompressed SEC1, or SPKI DER form.
///
/// Usage:
/// ```ignore
/// let ctx = build_auth_challenge_signing_payload(uri, pubkey_der)?;
/// let to_sign = ctx.signing_payload();
/// let signature = secure_enclave.sign(&to_sign)?; // iOS side
/// let body = assemble_auth_challenge_response(ctx, signature)?;
/// ```
#[uniffi::export]
pub fn build_auth_challenge_signing_payload(
    challenge_uri: String,
    device_signing_pubkey_der: Vec<u8>,
) -> Result<Arc<AuthChallengeContext>, MobileError> {
    let info = crate::parse_auth_challenge_uri(challenge_uri)?;

    let device_signing_pubkey_compressed =
        normalize_p256_pubkey_to_compressed_public(&device_signing_pubkey_der)?;

    // Canonical JSON payload — must match the auth server's verifier
    // byte-for-byte. The server canonicalizes via json_canon; we produce
    // the same canonical form here.
    let payload = serde_json::json!({
        "domain": info.domain,
        "nonce": info.challenge,
    });
    let signing_payload = json_canon::to_string(&payload)
        .map_err(|e| MobileError::Serialization(e.to_string()))?
        .into_bytes();

    Ok(Arc::new(AuthChallengeContext {
        signing_payload,
        session_id: info.session_id,
        nonce: info.challenge,
        domain: info.domain,
        auth_server_url: info.auth_server_url,
        device_signing_pubkey_compressed: device_signing_pubkey_compressed.to_vec(),
    }))
}

/// Assemble the final JSON body for the auth server's challenge-response
/// endpoint.
///
/// Args:
/// * `context`: The opaque handle returned by
///   [`build_auth_challenge_signing_payload`].
/// * `signature`: The P-256 ECDSA signature produced by the Secure Enclave.
///   Accepts X9.62 DER or raw r‖s (64 B).
///
/// The signature is verified locally against the stored canonical
/// challenge before the body is emitted.
#[uniffi::export]
pub fn assemble_auth_challenge_response(
    context: Arc<AuthChallengeContext>,
    signature: Vec<u8>,
) -> Result<Vec<u8>, MobileError> {
    let sig_raw = normalize_p256_signature_to_raw_public(&signature)?;

    let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(
        &context.device_signing_pubkey_compressed,
    )
    .map_err(|e| MobileError::InvalidKeyData(format!("P-256 pubkey parse failed: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw)
        .map_err(|e| MobileError::PairingFailed(format!("signature parse failed: {e}")))?;
    verifier
        .verify(&context.signing_payload, &sig)
        .map_err(|e| {
            MobileError::PairingFailed(format!(
                "signature does not match canonical challenge under supplied pubkey: {e}"
            ))
        })?;

    let body = AuthChallengeResponseBody {
        session_id: context.session_id.clone(),
        nonce: context.nonce.clone(),
        domain: context.domain.clone(),
        device_did: derive_device_did_public(&context.device_signing_pubkey_compressed)?,
        device_signing_pubkey: URL_SAFE_NO_PAD.encode(&context.device_signing_pubkey_compressed),
        curve: "p256".to_string(),
        signature: URL_SAFE_NO_PAD.encode(sig_raw),
    };

    serde_json::to_vec(&body).map_err(|e| MobileError::Serialization(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use rand_core::OsRng;

    fn make_uri() -> String {
        let endpoint_b64 = URL_SAFE_NO_PAD.encode(b"https://auth.auths.test/v1/auth/sessions");
        format!(
            "auths://auth?id=sess-abc123&c=deadbeef&d=example.com&e={endpoint_b64}"
        )
    }

    #[test]
    fn builder_produces_deterministic_canonical_payload() {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_encoded_point(true);

        let ctx_a =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();
        let ctx_b =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();

        assert_eq!(ctx_a.signing_payload, ctx_b.signing_payload);
        // json_canon emits alphabetized keys, no whitespace.
        assert_eq!(
            std::str::from_utf8(&ctx_a.signing_payload).unwrap(),
            r#"{"domain":"example.com","nonce":"deadbeef"}"#
        );
    }

    #[test]
    fn builder_exposes_session_and_endpoint() {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_encoded_point(true);
        let ctx =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();
        assert_eq!(ctx.session_id(), "sess-abc123");
        assert_eq!(ctx.domain(), "example.com");
        assert_eq!(ctx.nonce(), "deadbeef");
        assert_eq!(ctx.auth_server_url(), "https://auth.auths.test/v1/auth/sessions");
    }

    #[test]
    fn assembler_accepts_valid_raw_signature() {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_encoded_point(true);
        let ctx =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();

        let sig: p256::ecdsa::Signature = sk.sign(&ctx.signing_payload);
        let raw: [u8; 64] = sig.to_bytes().into();

        let body = assemble_auth_challenge_response(ctx, raw.to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["curve"], "p256");
        assert_eq!(parsed["session_id"], "sess-abc123");
        assert_eq!(parsed["domain"], "example.com");
        assert!(parsed["device_did"].as_str().unwrap().starts_with("did:key:zDna"));
    }

    #[test]
    fn assembler_accepts_valid_der_signature() {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_encoded_point(true);
        let ctx =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();

        let sig: p256::ecdsa::Signature = sk.sign(&ctx.signing_payload);
        let der_bytes = sig.to_der().as_bytes().to_vec();

        let body = assemble_auth_challenge_response(ctx, der_bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["curve"], "p256");
    }

    #[test]
    fn assembler_rejects_wrong_message_signature() {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_encoded_point(true);
        let ctx =
            build_auth_challenge_signing_payload(make_uri(), pk.as_bytes().to_vec()).unwrap();

        let sig: p256::ecdsa::Signature = sk.sign(b"unrelated bytes");
        let raw: [u8; 64] = sig.to_bytes().into();

        let err = assemble_auth_challenge_response(ctx, raw.to_vec()).unwrap_err();
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }
}
