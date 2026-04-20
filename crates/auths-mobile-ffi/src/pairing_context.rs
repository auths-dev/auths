//! Signature-injection FFI for the pairing flow.
//!
//! Replaces the legacy `create_pairing_response(uri, pkcs8_hex, device_name)`
//! entry point with a two-step dance that never surfaces private key material
//! in Rust:
//!
//! 1. [`build_pairing_binding_message`] — the caller supplies the device's
//!    public key (as DER-SPKI, 65-byte uncompressed SEC1, or 33-byte compressed
//!    SEC1). The FFI parses the pairing URI, performs the X25519 ECDH with the
//!    controller's ephemeral key, builds the canonical binding message, and
//!    hands back an opaque [`PairingBindingContext`] holding all session state.
//!
//! 2. [`assemble_pairing_response_body`] — the caller hands back the signature
//!    produced by the Secure Enclave (as X9.62 DER *or* raw r‖s). The FFI
//!    verifies the signature locally, then emits the JSON body the app will
//!    `POST` to `/v1/pairing/sessions/{id}/response`.
//!
//! The private key material never crosses the FFI. The SE owns it; Rust only
//! ever sees public keys and signatures.
//!
//! Wire formats (per ADRs 002 / 003):
//! - Pubkey on the wire: 33-byte compressed SEC1. The builder accepts any of
//!   33-byte compressed, 65-byte uncompressed, or SPKI DER on input and
//!   compresses as needed before emitting.
//! - Signature on the wire: raw r‖s (64 bytes). The assembler accepts DER on
//!   input (what `SecKeyCreateSignature` emits) and normalizes.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

use crate::{MobileError, PairingResponsePayload};

// ---------------------------------------------------------------------------
// Opaque UniFFI Object: round-trips through the caller between build+assemble
// ---------------------------------------------------------------------------

/// Per-session state assembled by [`build_pairing_binding_message`] and
/// consumed by [`assemble_pairing_response_body`].
///
/// This is a UniFFI *Object*, not a *Record* — the caller holds an opaque
/// `Arc<PairingBindingContext>` and can never serialize or inspect its
/// internals. Rationale: the ECDH shared secret and the canonical binding
/// bytes must not be tampered with between the two FFI calls, and an opaque
/// handle is the idiomatic UniFFI expression of that constraint.
#[derive(Debug, uniffi::Object)]
pub struct PairingBindingContext {
    /// The exact bytes the Secure Enclave must sign. See
    /// [`Self::binding_message`].
    binding_message: Vec<u8>,

    /// The device's P-256 signing pubkey in compressed SEC1 form (33 B).
    /// Pre-normalized from whatever the caller supplied so the wire body
    /// always carries the canonical form.
    device_signing_pubkey_compressed: Vec<u8>,

    /// The device's freshly-generated X25519 ephemeral pubkey (32 B),
    /// base64url-no-pad-encoded for direct inclusion in the response JSON.
    device_ephemeral_pubkey_b64: String,

    /// Controller DID from the pairing URI.
    controller_did: String,

    /// Registry endpoint URL from the pairing URI.
    endpoint: String,

    /// Pairing short code from the URI (used by the caller to look up
    /// the session ID via `GET /v1/pairing/sessions/by-code/{short_code}`).
    short_code: String,

    /// Capability strings from the pairing URI.
    capabilities: Vec<String>,

    /// ECDH shared secret, hex-encoded. Held inside `Zeroizing` bytes on
    /// the Rust side; the caller receives it as a hex string for parity
    /// with the legacy `PairingResult.shared_secret_hex` field.
    shared_secret_hex: String,
}

#[uniffi::export]
impl PairingBindingContext {
    /// The exact bytes the Secure Enclave must sign.
    ///
    /// Construction (kept stable across curves for wire compatibility):
    /// `binding_message = short_code || initiator_x25519_pubkey || device_x25519_pubkey`
    ///
    /// The SE signs these bytes directly (`SecKeyCreateSignature` with
    /// `.ecdsaSignatureMessageX962SHA256` hashes internally).
    pub fn binding_message(&self) -> Vec<u8> {
        self.binding_message.clone()
    }

    /// Base64url-no-pad-encoded 33-byte compressed SEC1 pubkey — already
    /// in the form `assemble_pairing_response_body` will put on the wire.
    pub fn device_signing_pubkey(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.device_signing_pubkey_compressed)
    }

    /// Controller DID from the QR-encoded pairing URI.
    pub fn controller_did(&self) -> String {
        self.controller_did.clone()
    }

    /// Registry endpoint URL from the pairing URI.
    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    /// Short code from the pairing URI.
    pub fn short_code(&self) -> String {
        self.short_code.clone()
    }

    /// Capability strings requested by the pairing URI.
    pub fn capabilities(&self) -> Vec<String> {
        self.capabilities.clone()
    }

    /// Hex-encoded 32-byte X25519 ECDH shared secret.
    ///
    /// The caller is responsible for treating this as sensitive material —
    /// typically by deriving a transport key via HKDF and then zeroizing the
    /// hex string. The Rust side held the raw bytes in a `Zeroizing` wrapper
    /// between generation and encoding.
    pub fn shared_secret_hex(&self) -> String {
        self.shared_secret_hex.clone()
    }
}

// ---------------------------------------------------------------------------
// Public FFI surface
// ---------------------------------------------------------------------------

/// Build the signing payload for a pairing response.
///
/// Args:
/// * `uri`: The full `auths://pair?...` URI from the QR code.
/// * `device_signing_pubkey_der`: The device's P-256 public key. Accepted
///   forms: 33-byte compressed SEC1, 65-byte uncompressed SEC1 (what iOS
///   `SecKeyCopyExternalRepresentation` returns), or SPKI DER (what
///   `wrapP256RawInSPKI` produces).
///
/// Usage:
/// ```ignore
/// let ctx = build_pairing_binding_message(uri, pubkey_der)?;
/// let to_sign = ctx.binding_message();
/// let signature = secure_enclave.sign(&to_sign)?; // iOS side
/// let body = assemble_pairing_response_body(ctx, signature, device_name)?;
/// ```
#[uniffi::export]
pub fn build_pairing_binding_message(
    uri: String,
    device_signing_pubkey_der: Vec<u8>,
) -> Result<Arc<PairingBindingContext>, MobileError> {
    let fields = crate::parse_token_fields(&uri)?;

    // Expiry check (wall-clock at FFI boundary is acceptable —
    // CLAUDE.md clock rule applies to core/sdk, not FFI).
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| MobileError::PairingFailed(format!("System time error: {e}")))?
        .as_secs() as i64;
    if now_unix > fields.expires_at_unix {
        return Err(MobileError::PairingExpired);
    }

    let device_signing_pubkey_compressed =
        normalize_p256_pubkey_to_compressed(&device_signing_pubkey_der)?;

    // X25519 ephemeral for transport ECDH — separate from the P-256
    // signing key. The phone's P-256 key lives in the SE; the X25519
    // key is session-ephemeral and fine to hold in Rust.
    let device_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let device_x25519_public = X25519PublicKey::from(&device_x25519_secret);

    let initiator_x25519_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&fields.ephemeral_pubkey)
        .map_err(|e| MobileError::PairingFailed(format!("Invalid pubkey encoding: {e}")))?
        .try_into()
        .map_err(|_| MobileError::PairingFailed("Invalid X25519 pubkey length".to_string()))?;
    let initiator_x25519 = X25519PublicKey::from(initiator_x25519_bytes);

    let shared = device_x25519_secret.diffie_hellman(&initiator_x25519);
    let shared_bytes = Zeroizing::new(*shared.as_bytes());
    let shared_secret_hex = hex::encode(*shared_bytes);

    // Binding message format matches the legacy create_pairing_response:
    //   short_code || initiator_x25519 || device_x25519
    let mut binding_message = Vec::with_capacity(
        fields.short_code.len() + 32 + 32,
    );
    binding_message.extend_from_slice(fields.short_code.as_bytes());
    binding_message.extend_from_slice(&initiator_x25519_bytes);
    binding_message.extend_from_slice(device_x25519_public.as_bytes());

    let device_ephemeral_pubkey_b64 = URL_SAFE_NO_PAD.encode(device_x25519_public.as_bytes());

    Ok(Arc::new(PairingBindingContext {
        binding_message,
        device_signing_pubkey_compressed: device_signing_pubkey_compressed.to_vec(),
        device_ephemeral_pubkey_b64,
        controller_did: fields.controller_did,
        endpoint: fields.endpoint,
        short_code: fields.short_code,
        capabilities: fields.capabilities,
        shared_secret_hex,
    }))
}

/// Assemble the final JSON body for `POST /v1/pairing/sessions/{id}/response`.
///
/// Args:
/// * `context`: The opaque handle returned by
///   [`build_pairing_binding_message`].
/// * `signature`: The P-256 ECDSA signature produced by the device (SE). Accepts
///   either X9.62 DER (what `SecKeyCreateSignature` emits) or raw r‖s (64 B).
/// * `device_name`: Friendly name to embed in the response body.
///
/// The signature is verified locally against the stored binding message
/// before the body is emitted — catches mobile-side SE misconfiguration
/// at the FFI boundary rather than at the daemon.
///
/// Usage:
/// ```ignore
/// let body = assemble_pairing_response_body(ctx, sig_der, "iPhone".into())?;
/// http_post(ctx.endpoint(), body).await?;
/// ```
#[uniffi::export]
pub fn assemble_pairing_response_body(
    context: Arc<PairingBindingContext>,
    signature: Vec<u8>,
    device_name: String,
) -> Result<Vec<u8>, MobileError> {
    let sig_raw: [u8; 64] = normalize_p256_signature_to_raw(&signature)?;

    // Local verification — cheap, catches SE misconfiguration before we
    // ship a bad body to the daemon.
    let pubkey_bytes: &[u8] = &context.device_signing_pubkey_compressed;
    let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey_bytes).map_err(|e| {
        MobileError::InvalidKeyData(format!("P-256 pubkey parse failed: {e}"))
    })?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw).map_err(|e| {
        MobileError::PairingFailed(format!("signature parse failed: {e}"))
    })?;
    verifier
        .verify(&context.binding_message, &sig)
        .map_err(|e| {
            MobileError::PairingFailed(format!(
                "signature does not match binding message under supplied pubkey: {e}"
            ))
        })?;

    let device_signing_pubkey_b64 = URL_SAFE_NO_PAD.encode(&context.device_signing_pubkey_compressed);
    let signature_b64 = URL_SAFE_NO_PAD.encode(sig_raw);

    let payload = PairingResponsePayload {
        device_ephemeral_pubkey: context.device_ephemeral_pubkey_b64.clone(),
        device_signing_pubkey: device_signing_pubkey_b64,
        curve: "p256".to_string(),
        device_did: derive_device_did(&context.device_signing_pubkey_compressed)?,
        signature: signature_b64,
        device_name,
    };

    serde_json::to_vec(&payload).map_err(|e| MobileError::Serialization(e.to_string()))
}

// ---------------------------------------------------------------------------
// Wire-format normalization (ADRs 002 / 003)
// ---------------------------------------------------------------------------

/// Accept P-256 pubkeys in any of three forms and emit compressed SEC1 (33 B).
///
/// - 33-byte compressed SEC1: returned as-is after leading-byte sanity check.
/// - 65-byte uncompressed SEC1 (iOS `SecKeyCopyExternalRepresentation`):
///   compressed via `p256::EncodedPoint`.
/// - SPKI DER (iOS `wrapP256RawInSPKI` output): parsed via `pkcs8`, then
///   compressed.
fn normalize_p256_pubkey_to_compressed(bytes: &[u8]) -> Result<[u8; 33], MobileError> {
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    // Fast path: 33-byte compressed with a valid leading byte.
    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        // Validate curve membership — a malformed point must fail here,
        // not silently propagate to the daemon.
        VerifyingKey::from_sec1_bytes(&arr).map_err(|e| {
            MobileError::InvalidKeyData(format!("invalid P-256 compressed pubkey: {e}"))
        })?;
        return Ok(arr);
    }

    // 65-byte uncompressed SEC1 — compress via VerifyingKey round-trip.
    if bytes.len() == 65 && bytes[0] == 0x04 {
        let vk = VerifyingKey::from_sec1_bytes(bytes).map_err(|e| {
            MobileError::InvalidKeyData(format!("invalid P-256 uncompressed pubkey: {e}"))
        })?;
        let compressed = vk.to_encoded_point(true);
        let out: [u8; 33] = compressed.as_bytes().try_into().map_err(|_| {
            MobileError::InvalidKeyData("compressed P-256 point was not 33 bytes".to_string())
        })?;
        return Ok(out);
    }

    // SPKI DER — parse SubjectPublicKeyInfo, compress the underlying point.
    if let Ok(vk) = VerifyingKey::from_public_key_der(bytes) {
        let compressed = vk.to_encoded_point(true);
        let out: [u8; 33] = compressed.as_bytes().try_into().map_err(|_| {
            MobileError::InvalidKeyData("compressed P-256 point was not 33 bytes".to_string())
        })?;
        return Ok(out);
    }

    Err(MobileError::InvalidKeyData(format!(
        "P-256 pubkey must be 33 B compressed, 65 B uncompressed, or SPKI DER; got {} B",
        bytes.len()
    )))
}

/// Accept P-256 signatures in either X9.62 DER or raw r‖s and emit raw (64 B).
///
/// iOS `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` emits
/// DER. CryptoKit `P256.Signing.ECDSASignature.rawRepresentation` emits raw.
/// Per ADR 002 the wire form is raw, so we normalize here.
fn normalize_p256_signature_to_raw(bytes: &[u8]) -> Result<[u8; 64], MobileError> {
    if bytes.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }

    // DER path: fallible parse. Reject anything that isn't a valid
    // ASN.1 SEQUENCE of two INTEGERs.
    let sig = p256::ecdsa::Signature::from_der(bytes).map_err(|e| {
        MobileError::PairingFailed(format!(
            "signature must be 64-byte raw r||s or X9.62 DER: {e}"
        ))
    })?;
    let raw: [u8; 64] = sig.to_bytes().into();
    Ok(raw)
}

/// Derive a `did:key:zDna...` identifier from a compressed P-256 pubkey.
///
/// Uses the multicodec prefix `0x1200` for P-256 public keys per the
/// W3C did:key method specification.
fn derive_device_did(compressed_pubkey: &[u8]) -> Result<String, MobileError> {
    if compressed_pubkey.len() != 33 {
        return Err(MobileError::InvalidKeyData(
            "compressed P-256 pubkey must be 33 bytes".to_string(),
        ));
    }
    // Multicodec p256-pub = 0x1200 (two-byte varint: 0x80 0x24).
    let mut prefixed = Vec::with_capacity(2 + 33);
    prefixed.push(0x80);
    prefixed.push(0x24);
    prefixed.extend_from_slice(compressed_pubkey);
    let mb = bs58::encode(&prefixed).with_alphabet(bs58::Alphabet::BITCOIN).into_string();
    Ok(format!("did:key:z{mb}"))
}

// ---------------------------------------------------------------------------
// Crate-visible aliases so `auth_challenge_context` can reuse the
// normalizers and did:key derivation without making them part of the
// public FFI.
// ---------------------------------------------------------------------------

pub(crate) fn normalize_p256_pubkey_to_compressed_public(
    bytes: &[u8],
) -> Result<[u8; 33], MobileError> {
    normalize_p256_pubkey_to_compressed(bytes)
}

pub(crate) fn normalize_p256_signature_to_raw_public(
    bytes: &[u8],
) -> Result<[u8; 64], MobileError> {
    normalize_p256_signature_to_raw(bytes)
}

pub(crate) fn derive_device_did_public(compressed_pubkey: &[u8]) -> Result<String, MobileError> {
    derive_device_did(compressed_pubkey)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// Minimal valid pairing URI helper.
    fn make_uri(expires_in_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires = now + expires_in_secs;
        let endpoint_b64 = URL_SAFE_NO_PAD.encode(b"https://auths.test");
        let ephemeral = URL_SAFE_NO_PAD.encode([0u8; 32]);
        format!(
            "auths://pair?d=did:keri:EABC&e={endpoint_b64}&k={ephemeral}&sc=AB12CD&x={expires}&c=sign_commit"
        )
    }

    #[test]
    fn builder_normalizes_33_byte_compressed_pubkey() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let compressed = vk.to_encoded_point(true);
        assert_eq!(compressed.as_bytes().len(), 33);

        let ctx = build_pairing_binding_message(make_uri(300), compressed.as_bytes().to_vec())
            .expect("33-byte compressed pubkey must accept");
        assert_eq!(ctx.device_signing_pubkey_compressed.len(), 33);
    }

    #[test]
    fn builder_normalizes_65_byte_uncompressed_pubkey() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        assert_eq!(uncompressed.as_bytes().len(), 65);

        let ctx =
            build_pairing_binding_message(make_uri(300), uncompressed.as_bytes().to_vec())
                .expect("65-byte uncompressed pubkey must accept and compress");
        assert_eq!(ctx.device_signing_pubkey_compressed.len(), 33);
    }

    #[test]
    fn builder_normalizes_spki_der_pubkey() {
        use p256::pkcs8::EncodePublicKey;
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let spki = vk.to_public_key_der().unwrap();

        let ctx = build_pairing_binding_message(make_uri(300), spki.as_bytes().to_vec())
            .expect("SPKI DER pubkey must accept and compress");
        assert_eq!(ctx.device_signing_pubkey_compressed.len(), 33);
    }

    #[test]
    fn builder_rejects_invalid_pubkey_length() {
        let err = build_pairing_binding_message(make_uri(300), vec![0u8; 17]).unwrap_err();
        assert!(
            matches!(err, MobileError::InvalidKeyData(_)),
            "expected InvalidKeyData, got {err:?}"
        );
    }

    #[test]
    fn builder_rejects_expired_uri() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let err =
            build_pairing_binding_message(make_uri(-60), compressed.as_bytes().to_vec()).unwrap_err();
        assert!(matches!(err, MobileError::PairingExpired));
    }

    #[test]
    fn assembler_accepts_raw_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let ctx = build_pairing_binding_message(make_uri(300), compressed.as_bytes().to_vec())
            .unwrap();

        let sig: p256::ecdsa::Signature = signing_key.sign(&ctx.binding_message);
        let raw: [u8; 64] = sig.to_bytes().into();

        let body =
            assemble_pairing_response_body(ctx, raw.to_vec(), "iPhone-15".into()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["curve"], "p256");
        assert_eq!(parsed["device_name"], "iPhone-15");
        assert!(parsed["device_did"].as_str().unwrap().starts_with("did:key:zDna"));
    }

    #[test]
    fn assembler_accepts_der_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let ctx = build_pairing_binding_message(make_uri(300), compressed.as_bytes().to_vec())
            .unwrap();

        let sig: p256::ecdsa::Signature = signing_key.sign(&ctx.binding_message);
        let der_bytes = sig.to_der().as_bytes().to_vec();
        assert_ne!(der_bytes.len(), 64, "DER encoding must not be raw 64B");

        let body =
            assemble_pairing_response_body(ctx, der_bytes, "iPhone-15".into()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["curve"], "p256");
    }

    #[test]
    fn assembler_rejects_wrong_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let vk = signing_key.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let ctx = build_pairing_binding_message(make_uri(300), compressed.as_bytes().to_vec())
            .unwrap();

        // Sign a *different* message with the same key — valid signature
        // but not over the stored binding message.
        let wrong_sig: p256::ecdsa::Signature = signing_key.sign(b"totally different bytes");
        let raw: [u8; 64] = wrong_sig.to_bytes().into();

        let err = assemble_pairing_response_body(ctx, raw.to_vec(), "iPhone".into())
            .expect_err("wrong-message signature must be rejected");
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }

    #[test]
    fn assembler_rejects_signature_under_different_key() {
        let key_a = SigningKey::random(&mut OsRng);
        let key_b = SigningKey::random(&mut OsRng);
        let compressed_a = key_a.verifying_key().to_encoded_point(true);
        let ctx = build_pairing_binding_message(make_uri(300), compressed_a.as_bytes().to_vec())
            .unwrap();

        // Sign with key_b; assembler expects sig under key_a.
        let sig: p256::ecdsa::Signature = key_b.sign(&ctx.binding_message);
        let raw: [u8; 64] = sig.to_bytes().into();

        let err = assemble_pairing_response_body(ctx, raw.to_vec(), "iPhone".into())
            .expect_err("signature under wrong key must be rejected");
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }

    #[test]
    fn builder_context_exposes_uri_fields() {
        let signing_key = SigningKey::random(&mut OsRng);
        let compressed = signing_key.verifying_key().to_encoded_point(true);
        let ctx = build_pairing_binding_message(make_uri(300), compressed.as_bytes().to_vec())
            .unwrap();
        assert_eq!(ctx.controller_did(), "did:keri:EABC");
        assert_eq!(ctx.endpoint(), "https://auths.test");
        assert_eq!(ctx.short_code(), "AB12CD");
        assert_eq!(ctx.capabilities(), vec!["sign_commit".to_string()]);
        assert_eq!(ctx.shared_secret_hex().len(), 64);
    }
}
