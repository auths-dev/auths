//! Signature-injection FFI for KERI identity creation.
//!
//! Mirrors the pattern established by the pairing / auth-challenge flows:
//! private key material never crosses the FFI. The caller supplies the
//! device's P-256 current + next public keys (from the Secure Enclave
//! on iOS; from StrongBox / TEE on Android), we build the unsigned
//! inception event, they sign it externally, and we assemble the
//! final JSON wire body.
//!
//! Wire formats (per ADRs 002 / 003):
//! - Pubkeys on input: 33-byte compressed SEC1, 65-byte uncompressed
//!   SEC1, or SPKI DER. Normalized to 33-byte compressed before use.
//! - Signature on input: X9.62 DER (what `SecKeyCreateSignature` emits)
//!   or raw 64-byte r‖s (what CryptoKit's `rawRepresentation` emits).
//!   Normalized to raw before embedding in the inception event.
//!
//! KERI notes:
//! - Key derivation code is `1AAI` (P-256 verkey, per CESR spec and
//!   `auths_keri::KeriPublicKey`). NOT `D` (Ed25519) and NOT `1AAJ`
//!   (that's the P-256 *signature* code, a common confusion).
//! - Next-key commitment is `E` + base64url-no-pad(Blake3-256(next_pubkey
//!   compressed SEC1 bytes)). Matches the convention used by the legacy
//!   Ed25519 flow.
//! - Signature is embedded in the event's `x` field as
//!   base64url-no-pad(raw_r_s). The validator dispatches on `k[0]`'s
//!   derivation code, so P-256 verification uses
//!   `p256::ecdsa::Signature::from_slice` (raw r‖s).

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;

use crate::{IcpEvent, IdentityResult, KERI_VERSION, MobileError, compute_next_commitment};

// ---------------------------------------------------------------------------
// Opaque UniFFI Object round-tripped between build+assemble
// ---------------------------------------------------------------------------

/// Per-identity state assembled by [`build_p256_identity_inception_payload`]
/// and consumed by [`assemble_p256_identity`].
///
/// Held across two FFI calls as an opaque `Arc<T>` so neither the caller
/// nor any intermediate code can tamper with the canonical signing
/// bytes between them.
#[derive(Debug, uniffi::Object)]
pub struct P256IdentityInceptionContext {
    /// Canonical bytes the caller must sign (the ICP event with `x=""`
    /// serialized via `serde_json`).
    signing_payload: Vec<u8>,

    /// The unsigned ICP event with SAID already computed. The assembler
    /// clones this, stamps the signature into `x`, and serializes for
    /// the wire.
    unsigned_event: IcpEvent,

    /// Current P-256 signing pubkey, 33-byte compressed SEC1.
    current_pubkey_compressed: [u8; 33],

    /// KERI prefix (self-addressing identifier derived from the ICP).
    prefix: String,
}

#[uniffi::export]
impl P256IdentityInceptionContext {
    /// The exact bytes the Secure Enclave must sign.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.signing_payload.clone()
    }

    /// KERI prefix for the identity being created. Same bytes as `did`
    /// minus the `did:keri:` scheme.
    pub fn prefix(&self) -> String {
        self.prefix.clone()
    }

    /// Full DID string, for UI display and for binding the pairing /
    /// auth flows to the newly-minted identity.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix)
    }

    /// Base64url-no-pad-encoded 33-byte compressed SEC1 pubkey — the
    /// exact form the inception event commits in `k[0]`.
    pub fn current_pubkey_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.current_pubkey_compressed)
    }
}

// ---------------------------------------------------------------------------
// Public FFI entries
// ---------------------------------------------------------------------------

/// Build the signing payload for a fresh P-256 KERI identity inception.
///
/// Accepts both the current and next-rotation public keys. Both live in
/// the Secure Enclave; the mobile side hands us just their bytes. The
/// `next_pubkey_der` commitment lets the identity rotate later without
/// exposing any private key material.
///
/// Args:
/// * `current_pubkey_der`: Current signing pubkey. 33 B compressed SEC1,
///   65 B uncompressed SEC1, or SPKI DER. The wire form is always
///   compressed.
/// * `next_pubkey_der`: Next-rotation commitment pubkey, same formats.
///
/// Usage:
/// ```ignore
/// // iOS Swift
/// let currentDER = try deviceDIDBootstrap.publicKeyDER()
/// let nextDER    = try inceptionNext.publicKeyDER()
/// let ctx = try buildP256IdentityInceptionPayload(
///     currentPubkeyDer: currentDER,
///     nextPubkeyDer: nextDER
/// )
/// let sig = try deviceDIDBootstrap.sign(ctx.signingPayload(), prompt: "Create identity")
/// let result = try assembleP256Identity(context: ctx, signature: sig, deviceName: "iPhone")
/// ```
#[uniffi::export]
pub fn build_p256_identity_inception_payload(
    current_pubkey_der: Vec<u8>,
    next_pubkey_der: Vec<u8>,
) -> Result<Arc<P256IdentityInceptionContext>, MobileError> {
    let current = normalize_p256_pubkey_to_compressed(&current_pubkey_der)?;
    let next = normalize_p256_pubkey_to_compressed(&next_pubkey_der)?;

    // `1AAI` is the CESR derivation-code prefix for P-256 verkeys. Do
    // NOT use `1AAJ` — that's the signature code and the parser rejects
    // it in key fields.
    let current_pub_encoded = format!("1AAI{}", URL_SAFE_NO_PAD.encode(current));
    let next_commitment = compute_next_commitment(&next);

    let icp = IcpEvent {
        t: "icp".to_string(),
        v: KERI_VERSION.to_string(),
        d: String::new(),
        i: String::new(),
        s: "0".to_string(),
        kt: "1".to_string(),
        k: vec![current_pub_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let finalized = crate::finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();
    let signing_payload = crate::serialize_for_signing(&finalized)?;

    Ok(Arc::new(P256IdentityInceptionContext {
        signing_payload,
        unsigned_event: finalized,
        current_pubkey_compressed: current,
        prefix,
    }))
}

/// Assemble the final signed identity inception event.
///
/// The caller supplies the P-256 ECDSA signature produced over
/// [`P256IdentityInceptionContext::signing_payload`]. The signature is
/// verified locally against `current_pubkey_compressed` before the
/// event is emitted — a mobile-side SE misconfiguration therefore
/// surfaces at the FFI boundary, not at the registry.
///
/// Args:
/// * `context`: Opaque handle from `build_p256_identity_inception_payload`.
/// * `signature`: P-256 ECDSA signature. Accepts X9.62 DER (what iOS SE
///   emits) or raw r‖s (64 bytes).
/// * `device_name`: Friendly label, stored on the returned `IdentityResult`
///   for display-only purposes.
///
/// Returns the ready-to-store `IdentityResult`. `inception_event_json`
/// should be POSTed to the registry at `/v1/identities/{prefix}/kel`.
#[uniffi::export]
pub fn assemble_p256_identity(
    context: Arc<P256IdentityInceptionContext>,
    signature: Vec<u8>,
    device_name: String,
) -> Result<IdentityResult, MobileError> {
    let sig_raw = normalize_p256_signature_to_raw(&signature)?;

    // Verify the signature locally — catches wrong-key / wrong-context
    // bugs at the FFI, not at the registry.
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&context.current_pubkey_compressed)
        .map_err(|e| MobileError::InvalidKeyData(format!("current pubkey unusable: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw).map_err(|e| {
        MobileError::InvalidKeyData(format!("P-256 signature parse failed: {e}"))
    })?;
    vk.verify(&context.signing_payload, &sig).map_err(|e| {
        MobileError::KeyGeneration(format!(
            "signature does not verify against committed pubkey — likely SE misconfiguration: {e}"
        ))
    })?;

    // Stamp the signature into the final event and serialize.
    let mut finalized = context.unsigned_event.clone();
    finalized.x = URL_SAFE_NO_PAD.encode(sig_raw);

    let inception_event_json = serde_json::to_string(&finalized)
        .map_err(|e| MobileError::Serialization(e.to_string()))?;

    Ok(IdentityResult {
        prefix: context.prefix.clone(),
        did: format!("did:keri:{}", context.prefix),
        device_name,
        inception_event_json,
    })
}

// ---------------------------------------------------------------------------
// Wire-format normalization (dup of helpers in pairing_context; kept local
// so identity creation can live without cross-module coupling on those
// internals. A later refactor can lift them into a shared module.)
// ---------------------------------------------------------------------------

fn normalize_p256_pubkey_to_compressed(bytes: &[u8]) -> Result<[u8; 33], MobileError> {
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        VerifyingKey::from_sec1_bytes(&arr).map_err(|e| {
            MobileError::InvalidKeyData(format!("invalid P-256 compressed pubkey: {e}"))
        })?;
        return Ok(arr);
    }

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

fn normalize_p256_signature_to_raw(bytes: &[u8]) -> Result<[u8; 64], MobileError> {
    if bytes.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }
    let sig = p256::ecdsa::Signature::from_der(bytes).map_err(|e| {
        MobileError::InvalidKeyData(format!(
            "signature must be 64-byte raw r||s or X9.62 DER: {e}"
        ))
    })?;
    let raw: [u8; 64] = sig.to_bytes().into();
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// Generate a fresh P-256 signing key and return (SigningKey, compressed SEC1 bytes).
    fn fresh_p256_key() -> (SigningKey, Vec<u8>) {
        use p256::elliptic_curve::rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true).as_bytes().to_vec();
        (sk, compressed)
    }

    #[test]
    fn happy_path_round_trip() {
        let (current_sk, current_pub) = fresh_p256_key();
        let (_next_sk, next_pub) = fresh_p256_key();

        let ctx = build_p256_identity_inception_payload(current_pub.clone(), next_pub).unwrap();
        assert!(ctx.prefix().starts_with('E'));
        assert!(ctx.did().starts_with("did:keri:E"));

        let payload = ctx.signing_payload();
        let sig: p256::ecdsa::Signature = current_sk.sign(&payload);

        let result = assemble_p256_identity(ctx, sig.to_der().as_bytes().to_vec(), "iPhone".into())
            .unwrap();

        assert!(result.prefix.starts_with('E'));
        assert_eq!(result.did, format!("did:keri:{}", result.prefix));
        assert_eq!(result.device_name, "iPhone");

        // Event parses as JSON, has the P-256 derivation code, has a signature.
        let event: serde_json::Value = serde_json::from_str(&result.inception_event_json).unwrap();
        assert_eq!(event["t"], "icp");
        assert_eq!(event["v"], KERI_VERSION);
        assert_eq!(event["s"], "0");
        assert!(event["k"][0].as_str().unwrap().starts_with("1AAI"));
        assert!(event["n"][0].as_str().unwrap().starts_with('E'));
        let sig_b64 = event["x"].as_str().unwrap();
        assert!(!sig_b64.is_empty());
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        assert_eq!(sig_bytes.len(), 64, "wire signature must be raw 64-byte r||s");
    }

    #[test]
    fn raw_signature_accepted() {
        let (current_sk, current_pub) = fresh_p256_key();
        let (_next_sk, next_pub) = fresh_p256_key();

        let ctx = build_p256_identity_inception_payload(current_pub, next_pub).unwrap();
        let sig: p256::ecdsa::Signature = current_sk.sign(&ctx.signing_payload());
        let raw: [u8; 64] = sig.to_bytes().into();

        let _ = assemble_p256_identity(ctx, raw.to_vec(), "Device".into()).unwrap();
    }

    #[test]
    fn uncompressed_pubkey_accepted_and_compressed_in_k() {
        let (current_sk, current_compressed) = fresh_p256_key();
        let (_next_sk, next_compressed) = fresh_p256_key();

        // Build the uncompressed form for `current`.
        let vk = current_sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(uncompressed.len(), 65);

        let ctx = build_p256_identity_inception_payload(uncompressed, next_compressed).unwrap();
        // The k[0] entry is base64url-no-pad of the COMPRESSED form.
        let expected_b64 = URL_SAFE_NO_PAD.encode(&current_compressed);
        assert_eq!(ctx.current_pubkey_b64(), expected_b64);
    }

    #[test]
    fn wrong_signature_rejected() {
        let (_current_sk, current_pub) = fresh_p256_key();
        let (attacker_sk, _) = fresh_p256_key();
        let (_next_sk, next_pub) = fresh_p256_key();

        let ctx = build_p256_identity_inception_payload(current_pub, next_pub).unwrap();
        // Sign with a DIFFERENT key — signature will fail local verification.
        let bad_sig: p256::ecdsa::Signature = attacker_sk.sign(&ctx.signing_payload());

        let result = assemble_p256_identity(ctx, bad_sig.to_der().as_bytes().to_vec(), "X".into());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_pubkey_length_rejected() {
        let (_sk, _) = fresh_p256_key();
        let err = build_p256_identity_inception_payload(vec![0x00; 40], vec![0x00; 33]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("P-256 pubkey"));
    }

    #[test]
    fn distinct_identities_have_distinct_prefixes() {
        let (sk_a, pub_a) = fresh_p256_key();
        let (_next_a_sk, next_a) = fresh_p256_key();
        let (sk_b, pub_b) = fresh_p256_key();
        let (_next_b_sk, next_b) = fresh_p256_key();

        let ctx_a = build_p256_identity_inception_payload(pub_a, next_a).unwrap();
        let ctx_b = build_p256_identity_inception_payload(pub_b, next_b).unwrap();
        let sig_a: p256::ecdsa::Signature = sk_a.sign(&ctx_a.signing_payload());
        let sig_b: p256::ecdsa::Signature = sk_b.sign(&ctx_b.signing_payload());

        let prefix_a = ctx_a.prefix();
        let prefix_b = ctx_b.prefix();
        let _ = assemble_p256_identity(ctx_a, sig_a.to_der().as_bytes().to_vec(), "A".into()).unwrap();
        let _ = assemble_p256_identity(ctx_b, sig_b.to_der().as_bytes().to_vec(), "B".into()).unwrap();

        assert_ne!(prefix_a, prefix_b);
    }
}
