//! Signature-injection FFI for KERI delegated inception (`dip`).
//!
//! Mirrors the build/assemble pattern of `identity_context`, but incepts the
//! device as a **delegated identifier** of an existing root identity: the
//! event is a `dip` naming the root as delegator (`di`), self-signed by the
//! device's own key. The initiator (root) anchors it during pairing, which is
//! what makes the phone a true delegated device (`auths device list` shows
//! it) rather than a recorded-but-unanchored gadget.
//!
//! As everywhere in this crate, private key material never crosses the FFI:
//! the caller supplies the device's current + next public keys (Secure
//! Enclave on iOS, StrongBox / TEE on Android), signs the canonical payload
//! externally, and hands the signature back.
//!
//! Unlike the local-only `identity_context` builders, the dip must be
//! anchored and later rotated by the *platform's* validators — so this module
//! builds the real [`auths_keri::DipEvent`] through the platform's own
//! finalize/serialize/commitment functions instead of a local JSON mirror.
//! What the host anchors is byte-identical to what a CLI joiner produces.

use std::sync::Arc;

use p256::ecdsa::signature::Verifier;

use auths_keri::{
    DipEvent, DipEventInit, Event, IndexedSignature, KeriPublicKey, KeriSequence, Prefix, Said,
    Threshold, VersionString, compute_next_commitment, encode_signed_dip, finalize_dip_event,
    serialize_attachment, serialize_for_signing,
};

use crate::MobileError;
use crate::pairing_context::normalize_p256_signature_to_raw_public;

/// Parse a `did:keri:` string (or a bare prefix) into a validated [`Prefix`].
fn parse_delegator_prefix(did: &str) -> Result<Prefix, MobileError> {
    let bare = did.strip_prefix("did:keri:").unwrap_or(did);
    Prefix::new(bare.to_string())
        .map_err(|e| MobileError::InvalidKeyData(format!("delegator did:keri prefix invalid: {e}")))
}

/// Build a transferable P-256 [`KeriPublicKey`] from caller-supplied bytes.
///
/// Accepts the same three forms as every other builder in this crate
/// (33 B compressed SEC1, 65 B uncompressed SEC1, SPKI DER). Transferable
/// (`1AAJ`) because a delegated device's key must be rotatable later.
fn parse_p256_verkey(bytes: &[u8]) -> Result<KeriPublicKey, MobileError> {
    let compressed = crate::pairing_context::normalize_p256_pubkey_to_compressed_public(bytes)?;
    Ok(KeriPublicKey::P256 {
        key: compressed,
        transferable: true,
    })
}

// ---------------------------------------------------------------------------
// Opaque UniFFI Objects round-tripped through the caller
// ---------------------------------------------------------------------------

/// Per-dip state assembled by [`build_p256_delegated_inception_payload`] and
/// consumed by [`assemble_p256_delegated_inception`].
///
/// Opaque (`Arc<T>`) so the canonical signing bytes and the unsigned event
/// cannot be tampered with between the two FFI calls.
#[derive(Debug, uniffi::Object)]
pub struct P256DelegatedInceptionContext {
    /// Canonical bytes the Secure Enclave must sign (the finalized dip
    /// serialized exactly as the wire will carry it).
    signing_payload: Vec<u8>,

    /// The finalized (SAID-computed, unsigned) dip event.
    unsigned_dip: DipEvent,

    /// Device's current P-256 signing pubkey, 33-byte compressed SEC1 —
    /// the key committed in the dip's `k[0]` and the only key whose
    /// signature the assembler accepts.
    device_signing_pubkey_compressed: [u8; 33],
}

#[uniffi::export]
impl P256DelegatedInceptionContext {
    /// The exact bytes the Secure Enclave must sign.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.signing_payload.clone()
    }

    /// The device's delegated KEL prefix (self-addressing — the dip's SAID).
    pub fn prefix(&self) -> String {
        self.unsigned_dip.i.as_str().to_string()
    }

    /// The device's full delegated DID: `did:keri:{prefix}`.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.unsigned_dip.i)
    }

    /// The delegating root's prefix (the dip's `di` field).
    pub fn delegator_prefix(&self) -> String {
        self.unsigned_dip.di.as_str().to_string()
    }
}

/// A device-signed, locally-verified delegated inception, ready for the
/// pairing wire.
///
/// Produced by [`assemble_p256_delegated_inception`]; consumed by
/// [`crate::assemble_pairing_response_body`], which embeds the wire envelope
/// in `responder_inception_event` after cross-checking that the dip's key is
/// the same key that signed the pairing binding (the custody invariant the
/// SAS ceremony proves).
#[derive(Debug, uniffi::Object)]
pub struct SignedDelegatedInception {
    /// The single-string wire form (`auths_keri::encode_signed_dip`).
    wire_envelope: String,

    /// The device's delegated KEL prefix.
    device_prefix: String,

    /// The delegating root's prefix.
    delegator_prefix: String,

    /// The dip's committed signing pubkey (compressed SEC1) — exposed to the
    /// pairing assembler for the same-key cross-check.
    pub(crate) device_signing_pubkey_compressed: [u8; 33],
}

#[uniffi::export]
impl SignedDelegatedInception {
    /// The wire envelope for `responder_inception_event` (base64url JSON of
    /// the signed dip + its CESR attachment).
    pub fn wire_envelope(&self) -> String {
        self.wire_envelope.clone()
    }

    /// The device's delegated KEL prefix.
    pub fn prefix(&self) -> String {
        self.device_prefix.clone()
    }

    /// The device's full delegated DID: `did:keri:{prefix}`.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.device_prefix)
    }

    /// The delegating root's prefix (the dip's `di` field).
    pub fn delegator_prefix(&self) -> String {
        self.delegator_prefix.clone()
    }
}

// ---------------------------------------------------------------------------
// Public FFI surface
// ---------------------------------------------------------------------------

/// Build the signing payload for a delegated inception (`dip`).
///
/// The dip names `delegator_did`'s prefix as delegator (`di`), commits the
/// device's current key in `k[0]` and the next-rotation key in `n[0]`, and is
/// finalized through the platform's own SAID computation — the device's
/// delegated prefix is the dip's SAID.
///
/// Args:
/// * `delegator_did`: The delegating root identity — `did:keri:E…` (as carried
///   in a pairing URI's `d` field) or the bare prefix.
/// * `current_pubkey_der`: Device's current signing pubkey. 33 B compressed
///   SEC1, 65 B uncompressed SEC1, or SPKI DER.
/// * `next_pubkey_der`: Next-rotation commitment pubkey, same formats.
///
/// Usage:
/// ```ignore
/// // iOS Swift
/// let ctx = try buildP256DelegatedInceptionPayload(
///     delegatorDid: pairingCtx.controllerDid(),
///     currentPubkeyDer: deviceKey.publicKeyDER,
///     nextPubkeyDer: deviceKey.nextPublicKeyDER
/// )
/// let sig = try deviceKey.sign(ctx.signingPayload())
/// let dip = try assembleP256DelegatedInception(context: ctx, signature: sig)
/// ```
#[uniffi::export]
pub fn build_p256_delegated_inception_payload(
    delegator_did: String,
    current_pubkey_der: Vec<u8>,
    next_pubkey_der: Vec<u8>,
) -> Result<Arc<P256DelegatedInceptionContext>, MobileError> {
    let delegator = parse_delegator_prefix(&delegator_did)?;
    let current = parse_p256_verkey(&current_pubkey_der)?;
    let next = parse_p256_verkey(&next_pubkey_der)?;

    let current_compressed: [u8; 33] = current
        .as_bytes()
        .try_into()
        .map_err(|_| MobileError::InvalidKeyData("P-256 verkey must be 33 bytes".to_string()))?;
    let current_qb64 = current
        .to_qb64()
        .map_err(|e| MobileError::InvalidKeyData(format!("P-256 verkey CESR encode: {e}")))?;

    let dip = finalize_dip_event(DipEvent::new(DipEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![auths_keri::CesrKey::new_unchecked(current_qb64)],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&next)],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: delegator,
    }))
    .map_err(|e| MobileError::Serialization(format!("dip finalize: {e}")))?;

    let signing_payload = serialize_for_signing(&Event::Dip(dip.clone()))
        .map_err(|e| MobileError::Serialization(format!("dip serialize: {e}")))?;

    Ok(Arc::new(P256DelegatedInceptionContext {
        signing_payload,
        unsigned_dip: dip,
        device_signing_pubkey_compressed: current_compressed,
    }))
}

/// Assemble the device-signed dip into its pairing-wire form.
///
/// The signature is verified locally against the dip's committed key before
/// the envelope is emitted — a Secure-Enclave misconfiguration surfaces at
/// the FFI boundary, not at the anchoring host.
///
/// Args:
/// * `context`: Opaque handle from [`build_p256_delegated_inception_payload`].
/// * `signature`: P-256 ECDSA signature over `signing_payload()`. Accepts
///   X9.62 DER (what iOS SE emits) or raw r‖s (64 bytes).
#[uniffi::export]
pub fn assemble_p256_delegated_inception(
    context: Arc<P256DelegatedInceptionContext>,
    signature: Vec<u8>,
) -> Result<Arc<SignedDelegatedInception>, MobileError> {
    let sig_raw = normalize_p256_signature_to_raw_public(&signature)?;

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&context.device_signing_pubkey_compressed)
        .map_err(|e| MobileError::InvalidKeyData(format!("dip pubkey unusable: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw)
        .map_err(|e| MobileError::InvalidKeyData(format!("P-256 signature parse failed: {e}")))?;
    vk.verify(&context.signing_payload, &sig).map_err(|e| {
        MobileError::PairingFailed(format!(
            "signature does not verify against the dip's committed key — likely SE misconfiguration: {e}"
        ))
    })?;

    let attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig_raw.to_vec(),
    }])
    .map_err(|e| MobileError::Serialization(format!("dip attachment: {e}")))?;

    let wire_envelope = encode_signed_dip(&context.unsigned_dip, &attachment)
        .map_err(|e| MobileError::Serialization(format!("dip envelope: {e}")))?;

    Ok(Arc::new(SignedDelegatedInception {
        wire_envelope,
        device_prefix: context.unsigned_dip.i.as_str().to_string(),
        delegator_prefix: context.unsigned_dip.di.as_str().to_string(),
        device_signing_pubkey_compressed: context.device_signing_pubkey_compressed,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    const DELEGATOR: &str = "did:keri:EHOMEBASEROOTPREFIXxxxxxxxxxxxxxxxxxxxxx90AB";

    fn fresh_p256_key() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut OsRng);
        let compressed = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (sk, compressed)
    }

    #[test]
    fn happy_path_round_trip() {
        let (current_sk, current_pub) = fresh_p256_key();
        let (_next_sk, next_pub) = fresh_p256_key();

        let ctx = build_p256_delegated_inception_payload(DELEGATOR.into(), current_pub, next_pub)
            .unwrap();
        assert!(
            ctx.prefix().starts_with('E'),
            "delegated AID is self-addressing"
        );
        assert_eq!(ctx.did(), format!("did:keri:{}", ctx.prefix()));
        assert_eq!(format!("did:keri:{}", ctx.delegator_prefix()), DELEGATOR);

        let sig: p256::ecdsa::Signature = current_sk.sign(&ctx.signing_payload());
        let signed =
            assemble_p256_delegated_inception(ctx.clone(), sig.to_der().as_bytes().to_vec())
                .unwrap();
        assert_eq!(signed.prefix(), ctx.prefix());

        // The envelope decodes through the SAME platform decoder the anchoring
        // host uses, and the signed bytes verify against the committed key.
        let (dip, attachment) = auths_keri::decode_signed_dip(&signed.wire_envelope()).unwrap();
        assert_eq!(dip.i.as_str(), signed.prefix());
        assert_eq!(format!("did:keri:{}", dip.di), DELEGATOR);
        let sigs = auths_keri::parse_attachment(&attachment).unwrap();
        assert_eq!(sigs.len(), 1);
        let canonical = serialize_for_signing(&Event::Dip(dip.clone())).unwrap();
        let key = dip.k[0].parse().unwrap();
        key.verify_signature(&canonical, &sigs[0].sig)
            .expect("device signature must verify through the platform validator");
    }

    #[test]
    fn dip_commits_transferable_p256_key_and_next_commitment() {
        let (_sk, current_pub) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();

        let ctx = build_p256_delegated_inception_payload(
            DELEGATOR.into(),
            current_pub.clone(),
            next_pub.clone(),
        )
        .unwrap();

        let event: serde_json::Value = serde_json::from_slice(&ctx.signing_payload()).unwrap();
        assert_eq!(event["t"], "dip");
        assert_eq!(event["s"], "0");
        // Transferable P-256 verkey code — the key must be rotatable later.
        assert!(event["k"][0].as_str().unwrap().starts_with("1AAJ"));
        assert!(event["n"][0].as_str().unwrap().starts_with('E'));
        assert_eq!(event["di"], DELEGATOR.trim_start_matches("did:keri:"));

        // Commitment matches the platform's convention (digest of the qb64
        // text), so a future rotation reveal will verify.
        let next_key = parse_p256_verkey(&next_pub).unwrap();
        let expected = compute_next_commitment(&next_key);
        assert_eq!(event["n"][0], expected.as_str());
    }

    #[test]
    fn bare_prefix_delegator_accepted() {
        let (_sk, current_pub) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();
        let bare = DELEGATOR.trim_start_matches("did:keri:");
        let ctx =
            build_p256_delegated_inception_payload(bare.into(), current_pub, next_pub).unwrap();
        assert_eq!(ctx.delegator_prefix(), bare);
    }

    #[test]
    fn invalid_delegator_rejected() {
        let (_sk, current_pub) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();
        let err = build_p256_delegated_inception_payload(
            "did:keri:!!not-a-prefix".into(),
            current_pub,
            next_pub,
        )
        .unwrap_err();
        assert!(matches!(err, MobileError::InvalidKeyData(_)));
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (_current_sk, current_pub) = fresh_p256_key();
        let (attacker_sk, _) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();

        let ctx = build_p256_delegated_inception_payload(DELEGATOR.into(), current_pub, next_pub)
            .unwrap();
        let bad: p256::ecdsa::Signature = attacker_sk.sign(&ctx.signing_payload());
        let err =
            assemble_p256_delegated_inception(ctx, bad.to_der().as_bytes().to_vec()).unwrap_err();
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }

    #[test]
    fn raw_signature_accepted() {
        let (current_sk, current_pub) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();
        let ctx = build_p256_delegated_inception_payload(DELEGATOR.into(), current_pub, next_pub)
            .unwrap();
        let sig: p256::ecdsa::Signature = current_sk.sign(&ctx.signing_payload());
        let raw: [u8; 64] = sig.to_bytes().into();
        let _ = assemble_p256_delegated_inception(ctx, raw.to_vec()).unwrap();
    }

    #[test]
    fn signing_payload_length_matches_version_string() {
        // A spec verifier frames the body by the length in `v` — the signed
        // bytes must be exactly that long.
        let (_sk, current_pub) = fresh_p256_key();
        let (_nsk, next_pub) = fresh_p256_key();
        let ctx = build_p256_delegated_inception_payload(DELEGATOR.into(), current_pub, next_pub)
            .unwrap();
        let payload = ctx.signing_payload();
        let event: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let v = event["v"].as_str().unwrap();
        // KERI10JSON{6 hex digits}_
        let size = usize::from_str_radix(&v["KERI10JSON".len()..v.len() - 1], 16).unwrap();
        assert_eq!(size, payload.len());
    }
}
