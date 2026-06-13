//! Signature-injection FFI for co-authoring shared-KEL rotations from a
//! device whose key lives in the Secure Enclave.
//!
//! Two-step authorship pattern mirrors `identity_context.rs`:
//!
//! 1. `build_shared_kel_rot_payload(...)` parses the prior key state,
//!    verifies the caller's revealed pre-committed key against its prior
//!    `n[]` slot, applies the requested controller change, and finalizes a
//!    real [`auths_keri::RotEvent`] through the platform's own SAID
//!    machinery — returning the exact canonical bytes the SE must sign.
//! 2. The iOS/macOS side calls `SecKeyCreateSignature` with the caller's
//!    biometric-gated key.
//! 3. `assemble_shared_kel_rot_indexed(ctx, signature)` verifies the
//!    signature, wraps it in a CESR [`IndexedSignature`] carrying both the
//!    signer's new key index and the prior next-commitment index it reveals
//!    (the dual-index siger the validator binds shrink rotations with),
//!    re-validates the whole signed event through
//!    [`auths_keri::validate_signed_event`], and emits the single-string
//!    wire envelope ([`auths_keri::encode_signed_rot`]) ready to POST to
//!    the daemon's shared-rot endpoint.
//!
//! As everywhere in this crate, private key material never crosses the FFI:
//! the caller supplies public keys, signs externally, and hands the
//! signature back.
//!
//! Threshold note: the assembler emits only events the platform validator
//! accepts with the single signature it holds. Under the current `kt=1`
//! shared-KEL model that is exactly one co-author; a future `kt≥2` state
//! makes the assemble step fail loudly rather than emit an under-signed
//! rotation for someone else to "fix up".

use std::sync::Arc;

use p256::ecdsa::signature::Verifier;

use auths_keri::{
    CesrKey, Event, IndexedSignature, KeriPublicKey, KeriSequence, KeyState, RotEvent,
    RotEventInit, Said, SignedEvent, VersionString, compute_next_commitment, encode_signed_rot,
    finalize_rot_event, serialize_attachment, serialize_for_signing, validate_signed_event,
    verify_commitment,
};

use crate::MobileError;
use crate::pairing_context::{
    normalize_p256_pubkey_to_compressed_public, normalize_p256_signature_to_raw_public,
};

/// Build a transferable P-256 [`KeriPublicKey`] from caller-supplied bytes.
///
/// Accepts the same three forms as every other builder in this crate
/// (33 B compressed SEC1, 65 B uncompressed SEC1, SPKI DER). Transferable
/// (`1AAJ`) because a shared-KEL controller must be rotatable — its next
/// key is committed in `n[]`, which is meaningless for a non-transferable
/// key.
fn parse_p256_verkey(bytes: &[u8]) -> Result<KeriPublicKey, MobileError> {
    let compressed = normalize_p256_pubkey_to_compressed_public(bytes)?;
    Ok(KeriPublicKey::P256 {
        key: compressed,
        transferable: true,
    })
}

/// CESR-encode a verkey for a `k[]` slot.
fn verkey_to_cesr(key: &KeriPublicKey) -> Result<CesrKey, MobileError> {
    key.to_qb64()
        .map(CesrKey::new_unchecked)
        .map_err(|e| MobileError::InvalidKeyData(format!("verkey CESR encode: {e}")))
}

/// Find the `k[]` slot holding `compressed`, comparing decoded key bytes
/// (curve/transferability-agnostic — a controller is its key, not its
/// CESR spelling).
fn slot_of_key(keys: &[CesrKey], compressed: &[u8; 33]) -> Option<usize> {
    keys.iter().position(|k| {
        k.parse()
            .is_ok_and(|pk| pk.as_bytes() == compressed.as_slice())
    })
}

/// Controller-set change co-authored by this device.
///
/// Controllers are identified by their *current* verkey bytes (the shared
/// KEL's `k[]` holds keys, not names); the builder resolves them to slots
/// internally — slot indices shift across rotations and would be a footgun
/// in a public API.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SharedKelChangeRequest {
    /// Add a new controller: its current verkey plus the next-rotation key
    /// whose digest becomes the new controller's `n[]` commitment.
    AddController {
        /// New controller's current P-256 pubkey (compressed/uncompressed
        /// SEC1 or SPKI DER).
        new_verkey_der: Vec<u8>,
        /// New controller's next-rotation pubkey, same formats.
        new_next_verkey_der: Vec<u8>,
    },
    /// Remove the controller whose current verkey matches. The authoring
    /// device cannot remove itself (the rotation's signer must survive to
    /// authorize it).
    RemoveController {
        /// Target controller's current P-256 pubkey.
        target_verkey_der: Vec<u8>,
    },
    /// Stolen-laptop recovery: atomically replace one controller with
    /// another in a single rotation — a verifier never observes an
    /// intermediate state with fewer controllers.
    SwapController {
        /// Outgoing controller's current P-256 pubkey.
        old_verkey_der: Vec<u8>,
        /// Replacement controller's current P-256 pubkey.
        new_verkey_der: Vec<u8>,
        /// Replacement controller's next-rotation pubkey.
        new_next_verkey_der: Vec<u8>,
    },
}

/// Opaque handle from [`build_shared_kel_rot_payload`], consumed by
/// [`assemble_shared_kel_rot_indexed`]. The canonical signing bytes, the
/// finalized unsigned event, and the prior state used for final validation
/// live here so nothing between the two FFI calls can mutate them.
#[derive(Debug, uniffi::Object)]
pub struct P256SharedKelRotationContext {
    /// Exact canonical bytes the SE must sign (the finalized rot serialized
    /// exactly as the wire carries it).
    signing_payload: Vec<u8>,
    /// The finalized (SAID-computed, unsigned) rot event.
    unsigned_rot: RotEvent,
    /// Prior key state — re-used by the assemble step to run the full
    /// platform validation before the envelope leaves the FFI.
    prior_state: KeyState,
    /// The revealed pre-committed key the SE signs with, 33-byte compressed
    /// SEC1 — the only key whose signature the assembler accepts.
    revealed_pubkey_compressed: [u8; 33],
    /// The signer's slot in the NEW `k[]`.
    signer_index: u32,
    /// The prior `n[]` slot the signer's key reveals (the dual-index ondex).
    signer_prior_index: u32,
    /// Sequence of the rotation event (prior + 1), pre-narrowed to u64.
    new_sequence: u64,
}

#[uniffi::export]
impl P256SharedKelRotationContext {
    /// The exact bytes the Secure Enclave must sign.
    pub fn signing_payload(&self) -> Vec<u8> {
        self.signing_payload.clone()
    }

    /// The shared KEL's identity DID (stable across rotations).
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.unsigned_rot.i)
    }

    /// Sequence number of the rot being built (prior + 1).
    pub fn new_sequence(&self) -> u64 {
        self.new_sequence
    }

    /// The signer's slot in the rotation's new key list.
    pub fn signer_index(&self) -> u32 {
        self.signer_index
    }

    /// The prior next-commitment slot the signer's key reveals.
    pub fn signer_prior_index(&self) -> u32 {
        self.signer_prior_index
    }
}

/// A finalized, locally-validated, indexed-signature shared-KEL rotation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SharedKelRotIndexedResult {
    /// Single-string wire form (`auths_keri::encode_signed_rot`) — the
    /// blob the app POSTs to the daemon's shared-rot endpoint.
    pub wire_envelope: String,
    /// The shared KEL's identity DID.
    pub did: String,
    /// Sequence number of this rotation event.
    pub sequence: u64,
    /// SAID (`d`) of the rotation event.
    pub event_said: String,
    /// The signer's slot in the new key list.
    pub signer_index: u32,
    /// The prior `n[]` slot the signer revealed (dual-index ondex).
    pub signer_prior_index: u32,
}

/// Build the canonical signing payload for a co-authored shared-KEL `rot`.
///
/// The caller proves controllership by *revealing* its pre-committed next
/// key: the builder locates the prior `n[]` slot whose digest the revealed
/// key matches ([`MobileError::CommitmentMismatch`] if none), rotates that
/// slot to the revealed key with a fresh next-commitment, applies the
/// requested controller change to the remaining slots, and finalizes the
/// event through the platform's own SAID computation.
///
/// Args:
/// * `prior_key_state_json`: The shared KEL's current key state — the JSON
///   serialization of the platform's [`auths_keri::KeyState`] (what the
///   host computes by replaying the KEL). Parsed, not re-modeled.
/// * `change`: The controller-set change being co-authored.
/// * `revealed_next_pubkey_der`: The caller's pre-committed next pubkey,
///   now revealed — the key that signs this rotation per KERI.
/// * `new_next_pubkey_der`: Fresh pubkey whose digest becomes the caller's
///   new `n[]` commitment.
///
/// Usage:
/// ```ignore
/// // iOS Swift
/// let ctx = try buildSharedKelRotPayload(
///     priorKeyStateJson: stateJson,
///     change: .swapController(oldVerkeyDer: lostMacKey, newVerkeyDer: newMacKey,
///                             newNextVerkeyDer: newMacNextKey),
///     revealedNextPubkeyDer: preCommitted.publicKeyDER,
///     newNextPubkeyDer: freshSEKey.publicKeyDER
/// )
/// let sig = try preCommitted.sign(ctx.signingPayload(), prompt: "Rotate identity")
/// let rot = try assembleSharedKelRotIndexed(context: ctx, signature: sig)
/// ```
#[uniffi::export]
pub fn build_shared_kel_rot_payload(
    prior_key_state_json: String,
    change: SharedKelChangeRequest,
    revealed_next_pubkey_der: Vec<u8>,
    new_next_pubkey_der: Vec<u8>,
) -> Result<Arc<P256SharedKelRotationContext>, MobileError> {
    let state: KeyState = serde_json::from_str(&prior_key_state_json)
        .map_err(|e| MobileError::Serialization(format!("prior key state parse: {e}")))?;

    if !state.can_rotate() {
        return Err(MobileError::PairingFailed(
            "shared KEL cannot rotate (abandoned or non-transferable)".into(),
        ));
    }
    if state.current_keys.len() != state.next_commitment.len() {
        return Err(MobileError::Serialization(format!(
            "prior key state is not slot-parallel: {} current keys vs {} next commitments",
            state.current_keys.len(),
            state.next_commitment.len()
        )));
    }

    let revealed = parse_p256_verkey(&revealed_next_pubkey_der)?;
    let revealed_compressed = normalize_p256_pubkey_to_compressed_public(&revealed_next_pubkey_der)?;
    let new_next = parse_p256_verkey(&new_next_pubkey_der)?;

    // The caller's controllership proof: its revealed key must be the
    // pre-image of exactly one prior next-commitment slot.
    let signer_slot = state
        .next_commitment
        .iter()
        .position(|c| verify_commitment(&revealed, c))
        .ok_or_else(|| {
            MobileError::CommitmentMismatch(
                "revealed key matches no prior next-commitment slot — this device is not a \
                 committed controller of this shared KEL"
                    .into(),
            )
        })?;

    // Per-slot view of the new establishment state: the signer's slot
    // rotates to its revealed key + fresh commitment; every other slot
    // carries forward.
    let mut slots: Vec<(CesrKey, Said)> = state
        .current_keys
        .iter()
        .cloned()
        .zip(state.next_commitment.iter().cloned())
        .collect();
    slots[signer_slot] = (verkey_to_cesr(&revealed)?, compute_next_commitment(&new_next));

    let mut signer_index = signer_slot;
    match &change {
        SharedKelChangeRequest::AddController {
            new_verkey_der,
            new_next_verkey_der,
        } => {
            let new_key = parse_p256_verkey(new_verkey_der)?;
            let new_key_compressed = normalize_p256_pubkey_to_compressed_public(new_verkey_der)?;
            if slot_of_key(&state.current_keys, &new_key_compressed).is_some() {
                return Err(MobileError::PairingFailed(
                    "controller to add is already in the shared KEL".into(),
                ));
            }
            let new_key_next = parse_p256_verkey(new_next_verkey_der)?;
            slots.push((verkey_to_cesr(&new_key)?, compute_next_commitment(&new_key_next)));
        }
        SharedKelChangeRequest::RemoveController { target_verkey_der } => {
            let target_compressed = normalize_p256_pubkey_to_compressed_public(target_verkey_der)?;
            let target_slot = slot_of_key(&state.current_keys, &target_compressed)
                .ok_or_else(|| {
                    MobileError::PairingFailed(
                        "controller to remove is not in the shared KEL".into(),
                    )
                })?;
            if target_slot == signer_slot {
                return Err(MobileError::PairingFailed(
                    "the authoring device cannot remove itself — the rotation's signer must \
                     survive to authorize it"
                        .into(),
                ));
            }
            slots.remove(target_slot);
            if target_slot < signer_slot {
                signer_index -= 1;
            }
        }
        SharedKelChangeRequest::SwapController {
            old_verkey_der,
            new_verkey_der,
            new_next_verkey_der,
        } => {
            let old_compressed = normalize_p256_pubkey_to_compressed_public(old_verkey_der)?;
            let old_slot = slot_of_key(&state.current_keys, &old_compressed).ok_or_else(|| {
                MobileError::PairingFailed("controller to swap out is not in the shared KEL".into())
            })?;
            if old_slot == signer_slot {
                return Err(MobileError::PairingFailed(
                    "the authoring device cannot swap itself out — rotate your own key with a \
                     plain rotation instead"
                        .into(),
                ));
            }
            let new_key = parse_p256_verkey(new_verkey_der)?;
            let new_key_next = parse_p256_verkey(new_next_verkey_der)?;
            slots[old_slot] = (verkey_to_cesr(&new_key)?, compute_next_commitment(&new_key_next));
        }
    }

    let (k, n): (Vec<CesrKey>, Vec<Said>) = slots.into_iter().unzip();

    let new_sequence_u128 = state.sequence.checked_add(1).ok_or_else(|| {
        MobileError::Serialization("shared-KEL sequence overflow".to_string())
    })?;
    let new_sequence = u64::try_from(new_sequence_u128)
        .map_err(|_| MobileError::Serialization("shared-KEL sequence exceeds u64".to_string()))?;

    let rot = finalize_rot_event(RotEvent::new(RotEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: state.prefix.clone(),
        s: KeriSequence::new(new_sequence_u128),
        p: state.last_event_said.clone(),
        kt: state.threshold.clone(),
        k,
        nt: state.next_threshold.clone(),
        n,
        bt: state.backer_threshold.clone(),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    }))
    .map_err(|e| MobileError::Serialization(format!("rot finalize: {e}")))?;

    let signing_payload = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| MobileError::Serialization(format!("rot serialize: {e}")))?;

    let signer_index = u32::try_from(signer_index)
        .map_err(|_| MobileError::Serialization("controller slot exceeds u32".to_string()))?;
    let signer_prior_index = u32::try_from(signer_slot)
        .map_err(|_| MobileError::Serialization("controller slot exceeds u32".to_string()))?;

    Ok(Arc::new(P256SharedKelRotationContext {
        signing_payload,
        unsigned_rot: rot,
        prior_state: state,
        revealed_pubkey_compressed: revealed_compressed,
        signer_index,
        signer_prior_index,
        new_sequence,
    }))
}

/// Assemble the signed, indexed shared-KEL rotation into its wire form.
///
/// Verifies the SE signature against the revealed key, binds it into a
/// dual-index CESR [`IndexedSignature`] (new-key index + revealed prior
/// `n[]` index), and — before anything leaves the FFI — replays the whole
/// signed event through the platform validator against the prior state.
/// An event this function returns is, by construction, one the daemon and
/// the host-side replay will accept.
///
/// Args:
/// * `context`: Handle from [`build_shared_kel_rot_payload`].
/// * `signature`: SE signature over `signing_payload()`. Accepts X9.62 DER
///   (what iOS SE emits) or raw r‖s (64 bytes).
#[uniffi::export]
pub fn assemble_shared_kel_rot_indexed(
    context: Arc<P256SharedKelRotationContext>,
    signature: Vec<u8>,
) -> Result<SharedKelRotIndexedResult, MobileError> {
    let sig_raw = normalize_p256_signature_to_raw_public(&signature)?;

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&context.revealed_pubkey_compressed)
        .map_err(|e| MobileError::InvalidKeyData(format!("revealed pubkey unusable: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_raw)
        .map_err(|e| MobileError::InvalidKeyData(format!("P-256 signature parse failed: {e}")))?;
    vk.verify(&context.signing_payload, &sig).map_err(|e| {
        MobileError::PairingFailed(format!(
            "signature does not verify against the revealed key — likely SE misconfiguration: {e}"
        ))
    })?;

    let indexed = IndexedSignature {
        index: context.signer_index,
        prior_index: Some(context.signer_prior_index),
        sig: sig_raw.to_vec(),
    };

    // Full platform validation against the prior state: current threshold
    // over the new keys AND prior next-threshold over the revealed
    // commitments. This is what makes the emitted envelope a proof, not a
    // proposal.
    let signed = SignedEvent::new(
        Event::Rot(context.unsigned_rot.clone()),
        vec![indexed.clone()],
    );
    validate_signed_event(&signed, Some(&context.prior_state)).map_err(|e| {
        MobileError::PairingFailed(format!(
            "co-authored rotation does not satisfy the platform validator: {e}"
        ))
    })?;

    let attachment = serialize_attachment(&[indexed])
        .map_err(|e| MobileError::Serialization(format!("rot attachment: {e}")))?;
    let wire_envelope = encode_signed_rot(&context.unsigned_rot, &attachment)
        .map_err(|e| MobileError::Serialization(format!("rot envelope: {e}")))?;

    Ok(SharedKelRotIndexedResult {
        wire_envelope,
        did: context.did(),
        sequence: context.new_sequence,
        event_said: context.unsigned_rot.d.as_str().to_string(),
        signer_index: context.signer_index,
        signer_prior_index: context.signer_prior_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_keri::{Prefix, Threshold, decode_signed_rot, parse_attachment};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    fn fresh_p256_key() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut OsRng);
        let compressed = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (sk, compressed)
    }

    fn qb64(pub_compressed: &[u8]) -> CesrKey {
        verkey_to_cesr(&parse_p256_verkey(pub_compressed).unwrap()).unwrap()
    }

    fn commitment(pub_compressed: &[u8]) -> Said {
        compute_next_commitment(&parse_p256_verkey(pub_compressed).unwrap())
    }

    /// A 2-controller shared KEL state: slot 0 = mac, slot 1 = phone.
    /// Returns (state_json, state, phone_next_sk, phone_next_pub).
    fn two_controller_state() -> (String, KeyState, SigningKey, Vec<u8>) {
        let (_mac_sk, mac_pub) = fresh_p256_key();
        let (_phone_sk, phone_pub) = fresh_p256_key();
        let (_mac_next_sk, mac_next_pub) = fresh_p256_key();
        let (phone_next_sk, phone_next_pub) = fresh_p256_key();

        let said = commitment(&mac_pub); // any structurally-valid Said
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EOZZSHAREDKELPREFIXxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
            vec![qb64(&mac_pub), qb64(&phone_pub)],
            vec![commitment(&mac_next_pub), commitment(&phone_next_pub)],
            Threshold::Simple(1),
            Threshold::Simple(1),
            said,
            vec![],
            Threshold::Simple(0),
            vec![],
        );
        let json = serde_json::to_string(&state).unwrap();
        (json, state, phone_next_sk, phone_next_pub)
    }

    #[test]
    fn swap_controller_round_trips_through_platform_validator() {
        let (state_json, state, phone_next_sk, phone_next_pub) = two_controller_state();
        let mac_pub = state.current_keys[0].parse().unwrap().as_bytes().to_vec();

        let (_nm_sk, new_mac_pub) = fresh_p256_key();
        let (_nmn_sk, new_mac_next_pub) = fresh_p256_key();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let ctx = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::SwapController {
                old_verkey_der: mac_pub,
                new_verkey_der: new_mac_pub.clone(),
                new_next_verkey_der: new_mac_next_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap();
        assert_eq!(ctx.new_sequence(), 1);
        assert_eq!(ctx.signer_index(), 1);
        assert_eq!(ctx.signer_prior_index(), 1);

        let sig: p256::ecdsa::Signature = phone_next_sk.sign(&ctx.signing_payload());
        let result =
            assemble_shared_kel_rot_indexed(ctx, sig.to_der().as_bytes().to_vec()).unwrap();
        assert_eq!(result.sequence, 1);
        assert!(result.did.starts_with("did:keri:E"));

        // The envelope decodes through the SAME platform decoder the daemon
        // uses, and the full signed event re-validates against prior state.
        let (rot, attachment) = decode_signed_rot(&result.wire_envelope).unwrap();
        assert_eq!(rot.k.len(), 2, "swap preserves controller count");
        assert_eq!(
            rot.k[0].parse().unwrap().as_bytes(),
            new_mac_pub.as_slice(),
            "slot 0 swapped in place"
        );
        let sigs = parse_attachment(&attachment).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].index, 1);
        // index == ondex round-trips through the canonical single-index
        // CESR code (`A`), where the ondex is implied by the index.
        assert_eq!(sigs[0].prior_index.unwrap_or(sigs[0].index), 1);
        validate_signed_event(&SignedEvent::new(Event::Rot(rot), sigs), Some(&state))
            .expect("daemon-side replay must accept the emitted rotation");
    }

    #[test]
    fn remove_controller_is_a_dual_index_shrink_the_validator_accepts() {
        let (state_json, state, phone_next_sk, phone_next_pub) = two_controller_state();
        let mac_pub = state.current_keys[0].parse().unwrap().as_bytes().to_vec();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let ctx = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::RemoveController {
                target_verkey_der: mac_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap();
        // After the shrink the phone is slot 0, but its reveal binds to
        // prior n[1] — the dual-index pair the validator requires.
        assert_eq!(ctx.signer_index(), 0);
        assert_eq!(ctx.signer_prior_index(), 1);

        let sig: p256::ecdsa::Signature = phone_next_sk.sign(&ctx.signing_payload());
        let result =
            assemble_shared_kel_rot_indexed(ctx, sig.to_der().as_bytes().to_vec()).unwrap();

        let (rot, attachment) = decode_signed_rot(&result.wire_envelope).unwrap();
        assert_eq!(rot.k.len(), 1, "shrink dropped the removed controller");
        let sigs = parse_attachment(&attachment).unwrap();
        assert_eq!(sigs[0].index, 0);
        assert_eq!(sigs[0].prior_index, Some(1));
        validate_signed_event(&SignedEvent::new(Event::Rot(rot), sigs), Some(&state))
            .expect("asymmetric (shrink) rotation must validate via the dual index");
    }

    #[test]
    fn add_controller_appends_key_and_commitment() {
        let (state_json, _state, phone_next_sk, phone_next_pub) = two_controller_state();
        let (_t_sk, tablet_pub) = fresh_p256_key();
        let (_tn_sk, tablet_next_pub) = fresh_p256_key();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let ctx = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::AddController {
                new_verkey_der: tablet_pub.clone(),
                new_next_verkey_der: tablet_next_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap();
        let sig: p256::ecdsa::Signature = phone_next_sk.sign(&ctx.signing_payload());
        let result =
            assemble_shared_kel_rot_indexed(ctx, sig.to_der().as_bytes().to_vec()).unwrap();

        let (rot, _attachment) = decode_signed_rot(&result.wire_envelope).unwrap();
        assert_eq!(rot.k.len(), 3);
        assert_eq!(rot.k[2].parse().unwrap().as_bytes(), tablet_pub.as_slice());
        assert_eq!(rot.n.len(), 3);
    }

    #[test]
    fn unrevealed_key_is_rejected_as_commitment_mismatch() {
        let (state_json, _state, _phone_next_sk, _phone_next_pub) = two_controller_state();
        let (_w_sk, wrong_pub) = fresh_p256_key();
        let (_n_sk, next_pub) = fresh_p256_key();

        let err = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::RemoveController {
                target_verkey_der: wrong_pub.clone(),
            },
            wrong_pub,
            next_pub,
        )
        .unwrap_err();
        assert!(matches!(err, MobileError::CommitmentMismatch(_)));
    }

    #[test]
    fn author_cannot_remove_itself() {
        let (state_json, state, _phone_next_sk, phone_next_pub) = two_controller_state();
        let phone_pub = state.current_keys[1].parse().unwrap().as_bytes().to_vec();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let err = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::RemoveController {
                target_verkey_der: phone_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap_err();
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }

    #[test]
    fn wrong_signature_is_rejected_before_any_envelope_is_emitted() {
        let (state_json, state, _phone_next_sk, phone_next_pub) = two_controller_state();
        let mac_pub = state.current_keys[0].parse().unwrap().as_bytes().to_vec();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let ctx = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::RemoveController {
                target_verkey_der: mac_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap();

        let (attacker_sk, _) = fresh_p256_key();
        let bad: p256::ecdsa::Signature = attacker_sk.sign(&ctx.signing_payload());
        let err = assemble_shared_kel_rot_indexed(ctx, bad.to_der().as_bytes().to_vec())
            .unwrap_err();
        assert!(matches!(err, MobileError::PairingFailed(_)));
    }

    #[test]
    fn signing_payload_length_matches_version_string() {
        // A spec verifier frames the body by the length in `v` — the signed
        // bytes must be exactly that long.
        let (state_json, state, _phone_next_sk, phone_next_pub) = two_controller_state();
        let mac_pub = state.current_keys[0].parse().unwrap().as_bytes().to_vec();
        let (_pn_sk, phone_new_next_pub) = fresh_p256_key();

        let ctx = build_shared_kel_rot_payload(
            state_json,
            SharedKelChangeRequest::RemoveController {
                target_verkey_der: mac_pub,
            },
            phone_next_pub,
            phone_new_next_pub,
        )
        .unwrap();
        let payload = ctx.signing_payload();
        let event: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(event["t"], "rot");
        let v = event["v"].as_str().unwrap();
        let size = usize::from_str_radix(&v["KERI10JSON".len()..v.len() - 1], 16).unwrap();
        assert_eq!(size, payload.len());
    }
}
