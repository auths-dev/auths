//! Apply a co-authored shared-KEL rotation received from a paired device.
//!
//! The pairing daemon verifies a rotation envelope's indexed signatures
//! against the rotation's own key list at its HTTP boundary, then holds it
//! for the embedding host. This module is the host's side of that handoff:
//! replay the registry's KEL to the identity's prior key state, validate
//! the rotation against that state (SAID, sequence, chain linkage, signing
//! threshold AND the prior next-commitment reveals), and append it to the
//! KEL. The device that authored the rotation never touches the registry;
//! the registry never accepts an event it has not replayed against its own
//! prior state.

use std::ops::ControlFlow;

use auths_id::keri::validate_kel;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::registry::backend::RegistryError;
use auths_keri::{
    Event, Prefix, Said, SignedEvent, decode_signed_rot, parse_attachment, validate_for_append,
    validate_signed_event,
};

/// Errors from applying a received shared-KEL rotation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharedRotError {
    /// The wire envelope could not be decoded into a rotation + attachment.
    #[error("rotation envelope invalid: {0}")]
    InvalidEnvelope(String),

    /// The rotation names a different identity than this host serves.
    #[error("rotation targets '{got}' but this host serves '{expected}'")]
    PrefixMismatch {
        /// The prefix the host expected (its controller identity).
        expected: String,
        /// The prefix the rotation actually names.
        got: String,
    },

    /// The registry holds no KEL for the rotation's identity.
    #[error("identity not found in the registry: {prefix}")]
    UnknownIdentity {
        /// The prefix that has no KEL.
        prefix: String,
    },

    /// Replaying the registry's existing KEL failed (corrupt local state).
    #[error("registry KEL replay failed: {0}")]
    KelReplayFailed(String),

    /// The rotation does not validate against the registry's prior key
    /// state (bad chain linkage, stale sequence, unsatisfied signing
    /// threshold, or unrevealed prior commitment).
    #[error("rotation rejected against prior key state: {0}")]
    RejectedByPriorState(String),

    /// The validated rotation could not be written to the KEL.
    #[error("KEL append failed: {0}")]
    AppendFailed(String),
}

/// A rotation that validated against the registry's prior key state and
/// is now appended to the KEL. Constructed only by
/// [`apply_shared_kel_rot`] — holding one means the registry's KEL has
/// already advanced.
#[derive(Debug, Clone)]
pub struct AppliedSharedKelRot {
    /// The identity whose KEL advanced.
    pub prefix: Prefix,
    /// The new tip sequence number.
    pub sequence: u128,
    /// SAID of the appended rotation event.
    pub said: Said,
    /// Number of controller keys in force after the rotation.
    pub controller_count: usize,
}

/// Validate a received shared-KEL rotation against the registry's prior
/// key state and append it.
///
/// The envelope is the single-string wire form a paired device emits
/// (`auths_keri::encode_signed_rot`) and the pairing daemon holds for the
/// host. The daemon already verified the indexed signatures against the
/// rotation's own key list; this function supplies what only the host can:
/// the registry's prior state. It replays the identity's KEL, checks the
/// rotation's SAID, sequence, and chain linkage against the replayed tip,
/// re-verifies the indexed signatures against BOTH the new signing
/// threshold and the prior next-commitment reveals, and only then appends.
///
/// Args:
/// * `envelope`: base64url wire envelope of the signed rotation.
/// * `expected_prefix`: the identity this host serves — a rotation naming
///   any other identity is refused before the registry is read.
/// * `registry`: the registry backend holding the identity's KEL.
///
/// Usage:
/// ```ignore
/// let applied = apply_shared_kel_rot(&held.rot_envelope, &prefix, registry.as_ref())?;
/// println!("KEL advanced to seq {}", applied.sequence);
/// ```
pub fn apply_shared_kel_rot(
    envelope: &str,
    expected_prefix: &Prefix,
    registry: &(dyn RegistryBackend + Send + Sync),
) -> Result<AppliedSharedKelRot, SharedRotError> {
    let (rot, attachment) =
        decode_signed_rot(envelope).map_err(|e| SharedRotError::InvalidEnvelope(e.to_string()))?;
    let signatures = parse_attachment(&attachment)
        .map_err(|e| SharedRotError::InvalidEnvelope(e.to_string()))?;

    if rot.i != *expected_prefix {
        return Err(SharedRotError::PrefixMismatch {
            expected: expected_prefix.as_str().to_string(),
            got: rot.i.as_str().to_string(),
        });
    }

    // Replay the registry's own KEL — prior state is derived from the
    // stored events, never trusted from the wire.
    let mut events: Vec<Event> = Vec::new();
    registry
        .visit_events(expected_prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .map_err(|e| match e {
            RegistryError::NotFound { .. } => SharedRotError::UnknownIdentity {
                prefix: expected_prefix.as_str().to_string(),
            },
            other => SharedRotError::KelReplayFailed(other.to_string()),
        })?;
    if events.is_empty() {
        return Err(SharedRotError::UnknownIdentity {
            prefix: expected_prefix.as_str().to_string(),
        });
    }
    let state =
        validate_kel(&events).map_err(|e| SharedRotError::KelReplayFailed(e.to_string()))?;

    // Structural gate: SAID, sequence, chain linkage against the replayed tip.
    let event = Event::Rot(rot);
    validate_for_append(&event, &state)
        .map_err(|e| SharedRotError::RejectedByPriorState(e.to_string()))?;

    // Cryptographic gate: indexed signatures must satisfy the rotation's own
    // signing threshold AND the prior establishment event's next-commitment
    // threshold (each verifying key must reveal a pre-committed `n[]` slot).
    let signed = SignedEvent::new(event, signatures);
    validate_signed_event(&signed, Some(&state))
        .map_err(|e| SharedRotError::RejectedByPriorState(e.to_string()))?;

    registry
        .append_signed_event(expected_prefix, &signed.event, &attachment)
        .map_err(|e| SharedRotError::AppendFailed(e.to_string()))?;

    let Event::Rot(rot) = signed.event else {
        // The event was constructed as a Rot above and never reassigned.
        return Err(SharedRotError::AppendFailed(
            "event variant changed during validation".to_string(),
        ));
    };
    Ok(AppliedSharedKelRot {
        sequence: rot.s.value(),
        controller_count: rot.k.len(),
        said: rot.d,
        prefix: rot.i,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    use auths_id::testing::fakes::FakeRegistryBackend;
    use auths_keri::{
        CesrKey, IcpEvent, IcpEventInit, IndexedSignature, KeriPublicKey, KeriSequence, RotEvent,
        RotEventInit, Threshold, VersionString, compute_next_commitment, encode_signed_rot,
        finalize_icp_event, finalize_rot_event, serialize_attachment, serialize_for_signing,
    };

    /// Deterministic P-256 key: any small nonzero scalar is valid.
    fn p256_key(seed: u8) -> (SigningKey, Vec<u8>) {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = SigningKey::from_slice(&bytes).unwrap();
        let compressed = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (sk, compressed)
    }

    fn verkey(compressed: &[u8]) -> KeriPublicKey {
        KeriPublicKey::P256 {
            key: compressed.try_into().unwrap(),
            transferable: true,
        }
    }

    fn qb64(compressed: &[u8]) -> CesrKey {
        CesrKey::new_unchecked(verkey(compressed).to_qb64().unwrap())
    }

    fn commitment(compressed: &[u8]) -> Said {
        compute_next_commitment(&verkey(compressed))
    }

    /// A registry holding a real 2-controller inception:
    /// slot 0 = mac, slot 1 = phone; `n` pre-commits both next keys.
    /// Returns (registry, icp, phone_next_sk, phone_next_pub).
    fn registry_with_shared_kel() -> (FakeRegistryBackend, IcpEvent, SigningKey, Vec<u8>) {
        let (_mac_sk, mac_pub) = p256_key(1);
        let (_phone_sk, phone_pub) = p256_key(2);
        let (_mac_next_sk, mac_next_pub) = p256_key(3);
        let (phone_next_sk, phone_next_pub) = p256_key(4);

        let icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked(String::new()),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![qb64(&mac_pub), qb64(&phone_pub)],
            nt: Threshold::Simple(1),
            n: vec![commitment(&mac_next_pub), commitment(&phone_next_pub)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        }))
        .unwrap();

        let registry = FakeRegistryBackend::new();
        registry
            .append_signed_event(&icp.i.clone(), &Event::Icp(icp.clone()), &[])
            .unwrap();
        (registry, icp, phone_next_sk, phone_next_pub)
    }

    /// The phone's swap rotation: replaces the mac slot, rotates the phone
    /// slot to its revealed pre-committed key, signed only by that key.
    fn phone_swap_envelope(
        icp: &IcpEvent,
        phone_next_sk: &SigningKey,
        phone_next_pub: &[u8],
    ) -> String {
        let (_new_mac_sk, new_mac_pub) = p256_key(5);
        let (_new_mac_next_sk, new_mac_next_pub) = p256_key(6);
        let (_phone_new_next_sk, phone_new_next_pub) = p256_key(7);

        let rot = finalize_rot_event(RotEvent::new(RotEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: Threshold::Simple(1),
            k: vec![qb64(&new_mac_pub), qb64(phone_next_pub)],
            nt: Threshold::Simple(1),
            n: vec![
                commitment(&new_mac_next_pub),
                commitment(&phone_new_next_pub),
            ],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
        }))
        .unwrap();

        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig: Signature = phone_next_sk.sign(&canonical);
        let raw: [u8; 64] = sig.to_bytes().into();
        let attachment = serialize_attachment(&[IndexedSignature {
            index: 1,
            prior_index: None,
            sig: raw.to_vec(),
        }])
        .unwrap();
        encode_signed_rot(&rot, &attachment).unwrap()
    }

    fn kel_len(registry: &FakeRegistryBackend, prefix: &Prefix) -> usize {
        let mut n = 0usize;
        registry
            .visit_events(prefix, 0, &mut |_| {
                n += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        n
    }

    #[test]
    fn phone_authored_swap_is_validated_and_appended() {
        let (registry, icp, phone_next_sk, phone_next_pub) = registry_with_shared_kel();
        let envelope = phone_swap_envelope(&icp, &phone_next_sk, &phone_next_pub);

        let applied = apply_shared_kel_rot(&envelope, &icp.i, &registry).unwrap();
        assert_eq!(applied.sequence, 1);
        assert_eq!(
            applied.controller_count, 2,
            "swap preserves controller count"
        );
        assert_eq!(applied.prefix, icp.i);

        assert_eq!(
            kel_len(&registry, &icp.i),
            2,
            "KEL advanced by exactly one event"
        );
        let stored = registry.get_attachment(&icp.i, 1).unwrap();
        assert!(
            stored.is_some_and(|a| !a.is_empty()),
            "the rot's signature attachment must be stored for later authentication"
        );
    }

    #[test]
    fn rotation_for_another_identity_is_refused_before_any_registry_read() {
        let (registry, icp, phone_next_sk, phone_next_pub) = registry_with_shared_kel();
        let envelope = phone_swap_envelope(&icp, &phone_next_sk, &phone_next_pub);

        let other = Prefix::new_unchecked("EOTHERIDENTITYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into());
        let err = apply_shared_kel_rot(&envelope, &other, &registry).unwrap_err();
        assert!(
            matches!(err, SharedRotError::PrefixMismatch { .. }),
            "got: {err}"
        );
        assert_eq!(kel_len(&registry, &icp.i), 1, "registry untouched");
    }

    #[test]
    fn forged_signature_is_rejected_and_nothing_is_appended() {
        let (registry, icp, phone_next_sk, phone_next_pub) = registry_with_shared_kel();
        let envelope = phone_swap_envelope(&icp, &phone_next_sk, &phone_next_pub);

        // Re-sign the same rot with a key that reveals NO prior commitment.
        let (rot, _attachment) = decode_signed_rot(&envelope).unwrap();
        let (attacker_sk, _attacker_pub) = p256_key(9);
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig: Signature = attacker_sk.sign(&canonical);
        let raw: [u8; 64] = sig.to_bytes().into();
        let forged_attachment = serialize_attachment(&[IndexedSignature {
            index: 1,
            prior_index: None,
            sig: raw.to_vec(),
        }])
        .unwrap();
        let forged = encode_signed_rot(&rot, &forged_attachment).unwrap();

        let err = apply_shared_kel_rot(&forged, &icp.i, &registry).unwrap_err();
        assert!(
            matches!(err, SharedRotError::RejectedByPriorState(_)),
            "got: {err}"
        );
        assert_eq!(
            kel_len(&registry, &icp.i),
            1,
            "a rejected rotation must never land"
        );
    }

    #[test]
    fn replayed_rotation_is_stale_against_the_advanced_kel() {
        let (registry, icp, phone_next_sk, phone_next_pub) = registry_with_shared_kel();
        let envelope = phone_swap_envelope(&icp, &phone_next_sk, &phone_next_pub);

        apply_shared_kel_rot(&envelope, &icp.i, &registry).unwrap();
        let err = apply_shared_kel_rot(&envelope, &icp.i, &registry).unwrap_err();
        assert!(
            matches!(err, SharedRotError::RejectedByPriorState(_)),
            "got: {err}"
        );
        assert_eq!(
            kel_len(&registry, &icp.i),
            2,
            "replay must not double-append"
        );
    }

    #[test]
    fn unknown_identity_is_a_typed_error() {
        let (_registry, icp, phone_next_sk, phone_next_pub) = registry_with_shared_kel();
        let envelope = phone_swap_envelope(&icp, &phone_next_sk, &phone_next_pub);

        let empty = FakeRegistryBackend::new();
        let err = apply_shared_kel_rot(&envelope, &icp.i, &empty).unwrap_err();
        assert!(
            matches!(err, SharedRotError::UnknownIdentity { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn garbage_envelope_is_invalid_not_a_panic() {
        let registry = FakeRegistryBackend::new();
        let prefix = Prefix::new_unchecked("EXXXX".into());
        let err = apply_shared_kel_rot("not-an-envelope", &prefix, &registry).unwrap_err();
        assert!(
            matches!(err, SharedRotError::InvalidEnvelope(_)),
            "got: {err}"
        );
    }
}
