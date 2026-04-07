//! KEL validation: SAID verification, chain linkage, signature verification,
//! and pre-rotation commitment checks.
//!
//! This module provides validation functions for ensuring a Key Event Log
//! is cryptographically valid and properly chained.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::keys::KeriPublicKey;
use ring::signature::UnparsedPublicKey;

use crate::crypto::verify_commitment;
use crate::events::{Event, IcpEvent, IxnEvent, RotEvent};
use crate::said::compute_said;
use crate::state::KeyState;
use crate::types::{Prefix, Said};

/// Errors specific to KEL validation.
///
/// These errors represent **protocol invariant violations**. They indicate
/// structural corruption or attack, not recoverable conditions.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// SAID (Self-Addressing Identifier) doesn't match content hash.
    #[error("Invalid SAID: expected {expected}, got {actual}")]
    InvalidSaid {
        /// The SAID that was expected from the content hash.
        expected: Said,
        /// The SAID that was actually found in the event.
        actual: Said,
    },

    /// Event references wrong previous event.
    #[error("Broken chain: event {sequence} references {referenced}, but previous was {actual}")]
    BrokenChain {
        /// Zero-based position of the event in the KEL.
        sequence: u64,
        /// The previous SAID referenced by this event.
        referenced: Said,
        /// The actual SAID of the previous event.
        actual: Said,
    },

    /// Sequence number is not monotonically increasing.
    #[error("Invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence {
        /// The sequence number that was expected.
        expected: u64,
        /// The sequence number that was found.
        actual: u64,
    },

    /// Pre-rotation commitment doesn't match the new current key.
    #[error("Pre-rotation commitment mismatch at sequence {sequence}")]
    CommitmentMismatch {
        /// Zero-based position of the rotation event that failed.
        sequence: u64,
    },

    /// Cryptographic signature verification failed for an event.
    #[error("Signature verification failed at sequence {sequence}")]
    SignatureFailed {
        /// Zero-based position of the event whose signature failed.
        sequence: u64,
    },

    /// The first event in a KEL must be an Inception event.
    #[error("First event must be inception")]
    NotInception,

    /// The KEL contains no events.
    #[error("Empty KEL")]
    EmptyKel,

    /// More than one Inception event was found in the KEL.
    #[error("Multiple inception events in KEL")]
    MultipleInceptions,

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// A sequence field could not be parsed as a valid hex number.
    #[error("Malformed sequence number: {raw:?}")]
    MalformedSequence {
        /// The raw string that could not be parsed.
        raw: String,
    },

    /// The key encoding prefix is unsupported or malformed.
    #[error("Invalid key encoding: {0}")]
    InvalidKey(String),
}

/// Validate a KEL and return the resulting KeyState.
///
/// This is a **pure function** serving as the core entrypoint for KEL replay.
///
/// Args:
/// * `events` - The ordered list of KERI events to validate.
///
/// Usage:
/// ```ignore
/// let key_state = validate_kel(&events)?;
/// ```
pub fn validate_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    if events.is_empty() {
        return Err(ValidationError::EmptyKel);
    }

    let Event::Icp(icp) = &events[0] else {
        return Err(ValidationError::NotInception);
    };

    verify_event_said(&events[0])?;
    let mut state = validate_inception(icp)?;

    for (idx, event) in events.iter().enumerate().skip(1) {
        let expected_seq = idx as u64;
        verify_event_said(event)?;
        verify_sequence(event, expected_seq)?;
        verify_chain_linkage(event, &state)?;

        match event {
            Event::Rot(rot) => validate_rotation(rot, event, expected_seq, &mut state)?,
            Event::Ixn(ixn) => validate_interaction(ixn, event, expected_seq, &mut state)?,
            Event::Icp(_) => return Err(ValidationError::MultipleInceptions),
        }
    }

    Ok(state)
}

fn parse_threshold(raw: &str) -> Result<u64, ValidationError> {
    raw.parse::<u64>()
        .map_err(|_| ValidationError::MalformedSequence {
            raw: raw.to_string(),
        })
}

fn validate_inception(icp: &IcpEvent) -> Result<KeyState, ValidationError> {
    verify_event_signature(
        &Event::Icp(icp.clone()),
        icp.k
            .first()
            .ok_or(ValidationError::SignatureFailed { sequence: 0 })?,
    )?;

    let threshold = parse_threshold(&icp.kt)?;
    let next_threshold = parse_threshold(&icp.nt)?;

    Ok(KeyState::from_inception(
        icp.i.clone(),
        icp.k.clone(),
        icp.n.clone(),
        threshold,
        next_threshold,
        icp.d.clone(),
    ))
}

fn verify_sequence(event: &Event, expected: u64) -> Result<(), ValidationError> {
    let actual = event.sequence().value();
    if actual != expected {
        return Err(ValidationError::InvalidSequence { expected, actual });
    }
    Ok(())
}

fn verify_chain_linkage(event: &Event, state: &KeyState) -> Result<(), ValidationError> {
    let prev_said = event.previous().ok_or(ValidationError::NotInception)?;
    if *prev_said != state.last_event_said {
        return Err(ValidationError::BrokenChain {
            sequence: event.sequence().value(),
            referenced: prev_said.clone(),
            actual: state.last_event_said.clone(),
        });
    }
    Ok(())
}

fn validate_rotation(
    rot: &RotEvent,
    event: &Event,
    sequence: u64,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    if !rot.k.is_empty() {
        verify_event_signature(event, &rot.k[0])?;
    }

    if !state.next_commitment.is_empty() && !rot.k.is_empty() {
        let key_bytes = KeriPublicKey::parse(&rot.k[0])
            .map(|k| k.as_bytes().to_vec())
            .map_err(|_| ValidationError::CommitmentMismatch { sequence })?;

        if !verify_commitment(&key_bytes, &state.next_commitment[0]) {
            return Err(ValidationError::CommitmentMismatch { sequence });
        }
    }

    let threshold = parse_threshold(&rot.kt)?;
    let next_threshold = parse_threshold(&rot.nt)?;

    state.apply_rotation(
        rot.k.clone(),
        rot.n.clone(),
        threshold,
        next_threshold,
        sequence,
        rot.d.clone(),
    );

    Ok(())
}

fn validate_interaction(
    ixn: &IxnEvent,
    event: &Event,
    sequence: u64,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    let current_key = state
        .current_key()
        .ok_or(ValidationError::SignatureFailed { sequence })?;
    verify_event_signature(event, current_key)?;
    state.apply_interaction(sequence, ixn.d.clone());
    Ok(())
}

/// Replay a KEL to get the current KeyState.
///
/// Alias for [`validate_kel`] — use whichever name fits your context better.
///
/// Args:
/// * `events` - The ordered list of KERI events to replay.
pub fn replay_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    validate_kel(events)
}

/// Validate the cryptographic integrity of a single event against the current key state.
///
/// Args:
/// * `event` - The event to validate.
/// * `current_state` - The current `KeyState` (None for inception events).
pub fn verify_event_crypto(
    event: &Event,
    current_state: Option<&KeyState>,
) -> Result<(), ValidationError> {
    match event {
        Event::Icp(icp) => {
            let key = icp
                .k
                .first()
                .ok_or(ValidationError::SignatureFailed { sequence: 0 })?;
            verify_event_signature(event, key)?;

            if icp.i.as_str() != icp.d.as_str() {
                return Err(ValidationError::InvalidSaid {
                    expected: icp.d.clone(),
                    actual: Said::new_unchecked(icp.i.as_str().to_string()),
                });
            }

            Ok(())
        }
        Event::Rot(rot) => {
            let sequence = event.sequence().value();
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;

            if state.is_abandoned || state.next_commitment.is_empty() {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }

            if rot.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence });
            }
            verify_event_signature(event, &rot.k[0])?;

            let key_str = &rot.k[0];
            let key_bytes = KeriPublicKey::parse(key_str)
                .map(|k| k.as_bytes().to_vec())
                .map_err(|_| ValidationError::CommitmentMismatch { sequence })?;

            if !verify_commitment(&key_bytes, &state.next_commitment[0]) {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }

            Ok(())
        }
        Event::Ixn(_) => {
            let sequence = event.sequence().value();
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;

            let current_key = state
                .current_key()
                .ok_or(ValidationError::SignatureFailed { sequence })?;
            verify_event_signature(event, current_key)?;

            Ok(())
        }
    }
}

/// Verify an event's SAID matches its content hash.
///
/// Args:
/// * `event` - The event to verify.
pub fn verify_event_said(event: &Event) -> Result<(), ValidationError> {
    let value =
        serde_json::to_value(event).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let computed =
        compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let actual = event.said();

    if computed != *actual {
        return Err(ValidationError::InvalidSaid {
            expected: computed,
            actual: actual.clone(),
        });
    }

    Ok(())
}

/// Validate a single event for appending to a KEL with known state.
///
/// Args:
/// * `event` - The event to validate for append.
/// * `state` - The current `KeyState` (tip of the existing KEL).
pub fn validate_for_append(event: &Event, state: &KeyState) -> Result<(), ValidationError> {
    if matches!(event, Event::Icp(_)) {
        return Err(ValidationError::MultipleInceptions);
    }

    verify_event_said(event)?;
    verify_sequence(event, state.sequence + 1)?;
    verify_chain_linkage(event, state)?;
    verify_event_crypto(event, Some(state))?;

    Ok(())
}

/// Compute the SAID for an event.
///
/// Args:
/// * `event` - The event to compute the SAID for.
pub fn compute_event_said(event: &Event) -> Result<Said, ValidationError> {
    let value =
        serde_json::to_value(event).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))
}

/// Serialize event for signing (clears d, i for icp, and x fields).
///
/// Args:
/// * `event` - The event to serialize for signing.
pub fn serialize_for_signing(event: &Event) -> Result<Vec<u8>, ValidationError> {
    match event {
        Event::Icp(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default();
            e.x = String::new();
            serde_json::to_vec(&Event::Icp(e))
        }
        Event::Rot(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.x = String::new();
            serde_json::to_vec(&Event::Rot(e))
        }
        Event::Ixn(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.x = String::new();
            serde_json::to_vec(&Event::Ixn(e))
        }
    }
    .map_err(|e| ValidationError::Serialization(e.to_string()))
}

/// Verify an event's signature using the specified key.
fn verify_event_signature(event: &Event, signing_key: &str) -> Result<(), ValidationError> {
    let sequence = event.sequence().value();

    let sig_str = event.signature();
    if sig_str.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_str)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    let key_bytes = KeriPublicKey::parse(signing_key)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    let canonical = serialize_for_signing(event)?;

    let pk = UnparsedPublicKey::new(&ring::signature::ED25519, key_bytes.as_bytes());
    pk.verify(&canonical, &sig_bytes)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    Ok(())
}

/// Create an inception event with a properly computed SAID.
///
/// Args:
/// * `icp` - The inception event to finalize.
pub fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, ValidationError> {
    let value = serde_json::to_value(Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;

    icp.d = said.clone();
    icp.i = Prefix::new_unchecked(said.into_inner());

    Ok(icp)
}

/// Search for a seal with the given digest in any IXN event in the KEL.
///
/// Returns the sequence number of the IXN event if found.
///
/// Args:
/// * `events` - The event log to search.
/// * `digest` - The SAID digest to search for.
pub fn find_seal_in_kel(events: &[Event], digest: &str) -> Option<u64> {
    for event in events {
        if let Event::Ixn(ixn) = event {
            for seal in &ixn.a {
                if seal.d.as_str() == digest {
                    return Some(ixn.s.value());
                }
            }
        }
    }
    None
}

/// Parse a KEL from a JSON string.
///
/// Args:
/// * `json` - JSON string containing a list of KERI events.
pub fn parse_kel_json(json: &str) -> Result<Vec<Event>, ValidationError> {
    serde_json::from_str(json).map_err(|e| ValidationError::Serialization(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::events::{KERI_VERSION, KeriSequence, Seal};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_raw_icp(key: &str, next: &str) -> IcpEvent {
        IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key.to_string()],
            nt: "1".to_string(),
            n: vec![next.to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        }
    }

    fn make_signed_icp() -> (IcpEvent, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec!["ENextCommitment".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        (finalized, keypair)
    }

    fn make_signed_ixn(
        prefix: &Prefix,
        prev_said: &Said,
        seq: u64,
        keypair: &Ed25519KeyPair,
    ) -> IxnEvent {
        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: prev_said.clone(),
            a: vec![Seal::device_attestation("EAttest")],
            x: String::new(),
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

        let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        ixn
    }

    #[test]
    fn finalize_icp_sets_said() {
        let icp = make_raw_icp("DKey1", "ENext1");
        let finalized = finalize_icp_event(icp).unwrap();

        assert!(!finalized.d.is_empty());
        assert_eq!(finalized.d.as_str(), finalized.i.as_str());
        assert!(finalized.d.as_str().starts_with('E'));
    }

    #[test]
    fn validates_single_inception() {
        let (icp, _keypair) = make_signed_icp();
        let events = vec![Event::Icp(icp.clone())];

        let state = validate_kel(&events).unwrap();
        assert_eq!(state.prefix, icp.i);
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn rejects_empty_kel() {
        let result = validate_kel(&[]);
        assert!(matches!(result, Err(ValidationError::EmptyKel)));
    }

    #[test]
    fn rejects_non_inception_first() {
        let ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked("ETest".to_string()),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: KeriSequence::new(0),
            p: Said::new_unchecked("EPrev".to_string()),
            a: vec![],
            x: String::new(),
        };
        let events = vec![Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(matches!(result, Err(ValidationError::NotInception)));
    }

    #[test]
    fn rejects_broken_sequence() {
        let (icp, keypair) = make_signed_icp();

        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(5),
            p: icp.d.clone(),
            a: vec![],
            x: String::new(),
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

        let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![Event::Icp(icp), Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidSequence {
                expected: 1,
                actual: 5
            })
        ));
    }

    #[test]
    fn rejects_broken_chain() {
        let (icp, keypair) = make_signed_icp();

        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EWrongPrevious".to_string()),
            a: vec![],
            x: String::new(),
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

        let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![Event::Icp(icp), Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(matches!(result, Err(ValidationError::BrokenChain { .. })));
    }

    #[test]
    fn rejects_invalid_said() {
        let icp = make_raw_icp("DKey1", "ENext1");
        let finalized = finalize_icp_event(icp).unwrap();

        let mut tampered = finalized.clone();
        tampered.d = Said::new_unchecked("EWrongSaid".to_string());

        let events = vec![Event::Icp(tampered)];
        let result = validate_kel(&events);
        assert!(matches!(result, Err(ValidationError::InvalidSaid { .. })));
    }

    #[test]
    fn validates_icp_then_ixn() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);

        let events = vec![Event::Icp(icp), Event::Ixn(ixn.clone())];
        let state = validate_kel(&events).unwrap();
        assert_eq!(state.sequence, 1);
        assert_eq!(state.last_event_said, ixn.d);
    }

    #[test]
    fn compute_event_said_works() {
        let icp = make_raw_icp("DKey1", "ENext1");
        let event = Event::Icp(icp);
        let said = compute_event_said(&event).unwrap();
        assert!(said.as_str().starts_with('E'));
        assert!(!said.is_empty());
    }

    #[test]
    fn rejects_forged_signature() {
        let (mut icp, _keypair) = make_signed_icp();
        icp.x = URL_SAFE_NO_PAD.encode([0u8; 64]);

        let events = vec![Event::Icp(icp)];
        let result = validate_kel(&events);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    #[test]
    fn rejects_missing_signature() {
        let (mut icp, _keypair) = make_signed_icp();
        icp.x = String::new();

        let events = vec![Event::Icp(icp)];
        let result = validate_kel(&events);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    #[test]
    fn rejects_wrong_key_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let mut icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec!["ENextCommitment".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        icp = finalize_icp_event(icp).unwrap();

        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_keypair = Ed25519KeyPair::from_pkcs8(wrong_pkcs8.as_ref()).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
        let sig = wrong_keypair.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![Event::Icp(icp)];
        let result = validate_kel(&events);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    #[test]
    fn crypto_accepts_valid_inception() {
        let (icp, _keypair) = make_signed_icp();
        let result = verify_event_crypto(&Event::Icp(icp), None);
        assert!(result.is_ok());
    }

    #[test]
    fn find_seal_in_kel_finds_digest() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);
        let events = vec![Event::Icp(icp), Event::Ixn(ixn)];
        assert_eq!(find_seal_in_kel(&events, "EAttest"), Some(1));
        assert_eq!(find_seal_in_kel(&events, "ENonExistent"), None);
    }

    #[test]
    fn parse_kel_json_rejects_invalid_hex_sequence() {
        let json = r#"[{"v":"KERI10JSON","t":"icp","i":"E123","s":"not_hex","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}]"#;
        let result = parse_kel_json(json);
        assert!(result.is_err(), "expected error for invalid hex sequence");
    }
}
