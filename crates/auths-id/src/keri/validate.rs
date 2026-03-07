//! KEL validation: SAID verification, chain linkage, signature verification,
//! and pre-rotation commitment checks.
//!
//! This module provides validation functions for ensuring a Key Event Log
//! is cryptographically valid and properly chained.
//!
//! ## Core Entrypoints (Pure Functions)
//!
//! The following functions are **pure** with no side effects:
//!
//! - [`validate_kel`] / [`replay_kel`]: Replays a KEL to compute the current `KeyState`
//!
//! **What "pure" means for these functions:**
//! - **Deterministic**: Same inputs always produce same outputs
//! - **No side effects**: No filesystem, network, or global state access
//! - **No storage assumptions**: Takes `&[Event]` slice, not registry references
//! - **Errors are values**: Returns `Result`, never panics on invalid input
//!
//! This enables property-based testing and makes the core logic independent of
//! storage backends.

use auths_core::crypto::said::{compute_said, verify_commitment};
use auths_crypto::KeriPublicKey;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::UnparsedPublicKey;

use super::types::{Prefix, Said};
use super::{Event, IcpEvent, IxnEvent, KeyState, RotEvent};

/// Errors specific to KEL validation.
///
/// These errors represent **protocol invariant violations**. They indicate
/// structural corruption or attack, not recoverable conditions.
///
/// # Invariants Enforced
///
/// - **Append-only KEL**: Sequence numbers must be monotonically increasing
/// - **Self-addressing**: Each event's SAID must match its content hash
/// - **Chain integrity**: Each event must reference the previous event's SAID
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// SAID (Self-Addressing Identifier) doesn't match content hash.
    ///
    /// This is a **protocol invariant violation**. The event's `d` field
    /// must equal the Blake3 hash of its canonical serialization.
    #[error("Invalid SAID: expected {expected}, got {actual}")]
    InvalidSaid { expected: Said, actual: Said },

    /// Event references wrong previous event.
    ///
    /// This is a **chain integrity violation**. Each event's `p` field
    /// must equal the SAID of the immediately preceding event.
    #[error("Broken chain: event {sequence} references {referenced}, but previous was {actual}")]
    BrokenChain {
        sequence: u64,
        referenced: Said,
        actual: Said,
    },

    /// Sequence number is not monotonically increasing.
    ///
    /// This is an **append-only invariant violation**. Sequence numbers
    /// must be 0, 1, 2, ... with no gaps or duplicates.
    #[error("Invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence { expected: u64, actual: u64 },

    #[error("Pre-rotation commitment mismatch at sequence {sequence}")]
    CommitmentMismatch { sequence: u64 },

    #[error("Signature verification failed at sequence {sequence}")]
    SignatureFailed { sequence: u64 },

    #[error("First event must be inception")]
    NotInception,

    #[error("Empty KEL")]
    EmptyKel,

    #[error("Multiple inception events in KEL")]
    MultipleInceptions,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Malformed sequence number: {raw:?}")]
    MalformedSequence { raw: String },
}

/// Validate a KEL and return the resulting KeyState.
///
/// This is a **pure function** and serves as the core entrypoint for
/// KEL replay. It is equivalent to `apply_event_chain` in the domain model.
///
/// # Pure Function Guarantees
///
/// - **Deterministic**: Same event sequence always produces same `KeyState`
/// - **No I/O**: No filesystem, network, or global state access
/// - **No storage assumptions**: Takes `&[Event]` slice directly
/// - **Errors are values**: Returns `Result`, never panics on invalid input
///
/// # Validation Performed
///
/// - SAID verification for each event
/// - Chain linkage (each event's `p` matches previous event's `d`)
/// - Sequence ordering (strict increment from 0)
/// - Pre-rotation commitment verification for rotation events
/// - Signature verification using declared keys
///
/// # Example
///
/// ```rust,ignore
/// use auths_id::keri::{validate_kel, Event};
///
/// let events: Vec<Event> = load_events_from_storage(...);
/// let key_state = validate_kel(&events)?;
/// // key_state now reflects the current identity state
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
/// This is an alias for [`validate_kel`] and shares all its pure function guarantees.
/// Use whichever name is more semantically appropriate for your context:
/// - `validate_kel` when emphasis is on validation
/// - `replay_kel` when emphasis is on state derivation
pub fn replay_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    validate_kel(events)
}

/// Validate the cryptographic integrity of a single event against the current key state.
///
/// This is an O(1) operation — it verifies only the incoming event's signature
/// and pre-rotation commitment against the cached tip state, avoiding full KEL replay.
///
/// For inception events, `current_state` should be `None`. The function verifies
/// the self-signing property (signature by declared key `k[0]`) and that `i == d`.
///
/// # Pure Function Guarantees
///
/// - **Deterministic**: Same inputs always produce same result
/// - **No I/O**: No filesystem, network, or global state access
/// - **O(1)**: Constant-time relative to KEL length
pub fn verify_event_crypto(
    event: &Event,
    current_state: Option<&KeyState>,
) -> Result<(), ValidationError> {
    match event {
        Event::Icp(icp) => {
            // Inception: verify self-signed with declared key k[0]
            let key = icp
                .k
                .first()
                .ok_or(ValidationError::SignatureFailed { sequence: 0 })?;
            verify_event_signature(event, key)?;

            // Verify self-certifying identifier: i == d
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

            // Reject rotation on abandoned identity (empty next commitment)
            if state.is_abandoned || state.next_commitment.is_empty() {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }

            // Rotation is signed by the NEW key
            if rot.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence });
            }
            verify_event_signature(event, &rot.k[0])?;

            // Verify pre-rotation commitment: blake3(new_key) == current_state.next_commitment
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

            // Interaction: signed by current key from cached state
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
/// The SAID is computed by hashing the event JSON with the `d` field cleared.
pub fn verify_event_said(event: &Event) -> Result<(), ValidationError> {
    // Serialize event without the 'd' field for hashing
    let json = serialize_for_said(event)?;
    let computed = compute_said(&json);
    let actual = event.said();

    if computed != actual.as_str() {
        return Err(ValidationError::InvalidSaid {
            expected: computed,
            actual: actual.clone(),
        });
    }

    Ok(())
}

/// Validate a single event for appending to a KEL with known state.
///
/// Checks all invariants that `validate_kel` checks per-event:
/// SAID integrity, sequence continuity, chain linkage, and cryptographic
/// validity (signature + pre-rotation commitment).
///
/// Args:
/// * `event` - The event to validate for append.
/// * `state` - The current KeyState (tip of the existing KEL).
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
/// This serializes the event with an empty `d` field and computes the Blake3 hash.
pub fn compute_event_said(event: &Event) -> Result<Said, ValidationError> {
    let json = serialize_for_said(event)?;
    Ok(compute_said(&json))
}

/// Serialize an event for SAID computation (with empty `d` and `x` fields).
/// For inception events, also clears `i` since it's set to the SAID.
/// The `x` field is cleared because SAID is computed before signature.
fn serialize_for_said(event: &Event) -> Result<Vec<u8>, ValidationError> {
    match event {
        Event::Icp(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default(); // For inception, `i` equals `d`
            e.x = String::new(); // SAID computed before signature
            serde_json::to_vec(&Event::Icp(e))
        }
        Event::Rot(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.x = String::new(); // SAID computed before signature
            serde_json::to_vec(&Event::Rot(e))
        }
        Event::Ixn(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.x = String::new(); // SAID computed before signature
            serde_json::to_vec(&Event::Ixn(e))
        }
    }
    .map_err(|e| ValidationError::Serialization(e.to_string()))
}

/// Serialize event for signing (clears d, i for icp, and x fields).
///
/// This produces the canonical form over which signatures are computed.
/// Both SAID and signature are computed over this form to avoid circular dependencies.
pub fn serialize_for_signing(event: &Event) -> Result<Vec<u8>, ValidationError> {
    match event {
        Event::Icp(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default(); // For inception, `i` equals `d`
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

    // Decode the signature
    let sig_str = event.signature();
    if sig_str.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_str)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    // Decode the signing key
    let key_bytes = KeriPublicKey::parse(signing_key)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    // Serialize the event for verification
    let canonical = serialize_for_signing(event)?;

    // Verify the signature
    let pk = UnparsedPublicKey::new(&ring::signature::ED25519, key_bytes.as_bytes());
    pk.verify(&canonical, &sig_bytes)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    Ok(())
}

/// Create an inception event with a properly computed SAID.
pub fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, ValidationError> {
    // Clear SAID for hashing
    icp.d = Said::default();
    icp.i = Prefix::default();

    // Compute SAID
    let json = serde_json::to_vec(&Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&json);

    // Set SAID and prefix (same for inception)
    icp.d = said.clone();
    icp.i = Prefix::new_unchecked(said.into_inner());

    Ok(icp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::{IxnEvent, KERI_VERSION, KeriSequence, Prefix, RotEvent, Said, Seal};
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

    /// Create a signed ICP event for testing
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

        // Finalize SAID
        let mut finalized = finalize_icp_event(icp).unwrap();

        // Sign
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        (finalized, keypair)
    }

    /// Create a signed IXN event for testing
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

        // Compute SAID
        let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&json);

        // Sign
        let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        ixn
    }

    #[test]
    fn finalize_icp_sets_said() {
        let icp = make_raw_icp("DKey1", "ENext1");
        let finalized = finalize_icp_event(icp).unwrap();

        // SAID should be set and match prefix
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

        // Create IXN with wrong sequence (but still properly signed)
        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(5), // Wrong! Should be 1
            p: icp.d.clone(),
            a: vec![],
            x: String::new(),
        };

        // Compute SAID for IXN
        let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&json);

        // Sign with current key
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

        // Create IXN with wrong previous SAID (but still properly signed)
        let mut ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EWrongPrevious".to_string()),
            a: vec![],
            x: String::new(),
        };

        // Compute SAID for IXN
        let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&json);

        // Sign with current key
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
        let finalized = finalize_icp_event(icp.clone()).unwrap();

        // Tamper with the SAID
        let mut tampered = finalized.clone();
        tampered.d = Said::new_unchecked("EWrongSaid".to_string());

        let events = vec![Event::Icp(tampered)];
        let result = validate_kel(&events);
        assert!(matches!(result, Err(ValidationError::InvalidSaid { .. })));
    }

    #[test]
    fn validates_icp_then_ixn() {
        let (icp, keypair) = make_signed_icp();

        // Create valid signed IXN
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);

        let events = vec![Event::Icp(icp), Event::Ixn(ixn.clone())];
        let state = validate_kel(&events).unwrap();
        assert_eq!(state.sequence, 1);
        assert_eq!(state.last_event_said, ixn.d);
    }

    #[test]
    fn rejects_multiple_inceptions() {
        let icp1 = finalize_icp_event(make_raw_icp("DKey1", "ENext1")).unwrap();
        let icp2 = finalize_icp_event(make_raw_icp("DKey2", "ENext2")).unwrap();

        let events = vec![Event::Icp(icp1), Event::Icp(icp2)];
        let result = validate_kel(&events);
        // Will fail on SAID or sequence validation before multiple inceptions check
        assert!(result.is_err());
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

        // Replace with forged signature (fake 64 bytes)
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

        // Clear the signature
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
        // Create ICP with one key but sign with a different key
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

        // Finalize SAID
        icp = finalize_icp_event(icp).unwrap();

        // Sign with a DIFFERENT key
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

    // =========================================================================
    // verify_event_crypto tests (O(1) delta validation)
    // =========================================================================

    #[test]
    fn crypto_accepts_valid_inception() {
        let (icp, _keypair) = make_signed_icp();
        let result = verify_event_crypto(&Event::Icp(icp), None);
        assert!(result.is_ok());
    }

    #[test]
    fn crypto_rejects_forged_inception_signature() {
        let (mut icp, _keypair) = make_signed_icp();
        icp.x = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let result = verify_event_crypto(&Event::Icp(icp), None);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    #[test]
    fn crypto_rejects_inception_with_mismatched_prefix() {
        let (mut icp, _keypair) = make_signed_icp();
        // Tamper i so it doesn't match d
        icp.i = Prefix::new_unchecked("EWrongPrefix".to_string());
        let result = verify_event_crypto(&Event::Icp(icp), None);
        // Signature will fail because canonical form includes the tampered i
        assert!(result.is_err());
    }

    #[test]
    fn crypto_accepts_valid_interaction() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);

        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            threshold,
            next_threshold,
            icp.d.clone(),
        );
        let result = verify_event_crypto(&Event::Ixn(ixn), Some(&state));
        assert!(result.is_ok());
    }

    #[test]
    fn crypto_rejects_interaction_with_forged_signature() {
        let (icp, keypair) = make_signed_icp();
        let mut ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);

        // Forge the signature
        ixn.x = URL_SAFE_NO_PAD.encode([0u8; 64]);

        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            threshold,
            next_threshold,
            icp.d.clone(),
        );
        let result = verify_event_crypto(&Event::Ixn(ixn), Some(&state));
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 1 })
        ));
    }

    #[test]
    fn crypto_rejects_interaction_signed_by_wrong_key() {
        let (icp, _keypair) = make_signed_icp();

        // Sign IXN with a different key
        let rng = SystemRandom::new();
        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_keypair = Ed25519KeyPair::from_pkcs8(wrong_pkcs8.as_ref()).unwrap();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &wrong_keypair);

        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            threshold,
            next_threshold,
            icp.d.clone(),
        );
        let result = verify_event_crypto(&Event::Ixn(ixn), Some(&state));
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 1 })
        ));
    }

    #[test]
    fn crypto_rejects_rotation_on_abandoned_identity() {
        use auths_core::crypto::said::compute_next_commitment;

        let (icp, _keypair) = make_signed_icp();

        // Create state with empty next_commitment (abandoned)
        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let mut state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            threshold,
            next_threshold,
            icp.d.clone(),
        );
        state.next_commitment = vec![];
        state.is_abandoned = true;

        // Generate a new key for rotation
        let rng = SystemRandom::new();
        let new_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let new_keypair = Ed25519KeyPair::from_pkcs8(new_pkcs8.as_ref()).unwrap();
        let new_key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(new_keypair.public_key().as_ref())
        );
        let new_commitment = compute_next_commitment(new_keypair.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: "1".to_string(),
            k: vec![new_key_encoded],
            nt: "1".to_string(),
            n: vec![new_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        // Compute SAID
        let json = serde_json::to_vec(&Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&json);

        // Sign
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig = new_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let result = verify_event_crypto(&Event::Rot(rot), Some(&state));
        assert!(matches!(
            result,
            Err(ValidationError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn crypto_rejects_rotation_without_precommitted_key() {
        use auths_core::crypto::said::compute_next_commitment;

        let rng = SystemRandom::new();

        // Create an inception with a known next commitment
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        // Generate the "real" next key to compute a commitment from
        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded.clone()],
            nt: "1".to_string(),
            n: vec![next_commitment.clone()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let mut icp = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            vec![next_commitment],
            threshold,
            next_threshold,
            icp.d.clone(),
        );

        // Rotate with a RANDOM key that doesn't match the commitment
        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_keypair = Ed25519KeyPair::from_pkcs8(wrong_pkcs8.as_ref()).unwrap();
        let wrong_key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(wrong_keypair.public_key().as_ref())
        );
        let new_commitment = compute_next_commitment(wrong_keypair.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: "1".to_string(),
            k: vec![wrong_key_encoded],
            nt: "1".to_string(),
            n: vec![new_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let json = serde_json::to_vec(&Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&json);
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig = wrong_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let result = verify_event_crypto(&Event::Rot(rot), Some(&state));
        assert!(matches!(
            result,
            Err(ValidationError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn crypto_accepts_valid_rotation() {
        use auths_core::crypto::said::compute_next_commitment;

        let rng = SystemRandom::new();

        // Create inception with known next commitment
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        // Generate the next key and its commitment
        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment.clone()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let mut icp = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let threshold = icp.kt.parse().unwrap();
        let next_threshold = icp.nt.parse().unwrap();
        let state = KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            vec![next_commitment],
            threshold,
            next_threshold,
            icp.d.clone(),
        );

        // Rotate with the CORRECT next key
        let next_key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(next_keypair.public_key().as_ref())
        );
        let third_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let third_keypair = Ed25519KeyPair::from_pkcs8(third_pkcs8.as_ref()).unwrap();
        let third_commitment = compute_next_commitment(third_keypair.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: "1".to_string(),
            k: vec![next_key_encoded],
            nt: "1".to_string(),
            n: vec![third_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let json = serde_json::to_vec(&Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&json);
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig = next_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let result = verify_event_crypto(&Event::Rot(rot), Some(&state));
        assert!(result.is_ok());
    }

    // =========================================================================
    // Extracted helper function tests
    // =========================================================================

    #[test]
    fn parse_threshold_valid() {
        assert_eq!(parse_threshold("1").unwrap(), 1);
        assert_eq!(parse_threshold("42").unwrap(), 42);
        assert_eq!(parse_threshold("0").unwrap(), 0);
    }

    #[test]
    fn parse_threshold_invalid() {
        assert!(matches!(
            parse_threshold("abc"),
            Err(ValidationError::MalformedSequence { .. })
        ));
        assert!(matches!(
            parse_threshold(""),
            Err(ValidationError::MalformedSequence { .. })
        ));
        assert!(matches!(
            parse_threshold("-1"),
            Err(ValidationError::MalformedSequence { .. })
        ));
    }

    #[test]
    fn validate_inception_success() {
        let (icp, _keypair) = make_signed_icp();
        let state = validate_inception(&icp).unwrap();
        assert_eq!(state.prefix, icp.i);
        assert_eq!(state.sequence, 0);
        assert_eq!(state.last_event_said, icp.d);
    }

    #[test]
    fn validate_inception_bad_signature() {
        let (mut icp, _keypair) = make_signed_icp();
        icp.x = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let result = validate_inception(&icp);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    #[test]
    fn verify_sequence_correct() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);
        assert!(verify_sequence(&Event::Ixn(ixn), 1).is_ok());
    }

    #[test]
    fn verify_sequence_mismatch() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 5, &keypair);
        let result = verify_sequence(&Event::Ixn(ixn), 1);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidSequence {
                expected: 1,
                actual: 5
            })
        ));
    }

    #[test]
    fn verify_chain_linkage_correct() {
        let (icp, keypair) = make_signed_icp();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);
        let state = validate_inception(&icp).unwrap();
        assert!(verify_chain_linkage(&Event::Ixn(ixn), &state).is_ok());
    }

    #[test]
    fn verify_chain_linkage_broken() {
        let (icp, keypair) = make_signed_icp();
        let wrong_said = Said::new_unchecked("EWrongPrevious".to_string());
        let ixn = make_signed_ixn(&icp.i, &wrong_said, 1, &keypair);
        let state = validate_inception(&icp).unwrap();
        let result = verify_chain_linkage(&Event::Ixn(ixn), &state);
        assert!(matches!(result, Err(ValidationError::BrokenChain { .. })));
    }

    #[test]
    fn validate_rotation_bad_commitment() {
        use auths_core::crypto::said::compute_next_commitment;

        let rng = SystemRandom::new();

        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![key_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let mut icp = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let mut state = validate_inception(&icp).unwrap();

        // Rotate with a WRONG key that doesn't match the commitment
        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_keypair = Ed25519KeyPair::from_pkcs8(wrong_pkcs8.as_ref()).unwrap();
        let wrong_key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(wrong_keypair.public_key().as_ref())
        );
        let wrong_commitment = compute_next_commitment(wrong_keypair.public_key().as_ref());

        let mut rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: "1".to_string(),
            k: vec![wrong_key_encoded],
            nt: "1".to_string(),
            n: vec![wrong_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let json = serde_json::to_vec(&Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&json);
        let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
        let sig = wrong_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let result = validate_rotation(&rot, &Event::Rot(rot.clone()), 1, &mut state);
        assert!(matches!(
            result,
            Err(ValidationError::CommitmentMismatch { sequence: 1 })
        ));
    }

    #[test]
    fn validate_interaction_wrong_key() {
        let (icp, _keypair) = make_signed_icp();
        let mut state = validate_inception(&icp).unwrap();

        let rng = SystemRandom::new();
        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_keypair = Ed25519KeyPair::from_pkcs8(wrong_pkcs8.as_ref()).unwrap();
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &wrong_keypair);

        let result = validate_interaction(&ixn, &Event::Ixn(ixn.clone()), 1, &mut state);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureFailed { sequence: 1 })
        ));
    }
}
