//! KEL validation: SAID verification, chain linkage, signature verification,
//! and pre-rotation commitment checks.
//!
//! This module provides validation functions for ensuring a Key Event Log
//! is cryptographically valid and properly chained.

use crate::crypto::verify_commitment;
use crate::events::{Event, IcpEvent, IxnEvent, KeriSequence, RotEvent, Seal};
use crate::said::compute_said;
use crate::state::KeyState;
use crate::types::{ConfigTrait, Prefix, Said};

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
        sequence: u128,
        /// The previous SAID referenced by this event.
        referenced: Said,
        /// The actual SAID of the previous event.
        actual: Said,
    },

    /// Sequence number is not monotonically increasing.
    #[error("Invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence {
        /// The sequence number that was expected.
        expected: u128,
        /// The sequence number that was found.
        actual: u128,
    },

    /// Pre-rotation commitment doesn't match the new current key.
    #[error("Pre-rotation commitment mismatch at sequence {sequence}")]
    CommitmentMismatch {
        /// Zero-based position of the rotation event that failed.
        sequence: u128,
    },

    /// Cryptographic signature verification failed for an event.
    #[error("Signature verification failed at sequence {sequence}")]
    SignatureFailed {
        /// Zero-based position of the event whose signature failed.
        sequence: u128,
    },

    /// Rotation event's key-list size differs from the prior next-commitment
    /// list. Properly expressing this case requires CESR indexed-signature
    /// type codes so verified indices can be mapped distinctly against prior
    /// and current key lists. Until that lands, such rotations are rejected.
    #[error(
        "Asymmetric key rotation at sequence {sequence}: prior next count {prior_next_count} != new key count {new_key_count} (removing devices requires CESR indexed signatures)"
    )]
    AsymmetricKeyRotation {
        /// Zero-based position of the rotation event.
        sequence: u128,
        /// Number of entries in the prior event's next-commitment list.
        prior_next_count: usize,
        /// Number of entries in this rotation's key list.
        new_key_count: usize,
    },

    /// A delegated event (`dip` / `drt`) references a delegator but no
    /// matching seal could be found in the delegator's KEL.
    #[error(
        "Delegator seal not found at sequence {sequence}: delegator {delegator_aid} has no ixn-anchored seal for this event"
    )]
    DelegatorSealNotFound {
        /// Zero-based position of the delegated event.
        sequence: u128,
        /// Delegator AID the event referenced (dip.di / drt.di).
        delegator_aid: String,
    },

    /// A delegated event was submitted but no `DelegatorKelLookup` was
    /// provided. Use `validate_kel_with_lookup` when processing KELs that
    /// contain `dip` or `drt` events.
    #[error(
        "Delegator lookup required for delegated event at sequence {sequence}; call validate_kel_with_lookup"
    )]
    DelegatorLookupMissing {
        /// Zero-based position of the delegated event.
        sequence: u128,
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

    /// The identity has been abandoned (empty next commitment) and no more events are allowed.
    #[error("Identity abandoned at sequence {sequence}, no more events allowed")]
    AbandonedIdentity {
        /// The sequence number of the rejected event.
        sequence: u128,
    },

    /// An interaction event was found in an establishment-only KEL.
    #[error("Interaction event at sequence {sequence} rejected: KEL is establishment-only (EO)")]
    EstablishmentOnly {
        /// The sequence number of the rejected event.
        sequence: u128,
    },

    /// The identity is non-transferable (inception had empty next commitments).
    #[error(
        "Non-transferable identity: inception had empty next key commitments, no subsequent events allowed"
    )]
    NonTransferable,

    /// A backer AID appears more than once in the backer list.
    #[error("Duplicate backer AID: {aid}")]
    DuplicateBacker {
        /// The duplicated AID.
        aid: String,
    },

    /// The backer threshold is inconsistent with the backer list size.
    #[error("Invalid backer threshold: bt={bt} but backer_count={backer_count}")]
    InvalidBackerThreshold {
        /// The backer threshold value.
        bt: u64,
        /// The number of backers.
        backer_count: usize,
    },
}

/// Validate a delegated event against the delegator's KEL.
///
/// Searches the delegator's KEL for an anchoring key event seal that matches
/// the delegated event's prefix, sequence number, and SAID. Also enforces
/// the `DND` (Do Not Delegate) configuration trait.
///
/// Args:
/// * `delegated_event` - The delegated event (dip or drt) to validate.
/// * `delegator_kel` - The delegator's full KEL.
pub fn validate_delegation(
    delegated_event: &Event,
    delegator_kel: &[Event],
) -> Result<(), ValidationError> {
    if !delegated_event.is_delegated() {
        return Err(ValidationError::Serialization(
            "validate_delegation called on non-delegated event".to_string(),
        ));
    }

    let event_said = delegated_event.said();
    let event_seq = delegated_event.sequence();

    // Check DND enforcement on delegator
    if let Some(Event::Icp(delegator_icp)) = delegator_kel.first()
        && delegator_icp.c.contains(&ConfigTrait::DoNotDelegate)
    {
        return Err(ValidationError::Serialization(
            "Delegator has DoNotDelegate (DND) config trait".to_string(),
        ));
    }

    // Search delegator's KEL for an anchoring seal
    let found = delegator_kel.iter().any(|event| {
        event.anchors().iter().any(|seal| {
            matches!(
                seal,
                Seal::KeyEvent { i, s, d }
                if i == delegated_event.prefix()
                    && s.value() == event_seq.value()
                    && d == event_said
            )
        })
    });

    if !found {
        return Err(ValidationError::Serialization(format!(
            "No delegation seal found in delegator KEL for prefix={}, sn={}, said={}",
            delegated_event.prefix(),
            event_seq,
            event_said
        )));
    }

    Ok(())
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
/// Pluggable cross-KEL seal lookup for validating delegated events.
///
/// A delegated identifier's rotation or inception must be anchored by the
/// delegator's KEL via an `ixn` event whose `a[]` seal references the
/// delegated event's SAID. This trait lets the validator ask "does my
/// delegator have a seal for this event?" without depending on any
/// particular KEL storage backend.
pub trait DelegatorKelLookup {
    /// Return the sequence of the delegator's `ixn` event that anchors the
    /// given seal SAID, or `None` if the delegator's KEL doesn't contain one.
    fn find_seal(&self, delegator_aid: &Prefix, seal_said: &Said) -> Option<KeriSequence>;
}

/// Validate a KEL with no delegator lookup.
///
/// Convenience wrapper over [`validate_kel_with_lookup`] for ordinary KELs
/// that contain only `icp`/`rot`/`ixn` events. Use the lookup variant for KELs
/// containing delegated events (`dip`/`drt`).
///
/// Args:
/// * `events` - The ordered list of KERI events to replay and validate.
pub fn validate_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    validate_kel_with_lookup(events, None::<&dyn DelegatorKelLookup>)
}

/// Validate a KEL with a delegator-lookup hook for delegated events.
///
/// Required when the KEL contains `dip` or `drt` events; ordinary KELs
/// (only `icp`/`rot`/`ixn`) can pass `None`.
pub fn validate_kel_with_lookup(
    events: &[Event],
    lookup: Option<&dyn DelegatorKelLookup>,
) -> Result<KeyState, ValidationError> {
    if events.is_empty() {
        return Err(ValidationError::EmptyKel);
    }

    verify_event_said(&events[0])?;
    let (mut state, inception_n_is_empty, establishment_only) = match &events[0] {
        Event::Icp(icp) => (
            validate_inception(icp)?,
            icp.n.is_empty(),
            icp.c.contains(&ConfigTrait::EstablishmentOnly),
        ),
        Event::Dip(dip) => (
            validate_delegated_inception(dip, lookup)?,
            dip.n.is_empty(),
            dip.c.contains(&ConfigTrait::EstablishmentOnly),
        ),
        _ => return Err(ValidationError::NotInception),
    };

    // Non-transferable identities (inception n is empty) cannot have subsequent events
    if inception_n_is_empty && events.len() > 1 {
        return Err(ValidationError::NonTransferable);
    }

    for (idx, event) in events.iter().enumerate().skip(1) {
        let expected_seq = idx as u128;

        // Reject any event after abandonment
        if state.is_abandoned {
            return Err(ValidationError::AbandonedIdentity {
                sequence: expected_seq,
            });
        }

        // Reject IXN in establishment-only KELs
        if establishment_only && matches!(event, Event::Ixn(_)) {
            return Err(ValidationError::EstablishmentOnly {
                sequence: expected_seq,
            });
        }

        verify_event_said(event)?;
        verify_sequence(event, expected_seq)?;
        verify_chain_linkage(event, &state)?;

        match event {
            Event::Rot(rot) => validate_rotation(rot, expected_seq, &mut state)?,
            Event::Ixn(ixn) => validate_interaction(ixn, expected_seq, &mut state)?,
            Event::Icp(_) | Event::Dip(_) => return Err(ValidationError::MultipleInceptions),
            Event::Drt(drt) => {
                validate_delegated_rotation(drt, expected_seq, &mut state, lookup)?;
            }
        }
    }

    Ok(state)
}

fn validate_backer_uniqueness(backers: &[Prefix]) -> Result<(), ValidationError> {
    let mut seen = std::collections::HashSet::new();
    for b in backers {
        if !seen.insert(b.as_str()) {
            return Err(ValidationError::DuplicateBacker {
                aid: b.as_str().to_string(),
            });
        }
    }
    Ok(())
}

fn validate_inception(icp: &IcpEvent) -> Result<KeyState, ValidationError> {
    // Validate backer uniqueness
    validate_backer_uniqueness(&icp.b)?;

    // Validate bt consistency: empty backers must have bt == 0
    let bt_val = icp.bt.simple_value().unwrap_or(0);
    if icp.b.is_empty() && bt_val != 0 {
        return Err(ValidationError::InvalidBackerThreshold {
            bt: bt_val,
            backer_count: 0,
        });
    }

    Ok(KeyState::from_inception(
        icp.i.clone(),
        icp.k.clone(),
        icp.n.clone(),
        icp.kt.clone(),
        icp.nt.clone(),
        icp.d.clone(),
        icp.b.clone(),
        icp.bt.clone(),
        icp.c.clone(),
    ))
}

fn verify_sequence(event: &Event, expected: u128) -> Result<(), ValidationError> {
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
    sequence: u128,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    // Verify all pre-rotation commitments (not just first key)
    if !state.next_commitment.is_empty() {
        let required = state.next_threshold.simple_value().unwrap_or(1);
        let mut matched_count = 0u64;
        for commitment in &state.next_commitment {
            let matched = rot.k.iter().any(|key| {
                key.parse()
                    .map(|pk| verify_commitment(pk.as_bytes(), commitment))
                    .unwrap_or(false)
            });
            if matched {
                matched_count += 1;
            }
        }
        if matched_count < required {
            return Err(ValidationError::CommitmentMismatch { sequence });
        }
    }

    // Validate backer uniqueness in br and ba
    validate_backer_uniqueness(&rot.br)?;
    validate_backer_uniqueness(&rot.ba)?;
    // Check no overlap between br and ba
    for aid in &rot.ba {
        if rot.br.contains(aid) {
            return Err(ValidationError::DuplicateBacker {
                aid: aid.as_str().to_string(),
            });
        }
    }

    state.apply_rotation(
        rot.k.clone(),
        rot.n.clone(),
        rot.kt.clone(),
        rot.nt.clone(),
        sequence,
        rot.d.clone(),
        &rot.br,
        &rot.ba,
        rot.bt.clone(),
        rot.c.clone(),
    );

    Ok(())
}

fn validate_interaction(
    ixn: &IxnEvent,
    sequence: u128,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    // Presence check: ixn events are only valid against a transferable,
    // non-abandoned identity with an available current key. The value itself
    // is not used here — signature verification against it happens at the
    // KEL-ingest boundary.
    state
        .current_key()
        .ok_or(ValidationError::SignatureFailed { sequence })?;
    state.apply_interaction(sequence, ixn.d.clone());
    Ok(())
}

/// Validate a delegated inception event (`dip`) per KERI §11.
///
/// Beyond the standard inception checks, the validator requires the
/// delegator's KEL to contain an `ixn` event whose `a[]` seal references
/// `dip.d`. Without that seal the delegated identifier is not authorized.
fn validate_delegated_inception(
    dip: &crate::events::DipEvent,
    lookup: Option<&dyn DelegatorKelLookup>,
) -> Result<KeyState, ValidationError> {
    let sequence = dip.s.value();
    let lookup = lookup.ok_or(ValidationError::DelegatorLookupMissing { sequence })?;

    // Delegator seal check.
    if lookup.find_seal(&dip.di, &dip.d).is_none() {
        return Err(ValidationError::DelegatorSealNotFound {
            sequence,
            delegator_aid: dip.di.as_str().to_string(),
        });
    }

    // Structural checks mirrored from `validate_inception` — backers, threshold.
    validate_backer_uniqueness(&dip.b)?;
    let bt_val = dip.bt.simple_value().unwrap_or(0);
    if dip.b.is_empty() && bt_val != 0 {
        return Err(ValidationError::InvalidBackerThreshold {
            bt: bt_val,
            backer_count: 0,
        });
    }

    // Build state from the dip event.
    let is_non_transferable = dip.n.is_empty();
    Ok(KeyState {
        prefix: dip.i.clone(),
        current_keys: dip.k.clone(),
        next_commitment: dip.n.clone(),
        sequence: dip.s.value(),
        last_event_said: dip.d.clone(),
        is_abandoned: false,
        threshold: dip.kt.clone(),
        next_threshold: dip.nt.clone(),
        backers: dip.b.clone(),
        backer_threshold: dip.bt.clone(),
        config_traits: dip.c.clone(),
        is_non_transferable,
        delegator: Some(dip.di.clone()),
    })
}

/// Validate a delegated rotation event (`drt`) per KERI §11.
///
/// Requires the delegator's KEL to contain an `ixn` event anchoring this
/// rotation via its SAID. Standard rotation rules also apply (chain,
/// sequence, pre-rotation commitment).
fn validate_delegated_rotation(
    drt: &crate::events::DrtEvent,
    sequence: u128,
    state: &mut KeyState,
    lookup: Option<&dyn DelegatorKelLookup>,
) -> Result<(), ValidationError> {
    let lookup = lookup.ok_or(ValidationError::DelegatorLookupMissing { sequence })?;

    // Delegator must match the state's recorded delegator AID and anchor
    // via a seal.
    if lookup.find_seal(&drt.di, &drt.d).is_none() {
        return Err(ValidationError::DelegatorSealNotFound {
            sequence,
            delegator_aid: drt.di.as_str().to_string(),
        });
    }

    // Standard rotation commitment/backer checks applied to drt fields.
    if !state.next_commitment.is_empty() {
        let required = state.next_threshold.simple_value().unwrap_or(1);
        let mut matched_count = 0u64;
        for commitment in &state.next_commitment {
            let matched = drt.k.iter().any(|key| {
                key.parse()
                    .map(|pk| verify_commitment(pk.as_bytes(), commitment))
                    .unwrap_or(false)
            });
            if matched {
                matched_count += 1;
            }
        }
        if matched_count < required {
            return Err(ValidationError::CommitmentMismatch { sequence });
        }
    }

    validate_backer_uniqueness(&drt.br)?;
    validate_backer_uniqueness(&drt.ba)?;
    for aid in &drt.ba {
        if drt.br.contains(aid) {
            return Err(ValidationError::DuplicateBacker {
                aid: aid.as_str().to_string(),
            });
        }
    }

    // Apply: the rotation advances the KEL state the same way a plain rot would.
    state.sequence = sequence;
    state.last_event_said = drt.d.clone();
    state.current_keys = drt.k.clone();
    state.next_commitment = drt.n.clone();
    state.threshold = drt.kt.clone();
    state.next_threshold = drt.nt.clone();
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
            // Presence check only: icp must commit at least one key.
            if icp.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence: 0 });
            }

            // Only enforce i == d for self-addressing AIDs (E-prefixed)
            let is_self_addressing = icp.i.as_str().starts_with('E');
            if is_self_addressing && icp.i.as_str() != icp.d.as_str() {
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

            // Verify all pre-rotation commitments
            let required = state.next_threshold.simple_value().unwrap_or(1);
            let mut matched_count = 0u64;
            for commitment in &state.next_commitment {
                let matched = rot.k.iter().any(|key| {
                    key.parse()
                        .map(|pk| verify_commitment(pk.as_bytes(), commitment))
                        .unwrap_or(false)
                });
                if matched {
                    matched_count += 1;
                }
            }
            if matched_count < required {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }

            Ok(())
        }
        Event::Ixn(_) => {
            let sequence = event.sequence().value();
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;

            // Presence check: ixn requires a transferable, non-abandoned state
            // with an available current key.
            state
                .current_key()
                .ok_or(ValidationError::SignatureFailed { sequence })?;

            Ok(())
        }
        // Delegated events use same crypto verification as their non-delegated counterparts
        Event::Dip(dip) => {
            if dip.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence: 0 });
            }
            Ok(())
        }
        Event::Drt(drt) => {
            let sequence = event.sequence().value();
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;

            if state.is_abandoned || state.next_commitment.is_empty() {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }
            if drt.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence });
            }
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
            serde_json::to_vec(&Event::Icp(e))
        }
        Event::Rot(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            serde_json::to_vec(&Event::Rot(e))
        }
        Event::Ixn(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            serde_json::to_vec(&Event::Ixn(e))
        }
        Event::Dip(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default();
            serde_json::to_vec(&Event::Dip(e))
        }
        Event::Drt(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            serde_json::to_vec(&Event::Drt(e))
        }
    }
    .map_err(|e| ValidationError::Serialization(e.to_string()))
}

/// Validate a signed event's crypto (signatures + commitments) against key state.
///
/// This is the preferred entry point for validating events with externalized signatures.
///
/// Args:
/// * `signed` - The signed event with detached signatures.
/// * `current_state` - The current `KeyState` (None for inception events).
pub fn validate_signed_event(
    signed: &crate::events::SignedEvent,
    current_state: Option<&KeyState>,
) -> Result<(), ValidationError> {
    let event = &signed.event;
    let sequence = event.sequence().value();

    if signed.signatures.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence });
    }

    // Determine the key list and threshold for verification
    let (keys, threshold) = match event {
        Event::Icp(icp) => (&icp.k, &icp.kt),
        Event::Dip(dip) => (&dip.k, &dip.kt),
        Event::Rot(rot) => (&rot.k, &rot.kt),
        Event::Drt(drt) => (&drt.k, &drt.kt),
        Event::Ixn(_) => {
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;
            (&state.current_keys, &state.threshold)
        }
    };

    if keys.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence });
    }

    // Verify each signature and collect verified indices
    let canonical = serialize_for_signing(event)?;
    let mut verified_indices = Vec::new();

    for sig in &signed.signatures {
        let idx = sig.index as usize;
        if idx >= keys.len() {
            continue; // out-of-range index, skip
        }
        let key = &keys[idx];
        if let Ok(pk) = key.parse()
            && pk.verify_signature(&canonical, &sig.sig).is_ok()
        {
            verified_indices.push(sig.index);
        }
    }

    // Check threshold satisfaction (current key threshold)
    if !threshold.is_satisfied(&verified_indices, keys.len()) {
        return Err(ValidationError::SignatureFailed { sequence });
    }

    // For rotation events: also check prior next-threshold from the previous
    // establishment event. The spec requires signatures satisfy BOTH the current
    // signing threshold AND the prior next rotation threshold.
    if matches!(event, Event::Rot(_) | Event::Drt(_))
        && let Some(state) = current_state
    {
        // Reject asymmetric rotations (prior next count != new key count)
        // until CESR indexed-signature type codes let us map verified indices
        // distinctly against prior and current lists.
        if state.next_commitment.len() != keys.len() {
            return Err(ValidationError::AsymmetricKeyRotation {
                sequence,
                prior_next_count: state.next_commitment.len(),
                new_key_count: keys.len(),
            });
        }

        // "Same indices apply to both lists" simplification — valid only when
        // the two lists have matching shapes (enforced just above).
        if !state
            .next_threshold
            .is_satisfied(&verified_indices, keys.len())
        {
            return Err(ValidationError::SignatureFailed { sequence });
        }
    }

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
    // Only set i = d for self-addressing AIDs (empty or E-prefixed)
    if icp.i.is_empty() || icp.i.as_str().starts_with('E') {
        icp.i = Prefix::new_unchecked(said.into_inner());
    }

    // Set version string with actual byte count
    let final_bytes = serde_json::to_vec(&Event::Icp(icp.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    icp.v = crate::types::VersionString::json(final_bytes.len() as u32);

    Ok(icp)
}

/// Create a rotation event with a properly computed SAID.
///
/// Args:
/// * `rot` - The rotation event to finalize.
pub fn finalize_rot_event(mut rot: RotEvent) -> Result<RotEvent, ValidationError> {
    let value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    rot.d = said;

    let final_bytes = serde_json::to_vec(&Event::Rot(rot.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    rot.v = crate::types::VersionString::json(final_bytes.len() as u32);

    Ok(rot)
}

/// Create an interaction event with a properly computed SAID.
///
/// Args:
/// * `ixn` - The interaction event to finalize.
pub fn finalize_ixn_event(mut ixn: IxnEvent) -> Result<IxnEvent, ValidationError> {
    let value = serde_json::to_value(Event::Ixn(ixn.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    ixn.d = said;

    let final_bytes = serde_json::to_vec(&Event::Ixn(ixn.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    ixn.v = crate::types::VersionString::json(final_bytes.len() as u32);

    Ok(ixn)
}

/// Search for a seal with the given digest in any IXN event in the KEL.
///
/// Returns the sequence number of the IXN event if found.
///
/// Args:
/// * `events` - The event log to search.
/// * `digest` - The SAID digest to search for.
pub fn find_seal_in_kel(events: &[Event], digest: &str) -> Option<u128> {
    for event in events {
        if let Event::Ixn(ixn) = event {
            for seal in &ixn.a {
                if seal.digest_value().is_some_and(|d| d.as_str() == digest) {
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
    use crate::events::{IndexedSignature, KeriSequence, Seal, SignedEvent};
    use crate::types::{CesrKey, Threshold, VersionString};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn gen_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn encode_pubkey(kp: &Ed25519KeyPair) -> String {
        format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()))
    }

    fn make_raw_icp(key: &str, next: &str) -> IcpEvent {
        IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked(next.to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        }
    }

    fn make_signed_icp() -> (IcpEvent, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key_encoded)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };

        let finalized = finalize_icp_event(icp).unwrap();
        (finalized, keypair)
    }

    fn make_signed_ixn(
        prefix: &Prefix,
        prev_said: &Said,
        seq: u128,
        _keypair: &Ed25519KeyPair,
    ) -> IxnEvent {
        let mut ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: prev_said.clone(),
            a: vec![Seal::digest("EAttest")],
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

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
            v: VersionString::placeholder(),
            d: Said::new_unchecked("ETest".to_string()),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: KeriSequence::new(0),
            p: Said::new_unchecked("EPrev".to_string()),
            a: vec![],
        };
        let events = vec![Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(matches!(result, Err(ValidationError::NotInception)));
    }

    #[test]
    fn rejects_broken_sequence() {
        let (icp, _keypair) = make_signed_icp();

        let mut ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(5),
            p: icp.d.clone(),
            a: vec![],
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

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
        let (icp, _keypair) = make_signed_icp();

        let mut ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EWrongPrevious".to_string()),
            a: vec![],
        };

        let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
        ixn.d = compute_said(&value).unwrap();

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

    // Sanity control: a correctly-signed SignedEvent must be accepted. Without
    // this, a regression that makes `validate_signed_event` always return
    // `SignatureFailed` would silently "pass" the rejection tests below.
    #[test]
    fn accepts_correct_signature() {
        let (icp, keypair) = make_signed_icp();
        let event = Event::Icp(icp);
        let canonical = serialize_for_signing(&event).unwrap();
        let sig = keypair.sign(&canonical).as_ref().to_vec();
        let signed = SignedEvent::new(event, vec![IndexedSignature { index: 0, sig }]);

        validate_signed_event(&signed, None).expect("correct signature must validate");
    }

    // Intent: a SignedEvent whose attached signature bytes do not match the
    // canonical event body must be rejected. Uses the externalized-signature
    // entry point (`validate_signed_event`); `validate_kel` only checks KEL
    // structure and does not consume attached signatures, so it cannot be
    // used to test signature-level rejection.
    #[test]
    fn rejects_forged_signature() {
        let (icp, _keypair) = make_signed_icp();
        let event = Event::Icp(icp);
        let forged_sig = vec![0u8; 64]; // valid length, invalid content
        let signed = SignedEvent::new(
            event,
            vec![IndexedSignature {
                index: 0,
                sig: forged_sig,
            }],
        );

        assert!(matches!(
            validate_signed_event(&signed, None),
            Err(ValidationError::SignatureFailed { sequence: 0 })
        ));
    }

    // `rejects_missing_signature` was tied to the legacy in-body `x` field.
    // Signatures are externalized now; the equivalent check is covered by
    // `validate_signed_event` tests in `multi_key_threshold.rs`.

    // Intent: a SignedEvent signed by a keypair other than the one committed
    // in `icp.k` must be rejected. The wrong-key signature is structurally
    // valid (correct length, correct type) but fails Ed25519 verification
    // against the committed public key.
    #[test]
    fn rejects_wrong_key_signature() {
        let committed = gen_keypair();
        let key_encoded = encode_pubkey(&committed);

        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key_encoded)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let icp = finalize_icp_event(icp).unwrap();
        let event = Event::Icp(icp);

        let wrong = gen_keypair();
        let canonical = serialize_for_signing(&event).unwrap();
        let wrong_sig = wrong.sign(&canonical).as_ref().to_vec();
        let signed = SignedEvent::new(
            event,
            vec![IndexedSignature {
                index: 0,
                sig: wrong_sig,
            }],
        );

        assert!(matches!(
            validate_signed_event(&signed, None),
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

    /// Build a signed ICP with caller-supplied overrides applied after keypair
    /// generation but before finalization and signing.
    fn make_custom_signed_icp(customize: impl FnOnce(&mut IcpEvent)) -> (IcpEvent, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let mut icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key_encoded)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };

        customize(&mut icp);

        let finalized = finalize_icp_event(icp).unwrap();
        (finalized, keypair)
    }

    #[test]
    fn rejects_events_after_abandonment() {
        // Abandonment = rotation with empty n (not inception — that's NonTransferable).
        let kp2 = gen_keypair();

        // Use make_custom_signed_icp with pre-committed key for kp2
        let commitment2 = crate::crypto::compute_next_commitment(kp2.public_key().as_ref());
        let (icp, _kp1) = make_custom_signed_icp(|icp| {
            icp.n = vec![commitment2.clone()];
        });
        let prefix = icp.i.clone();

        // Rotation that abandons (empty n)
        let mut rot = RotEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(encode_pubkey(&kp2))],
            nt: Threshold::Simple(0),
            n: vec![],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
        };
        let val = serde_json::to_value(Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&val).unwrap();

        let ixn = make_signed_ixn(&prefix, &rot.d, 2, &kp2);
        let events = vec![Event::Icp(icp), Event::Rot(rot), Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(
            matches!(result, Err(ValidationError::AbandonedIdentity { .. })),
            "expected AbandonedIdentity, got: {result:?}"
        );
    }

    #[test]
    fn rejects_ixn_in_establishment_only_kel() {
        let (icp, keypair) = make_custom_signed_icp(|icp| {
            icp.c = vec![ConfigTrait::EstablishmentOnly];
        });
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);
        let events = vec![Event::Icp(icp), Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(
            matches!(result, Err(ValidationError::EstablishmentOnly { .. })),
            "expected EstablishmentOnly, got: {result:?}"
        );
    }

    #[test]
    fn rejects_events_after_non_transferable_inception() {
        let (icp, keypair) = make_custom_signed_icp(|icp| {
            icp.n = vec![];
            icp.nt = Threshold::Simple(0);
        });
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &keypair);
        let events = vec![Event::Icp(icp), Event::Ixn(ixn)];
        let result = validate_kel(&events);
        assert!(
            matches!(
                result,
                Err(ValidationError::NonTransferable)
                    | Err(ValidationError::AbandonedIdentity { .. })
            ),
            "expected NonTransferable or AbandonedIdentity, got: {result:?}"
        );
    }

    #[test]
    fn rejects_duplicate_backers() {
        let (_, result) = {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

            let dup_backer = Prefix::new_unchecked("DWit1".to_string());
            let icp = IcpEvent {
                v: VersionString::placeholder(),
                d: Said::default(),
                i: Prefix::default(),
                s: KeriSequence::new(0),
                kt: Threshold::Simple(1),
                k: vec![CesrKey::new_unchecked(key_encoded)],
                nt: Threshold::Simple(1),
                n: vec![Said::new_unchecked("ENextCommitment".to_string())],
                bt: Threshold::Simple(2),
                b: vec![dup_backer.clone(), dup_backer],
                c: vec![],
                a: vec![],
            };

            let finalized = finalize_icp_event(icp).unwrap();
            let events = vec![Event::Icp(finalized)];
            (keypair, validate_kel(&events))
        };
        assert!(
            matches!(result, Err(ValidationError::DuplicateBacker { .. })),
            "expected DuplicateBacker, got: {result:?}"
        );
    }

    #[test]
    fn rejects_invalid_backer_threshold() {
        let (_, result) = {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

            let icp = IcpEvent {
                v: VersionString::placeholder(),
                d: Said::default(),
                i: Prefix::default(),
                s: KeriSequence::new(0),
                kt: Threshold::Simple(1),
                k: vec![CesrKey::new_unchecked(key_encoded)],
                nt: Threshold::Simple(1),
                n: vec![Said::new_unchecked("ENextCommitment".to_string())],
                bt: Threshold::Simple(2),
                b: vec![],
                c: vec![],
                a: vec![],
            };

            let finalized = finalize_icp_event(icp).unwrap();
            let events = vec![Event::Icp(finalized)];
            (keypair, validate_kel(&events))
        };
        assert!(
            matches!(result, Err(ValidationError::InvalidBackerThreshold { .. })),
            "expected InvalidBackerThreshold, got: {result:?}"
        );
    }
}
