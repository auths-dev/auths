//! KEL validation: SAID verification, chain linkage, signature verification,
//! and pre-rotation commitment checks.
//!
//! This module provides validation functions for ensuring a Key Event Log
//! is cryptographically valid and properly chained.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::crypto::verify_commitment;
use crate::events::{Event, IcpEvent, IxnEvent, RotEvent, Seal};
use crate::keys::KeriPublicKey;
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

    /// The identity has been abandoned (empty next commitment) and no more events are allowed.
    #[error("Identity abandoned at sequence {sequence}, no more events allowed")]
    AbandonedIdentity {
        /// The sequence number of the rejected event.
        sequence: u64,
    },

    /// An interaction event was found in an establishment-only KEL.
    #[error("Interaction event at sequence {sequence} rejected: KEL is establishment-only (EO)")]
    EstablishmentOnly {
        /// The sequence number of the rejected event.
        sequence: u64,
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
pub fn validate_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    if events.is_empty() {
        return Err(ValidationError::EmptyKel);
    }

    let Event::Icp(icp) = &events[0] else {
        return Err(ValidationError::NotInception);
    };

    verify_event_said(&events[0])?;
    let mut state = validate_inception(icp)?;

    // Non-transferable identities (inception n is empty) cannot have subsequent events
    if icp.n.is_empty() && events.len() > 1 {
        return Err(ValidationError::NonTransferable);
    }

    // Check if this is an establishment-only KEL
    let establishment_only = icp.c.contains(&ConfigTrait::EstablishmentOnly);

    for (idx, event) in events.iter().enumerate().skip(1) {
        let expected_seq = idx as u64;

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
            Event::Rot(rot) => validate_rotation(rot, event, expected_seq, &mut state)?,
            Event::Ixn(ixn) => validate_interaction(ixn, event, expected_seq, &mut state)?,
            Event::Icp(_) | Event::Dip(_) => return Err(ValidationError::MultipleInceptions),
            // Delegated rotation validation requires cross-KEL seal check (fn-107.12)
            Event::Drt(_) => {
                return Err(ValidationError::Serialization(
                    "delegated rotation (drt) validation not yet implemented".to_string(),
                ));
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
    verify_event_signature(
        &Event::Icp(icp.clone()),
        icp.k
            .first()
            .ok_or(ValidationError::SignatureFailed { sequence: 0 })?
            .as_str(),
    )?;

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
        verify_event_signature(event, rot.k[0].as_str())?;
    }

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
    event: &Event,
    sequence: u64,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    let current_key = state
        .current_key()
        .ok_or(ValidationError::SignatureFailed { sequence })?;
    verify_event_signature(event, current_key.as_str())?;
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
            verify_event_signature(event, key.as_str())?;

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
            verify_event_signature(event, rot.k[0].as_str())?;

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

            let current_key = state
                .current_key()
                .ok_or(ValidationError::SignatureFailed { sequence })?;
            verify_event_signature(event, current_key.as_str())?;

            Ok(())
        }
        // Delegated events use same crypto verification as their non-delegated counterparts
        Event::Dip(dip) => {
            let key = dip
                .k
                .first()
                .ok_or(ValidationError::SignatureFailed { sequence: 0 })?;
            verify_event_signature(event, key.as_str())?;
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
            verify_event_signature(event, drt.k[0].as_str())?;
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
        Event::Dip(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.i = Prefix::default();
            e.x = String::new();
            serde_json::to_vec(&Event::Dip(e))
        }
        Event::Drt(e) => {
            let mut e = e.clone();
            e.d = Said::default();
            e.x = String::new();
            serde_json::to_vec(&Event::Drt(e))
        }
    }
    .map_err(|e| ValidationError::Serialization(e.to_string()))
}

/// Verify an event's signature using the specified key and explicit signature bytes.
///
/// Args:
/// * `event` - The event whose canonical form to verify against.
/// * `signing_key` - CESR-encoded public key string.
/// * `sig_bytes` - Raw signature bytes (64 bytes for Ed25519).
fn verify_signature_bytes(
    event: &Event,
    signing_key: &str,
    sig_bytes: &[u8],
) -> Result<(), ValidationError> {
    let sequence = event.sequence().value();

    let key = KeriPublicKey::parse(signing_key)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    let canonical = serialize_for_signing(event)?;

    key.verify_signature(&canonical, sig_bytes)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    Ok(())
}

/// Verify an event's signature using the legacy `x` field.
///
/// Reads the signature from `event.signature()` (the `x` field).
/// Prefer `verify_signature_bytes` with explicit sig bytes for new code.
fn verify_event_signature(event: &Event, signing_key: &str) -> Result<(), ValidationError> {
    let sequence = event.sequence().value();

    let sig_str = event.signature();
    if sig_str.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_str)
        .map_err(|_| ValidationError::SignatureFailed { sequence })?;

    verify_signature_bytes(event, signing_key, &sig_bytes)
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
        // The verified indices may map differently in the prior key context.
        // For now, use "both same" semantics (same indices apply to both lists).
        // Full "current only" vs "both same" distinction requires CESR indexed
        // signature type codes, which we'll implement when CESR attachments land.
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
pub fn find_seal_in_kel(events: &[Event], digest: &str) -> Option<u64> {
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
    use crate::events::{KeriSequence, Seal};
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

    fn sign_event(event: &Event, kp: &Ed25519KeyPair) -> String {
        let canonical = serialize_for_signing(event).unwrap();
        URL_SAFE_NO_PAD.encode(kp.sign(&canonical).as_ref())
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
            x: String::new(),
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
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
            p: prev_said.clone(),
            a: vec![Seal::digest("EAttest")],
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
            v: VersionString::placeholder(),
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
            v: VersionString::placeholder(),
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
            v: VersionString::placeholder(),
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
            x: String::new(),
        };

        customize(&mut icp);

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

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
            x: String::new(),
        };
        let val = serde_json::to_value(Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&val).unwrap();
        rot.x = sign_event(&Event::Rot(rot.clone()), &kp2);

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
                x: String::new(),
            };

            let mut finalized = finalize_icp_event(icp).unwrap();
            let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
            let sig = keypair.sign(&canonical);
            finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

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
                x: String::new(),
            };

            let mut finalized = finalize_icp_event(icp).unwrap();
            let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
            let sig = keypair.sign(&canonical);
            finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

            let events = vec![Event::Icp(finalized)];
            (keypair, validate_kel(&events))
        };
        assert!(
            matches!(result, Err(ValidationError::InvalidBackerThreshold { .. })),
            "expected InvalidBackerThreshold, got: {result:?}"
        );
    }
}
