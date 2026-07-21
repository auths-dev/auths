//! KEL validation: SAID verification, chain linkage, signature verification,
//! and pre-rotation commitment checks.
//!
//! This module provides validation functions for ensuring a Key Event Log
//! is cryptographically valid and properly chained.

use crate::crypto::verify_commitment;
use crate::events::{Event, IcpEvent, IxnEvent, KeriSequence, RotEvent, Seal, SourceSeal};
use crate::keys::KeriPublicKey;
use crate::said::compute_said;
use crate::state::KeyState;
use crate::types::{CesrKey, ConfigTrait, Prefix, Said, Threshold};
use crate::witness::WitnessReceiptLookup;
use crate::witness::agreement::{AgreementStatus, WitnessAgreement};

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

    /// A threshold (`kt`, `nt`, or `bt`) is structurally unsatisfiable against
    /// the list it governs — e.g. `kt=5` over a single key, or a weighted
    /// clause whose length differs from the key-list length.
    #[error("Unsatisfiable threshold at sequence {sequence}: {reason}")]
    ThresholdNotSatisfiable {
        /// Zero-based position of the offending event.
        sequence: u128,
        /// Which threshold and why it cannot be met.
        reason: String,
    },

    /// A rotation's backer delta is invalid: a `br` (cut) entry isn't in the
    /// prior backer set, or a `ba` (add) entry duplicates a surviving backer.
    #[error("Invalid backer delta at sequence {sequence}: {reason}")]
    InvalidBackerDelta {
        /// Zero-based position of the offending rotation.
        sequence: u128,
        /// What was wrong with the delta.
        reason: String,
    },

    /// A rotation flips the registrar-backer role (`RB` <-> `NRB`) while
    /// retaining prior backers via a partial `br`/`ba` delta. `RB` and `NRB`
    /// carry different backer-list semantics, so a surviving backer would be
    /// governed by semantics it was never admitted under. A role flip must
    /// rebuild `b[]` — every prior backer cut (F-23).
    #[error("Invalid backer role flip at sequence {sequence}: {reason}")]
    BackerRoleFlip {
        /// Zero-based position of the offending rotation.
        sequence: u128,
        /// Which roles flipped and how many backers survived.
        reason: String,
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

    /// A delegated event (`dip` / `drt`) has no delegate-side source seal
    /// (`-G` couple). The delegator anchored it, but the event itself doesn't
    /// point back at that anchoring event — a one-directional (and therefore
    /// non-keripy-interoperable, weakly-bound) delegation. Bilateral required.
    #[error(
        "Delegate source seal missing at sequence {sequence}: delegated event carries no -G back-reference to its anchoring event"
    )]
    DelegateSourceSealMissing {
        /// Zero-based position of the delegated event.
        sequence: u128,
    },

    /// A delegated event's source seal (`-G` couple) points at a different
    /// delegator event than the one that actually anchored it. The bilateral
    /// binding is broken: the delegate claims anchoring location L while the
    /// delegator's `Seal::KeyEvent` lives at L′ ≠ L.
    #[error(
        "Delegation source seal back-reference mismatch at sequence {sequence}: delegate points at a different anchoring event than the delegator's seal"
    )]
    SealBackRefMismatch {
        /// Zero-based position of the delegated event.
        sequence: u128,
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

    /// A non-inception event was applied without the prior key state it
    /// chains from (missing inception or out-of-order application).
    #[error("Event at sequence {sequence} applied without prior key state")]
    MissingPriorState {
        /// Zero-based position of the event that lacked prior state.
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

    /// A policy-only variant: an establishment event is missing the `dt`
    /// field, so the cooldown cannot be enforced. Structural validation
    /// (`validate_kel`) permits missing `dt`; the policy validator
    /// (`validate_kel_with_policy`) does not.
    #[error("Policy violation: event at seq {sequence} missing `dt`")]
    MissingTimestamp {
        /// Zero-based position of the event in the KEL.
        sequence: u128,
    },

    /// Two consecutive events have non-monotonic `dt`.
    #[error(
        "Policy violation: timestamps not monotonic at seq {sequence} (prev={prev}, curr={curr})"
    )]
    NonMonotonicTimestamp {
        /// Zero-based position of the offending event.
        sequence: u128,
        /// Previous event's `dt`.
        prev: String,
        /// Current event's `dt`.
        curr: String,
    },

    /// Two rotations happened closer together than the configured
    /// cooldown allows (and the event is not an emergency override).
    #[error(
        "Policy violation: rotation cooldown breached at seq {sequence} (interval {interval_secs}s < minimum {min_secs}s)"
    )]
    RotationCooldown {
        /// Zero-based position of the offending rotation.
        sequence: u128,
        /// Observed inter-rotation interval (seconds).
        interval_secs: i64,
        /// Configured minimum interval (seconds).
        min_secs: i64,
    },

    /// An event's `dt` is beyond the configured clock-skew tolerance.
    #[error(
        "Policy violation: clock skew at seq {sequence} ({skew_secs}s) exceeds tolerance ({tolerance_secs}s)"
    )]
    ClockSkew {
        /// Zero-based position of the event.
        sequence: u128,
        /// Observed skew vs server clock (seconds, signed).
        skew_secs: i64,
        /// Configured tolerance (seconds).
        tolerance_secs: i64,
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

    // Delegator side: find the anchoring event whose a[] carries a KeyEvent seal
    // for this delegated event, and capture that event's own (sequence, SAID).
    let anchor = delegator_kel.iter().find_map(|event| {
        let anchors = event.anchors().iter().any(|seal| {
            matches!(
                seal,
                Seal::KeyEvent { i, s, d }
                if i == delegated_event.prefix()
                    && s.value() == event_seq.value()
                    && d == event_said
            )
        });
        anchors.then(|| SourceSeal {
            s: event.sequence(),
            d: event.said().clone(),
        })
    });

    let Some(anchor) = anchor else {
        return Err(ValidationError::Serialization(format!(
            "No delegation seal found in delegator KEL for prefix={}, sn={}, said={}",
            delegated_event.prefix(),
            event_seq,
            event_said
        )));
    };

    // Delegate side: the event's -G source seal must point back at that exact
    // anchoring event. A missing or mismatched back-reference is rejected.
    enforce_source_seal(delegated_event.source_seal(), &anchor, event_seq.value())
}

/// Enforce the delegate side of the bilateral delegation binding: the delegated
/// event's `-G` source seal must be present and equal the delegator's anchoring
/// event `(sequence, SAID)`.
fn enforce_source_seal(
    source_seal: Option<&SourceSeal>,
    anchor: &SourceSeal,
    sequence: u128,
) -> Result<(), ValidationError> {
    match source_seal {
        None => Err(ValidationError::DelegateSourceSealMissing { sequence }),
        Some(seal) if seal == anchor => Ok(()),
        Some(_) => Err(ValidationError::SealBackRefMismatch { sequence }),
    }
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
    /// Return the delegator's anchoring event — its sequence **and** SAID — whose
    /// `a[]` carries a `Seal::KeyEvent` for `seal_said`, or `None` if the
    /// delegator's KEL contains none. The returned [`SourceSeal`] is exactly what
    /// the delegated event's `-G` back-reference must equal for the bilateral
    /// binding to hold.
    fn find_seal(&self, delegator_aid: &Prefix, seal_said: &Said) -> Option<SourceSeal>;
}

/// A precomputed index of a delegator KEL's anchoring seals.
///
/// Build it once from a KEL slice with [`KelSealIndex::from_events`]; `find_seal`
/// is then an O(1) map lookup. This is the shared [`DelegatorKelLookup`] every
/// verify path uses to resolve the [`SourceSeal`] that authorizes a delegated
/// (`dip`/`drt`) event — replacing the per-call-site linear scans the commit,
/// presentation, and offline-org verifiers each used to carry (so the lookup is
/// defined once, with one performance profile, instead of three times).
pub struct KelSealIndex {
    /// `sealed-event SAID → SourceSeal of the anchoring event`.
    seals: std::collections::HashMap<Said, SourceSeal>,
}

impl KelSealIndex {
    /// Index every `Seal::KeyEvent` anchored in `events`, mapping the sealed event
    /// SAID to the [`SourceSeal`] (sequence + SAID) of the event that anchored it.
    /// On a duplicate sealed SAID the first (lowest-sequence) anchor wins —
    /// identical to a forward linear scan over an ordered KEL.
    ///
    /// Args:
    /// * `events`: The delegator's KEL.
    pub fn from_events(events: &[Event]) -> Self {
        let mut seals = std::collections::HashMap::new();
        for event in events {
            for seal in event.anchors() {
                if let Seal::KeyEvent { d, .. } = seal {
                    seals.entry(d.clone()).or_insert_with(|| SourceSeal {
                        s: event.sequence(),
                        d: event.said().clone(),
                    });
                }
            }
        }
        Self { seals }
    }
}

impl DelegatorKelLookup for KelSealIndex {
    fn find_seal(&self, _delegator_aid: &Prefix, seal_said: &Said) -> Option<SourceSeal> {
        self.seals.get(seal_said).cloned()
    }
}

/// A KEL the caller asserts comes from a **trusted source** — the local identity
/// registry / a self-owned store, or a chain already authenticated via
/// [`validate_signed_kel`].
///
/// Structural replay (SAID + sequence + chain-linkage + pre-rotation commitment,
/// *without* re-verifying each event's signature) is exposed to other crates
/// **only** through this type. Bare-`&[Event]` structural replay
/// ([`validate_kel`] and friends) is `pub(crate)`, so untrusted input — a CI
/// `--identity-bundle`, a `--remote`/`--oobi` fetch, a WASM/FFI buffer — cannot be
/// structurally replayed from outside auths-keri without either an explicit,
/// greppable trust assertion ([`TrustedKel::from_trusted_source`]) or prior
/// authentication via [`validate_signed_kel`] (RT-002 / #263). The assertion is a
/// reviewable, lint-gated decision rather than an invisible `validate_kel(bytes)`
/// call.
///
/// Borrowing and `Copy` — zero-cost over a `&[Event]`.
#[derive(Clone, Copy)]
pub struct TrustedKel<'a>(&'a [Event]);

impl<'a> TrustedKel<'a> {
    /// Assert that `events` come from a trusted source. Every call site is a
    /// reviewable trust assertion — **never** call this on attacker-influenced
    /// bytes (bundle / `--remote` / `--oobi` / WASM / FFI); authenticate those
    /// through [`validate_signed_kel`] instead.
    ///
    /// Args:
    /// * `events`: A KEL whose provenance the caller vouches for (local registry
    ///   read, or an already-authenticated chain).
    pub fn from_trusted_source(events: &'a [Event]) -> Self {
        Self(events)
    }

    /// The underlying events.
    pub fn events(&self) -> &'a [Event] {
        self.0
    }

    /// Structural replay to the current [`KeyState`].
    pub fn replay(self) -> Result<KeyState, ValidationError> {
        validate_kel(self.0)
    }

    /// Structural replay with a delegator-seal lookup for delegated (`dip`/`drt`)
    /// events.
    pub fn replay_with_lookup(
        self,
        lookup: Option<&dyn DelegatorKelLookup>,
    ) -> Result<KeyState, ValidationError> {
        validate_kel_with_lookup(self.0, lookup)
    }

    /// Structural replay with the M-of-N witness-receipt gate.
    pub fn replay_with_receipts(
        self,
        lookup: Option<&dyn DelegatorKelLookup>,
        receipt_lookup: &dyn WitnessReceiptLookup,
    ) -> Result<WitnessedReplay, ValidationError> {
        validate_kel_with_receipts(self.0, lookup, receipt_lookup)
    }

    /// Structural replay with the time / rotation-cadence policy checks
    /// ([`KelPolicy`]). `timestamps[i]` is the optional signing time of `events[i]`.
    pub fn replay_with_policy(
        self,
        timestamps: &[Option<chrono::DateTime<chrono::Utc>>],
        policy: &KelPolicy,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<KeyState, ValidationError> {
        validate_kel_with_policy(self.0, timestamps, policy, now)
    }
}

/// Validate a KEL with no delegator lookup.
///
/// Crate-private (RT-002 / #263): other crates reach structural replay only via
/// [`TrustedKel`], so untrusted input cannot be replayed without an explicit trust
/// assertion. Convenience wrapper over [`validate_kel_with_lookup`] for ordinary
/// KELs that contain only `icp`/`rot`/`ixn` events.
///
/// Args:
/// * `events` - The ordered list of KERI events to replay and validate.
pub(crate) fn validate_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    validate_kel_with_lookup(events, None::<&dyn DelegatorKelLookup>)
}

/// Validate a KEL with a delegator-lookup hook for delegated events.
///
/// Required when the KEL contains `dip` or `drt` events; ordinary KELs
/// (only `icp`/`rot`/`ixn`) can pass `None`.
pub(crate) fn validate_kel_with_lookup(
    events: &[Event],
    lookup: Option<&dyn DelegatorKelLookup>,
) -> Result<KeyState, ValidationError> {
    match replay_kel_gated(events, lookup, None)? {
        WitnessedReplay::Accepted(state) => Ok(state),
        // With no receipt lookup the gate never runs, so `Pending` is
        // unreachable; returning the structural state preserves the
        // no-receipt contract (advance regardless of receipts).
        WitnessedReplay::Pending { state, .. } => Ok(state),
    }
}

/// The outcome of replaying a KEL through the witness-receipt gate.
///
/// Unlike [`validate_kel`] (structural only), [`validate_kel_with_receipts`]
/// will not silently advance past an establishment event that lacks M-of-N
/// witness agreement — it reports [`WitnessedReplay::Pending`] so the caller
/// (verifier policy, D.7) can warn or refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessedReplay {
    /// Every `bt>0` establishment event reached witness quorum; the key-state
    /// is witness-authoritative.
    Accepted(KeyState),
    /// The KEL is structurally valid, but the establishment event at `sequence`
    /// did not reach quorum. `state` is the structural replay through that event;
    /// the caller must not treat key-state at or after `sequence` as
    /// witness-authoritative.
    Pending {
        /// Structural replay result through the under-quorum event.
        state: KeyState,
        /// Sequence of the first under-quorum establishment event.
        sequence: u128,
        /// SAID of that event.
        said: Said,
        /// The backer threshold that was required.
        required: Threshold,
        /// Distinct, in-force witness receipts collected for it.
        collected: usize,
    },
}

impl WitnessedReplay {
    /// The replayed key-state, regardless of the witness-quorum outcome.
    pub fn state(&self) -> &KeyState {
        match self {
            WitnessedReplay::Accepted(state) | WitnessedReplay::Pending { state, .. } => state,
        }
    }
}

/// Validate a KEL and gate each establishment event on M-of-N witness receipts.
///
/// Extends [`validate_kel_with_lookup`] with receipt-gated replay: a `bt>0`
/// establishment event advances `KeyState` only when KAWA
/// ([`WitnessAgreement`](crate::witness::agreement::WitnessAgreement)) reports
/// agreement over receipts from **distinct** witnesses in the `b[]` set **in
/// force at that sequence**. `bt=0` events accept without receipts (the
/// zero-witness path). Receipts are matched by `(controller, sn, said)` via
/// `receipt_lookup` and deduped by witness AID; a receipt from a non-designated
/// witness never counts.
///
/// Args:
/// * `events`: The ordered KEL to replay.
/// * `delegator_lookup`: Cross-KEL seal lookup for delegated events (`dip`/`drt`).
/// * `receipt_lookup`: Source of witness receipts per event.
///
/// Usage:
/// ```ignore
/// match validate_kel_with_receipts(&events, None, &receipts)? {
///     WitnessedReplay::Accepted(state) => trust(state),
///     WitnessedReplay::Pending { sequence, .. } => warn_or_refuse(sequence),
/// }
/// ```
pub(crate) fn validate_kel_with_receipts(
    events: &[Event],
    delegator_lookup: Option<&dyn DelegatorKelLookup>,
    receipt_lookup: &dyn WitnessReceiptLookup,
) -> Result<WitnessedReplay, ValidationError> {
    replay_kel_gated(events, delegator_lookup, Some(receipt_lookup))
}

/// Shared structural replay with an optional witness-receipt gate.
///
/// With `receipt_lookup = None` this is pure structural replay (the
/// [`validate_kel`] contract). With `Some(_)` each establishment event is gated
/// on witness quorum; the first under-quorum event short-circuits to
/// [`WitnessedReplay::Pending`].
fn replay_kel_gated(
    events: &[Event],
    lookup: Option<&dyn DelegatorKelLookup>,
    receipt_lookup: Option<&dyn WitnessReceiptLookup>,
) -> Result<WitnessedReplay, ValidationError> {
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

    let controller = state.prefix.clone();

    // Gate the inception establishment event on witness quorum.
    if let Some(rl) = receipt_lookup
        && let Some(pending) = gate_establishment(&controller, &state, 0, events[0].said(), rl)
    {
        return Ok(pending);
    }

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

        // Gate establishment events (rot/drt) on witness quorum; ixn never gates.
        if let Some(rl) = receipt_lookup
            && matches!(event, Event::Rot(_) | Event::Drt(_))
            && let Some(pending) =
                gate_establishment(&controller, &state, expected_seq, event.said(), rl)
        {
            return Ok(pending);
        }
    }

    Ok(WitnessedReplay::Accepted(state))
}

/// Replay a KEL of **signed** events, verifying each event's signature against the
/// key-state that authorizes it — the authenticated counterpart to the
/// structural-only [`validate_kel`] (RT-002).
///
/// Where [`validate_kel`] authorizes by log *structure* alone (SAID + sequence +
/// chain-linkage + pre-rotation commitment), this folds [`validate_signed_event`]
/// into the replay so every event must also carry a valid signature from the
/// in-force key-state: inception/`dip` against their own committed keys under
/// `kt`; `rot`/`drt` against the new keys plus the prior pre-rotation commitment;
/// `ixn` against the current key-state. An event with no — or an invalid —
/// signature fails closed with [`ValidationError::SignatureFailed`].
///
/// This is the function the stateless verify entrypoints call to AUTHENTICATE an
/// ingested KEL: the identity bundle carries a CESR signature attachment per `kel`
/// event (`IdentityBundle::kel_attachments`, paired via `pair_kel_attachments`),
/// and the WASM KEL boundary replays through this function and deliberately does
/// not expose the structural `validate_kel`. Structural checks are applied here
/// too, so a forged SAID or broken chain is still rejected — but the signature
/// check is the point: an unsigned or wrong-signer event fails closed.
///
/// Args:
/// * `events`: The ordered KEL of signed events to replay.
/// * `lookup`: Cross-KEL seal lookup for delegated events (`dip`/`drt`).
pub fn validate_signed_kel(
    events: &[crate::events::SignedEvent],
    lookup: Option<&dyn DelegatorKelLookup>,
) -> Result<KeyState, ValidationError> {
    if events.is_empty() {
        return Err(ValidationError::EmptyKel);
    }

    // Inception: structural (SAID + self-certification) AND a signature from the
    // event's own committed keys.
    let first = &events[0];
    verify_event_said(&first.event)?;
    validate_signed_event(first, None)?;
    let (mut state, inception_n_is_empty, establishment_only) = match &first.event {
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

    if inception_n_is_empty && events.len() > 1 {
        return Err(ValidationError::NonTransferable);
    }

    for (idx, signed) in events.iter().enumerate().skip(1) {
        let event = &signed.event;
        let expected_seq = idx as u128;

        if state.is_abandoned {
            return Err(ValidationError::AbandonedIdentity {
                sequence: expected_seq,
            });
        }
        if establishment_only && matches!(event, Event::Ixn(_)) {
            return Err(ValidationError::EstablishmentOnly {
                sequence: expected_seq,
            });
        }

        verify_event_said(event)?;
        verify_sequence(event, expected_seq)?;
        verify_chain_linkage(event, &state)?;
        // Authenticate against the in-force key-state BEFORE applying the event
        // (rot/drt verify the prior next-threshold against the pre-rotation state).
        validate_signed_event(signed, Some(&state))?;

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

/// Gate one establishment event on M-of-N witness agreement.
///
/// Returns `Some(WitnessedReplay::Pending)` when the in-force backer threshold
/// is not met by distinct designated-witness receipts, or `None` when the event
/// is witness-accepted (including the `bt=0` zero-witness path). KAWA does the
/// M-of-N math and the AID dedupe / non-designated-witness filtering.
fn gate_establishment(
    controller: &Prefix,
    state: &KeyState,
    sequence: u128,
    event_said: &Said,
    receipt_lookup: &dyn WitnessReceiptLookup,
) -> Option<WitnessedReplay> {
    let sn = sequence as u64;
    let agreement = WitnessAgreement::new(1);
    agreement.submit_event(
        controller,
        sn,
        event_said,
        &state.backer_threshold,
        &state.backers,
    );
    for receipt in receipt_lookup.receipts_for(controller, KeriSequence::new(sequence), event_said)
    {
        agreement.add_receipt(controller, sn, event_said, receipt.witness.as_str());
    }
    match agreement.status(controller, sn, event_said) {
        AgreementStatus::Accepted => None,
        AgreementStatus::Pending { collected } => Some(WitnessedReplay::Pending {
            state: state.clone(),
            sequence,
            said: event_said.clone(),
            required: state.backer_threshold.clone(),
            collected,
        }),
    }
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

/// Structural threshold satisfiability for an establishment event's
/// `kt`/`nt`/`bt` against the key, next-commitment, and backer lists.
fn validate_thresholds(
    sequence: u128,
    kt: &Threshold,
    k_len: usize,
    nt: &Threshold,
    n_len: usize,
    bt: &Threshold,
    b_len: usize,
) -> Result<(), ValidationError> {
    let check = |t: &Threshold, len: usize, which: &str| {
        t.validate_satisfiable(len)
            .map_err(|e| ValidationError::ThresholdNotSatisfiable {
                sequence,
                reason: format!("{which}: {}", e.reason),
            })
    };
    check(kt, k_len, "kt")?;
    check(nt, n_len, "nt")?;
    check(bt, b_len, "bt")?;
    Ok(())
}

/// Enforce inception self-certification — bind the controller prefix `i` to the
/// event so a forged inception cannot claim an arbitrary prefix with
/// attacker-controlled keys (RT-001).
///
/// `compute_said` blanks `i` before hashing (an inception's prefix derives FROM
/// its SAID, not the reverse), so verifying `d == compute_said(body)` does NOT
/// bind `i`. This supplies that binding:
/// - self-addressing (`E`-prefixed) AIDs: `i` MUST equal the SAID `d`;
/// - basic-derivation AIDs (`D`/`1AAI`/…): `i` MUST equal the lone key `k[0]`.
///
/// This is the same rule [`verify_event_crypto`] enforces on the append path;
/// both now route through here so the two paths cannot drift.
fn verify_inception_self_cert(i: &Prefix, d: &Said, k: &[CesrKey]) -> Result<(), ValidationError> {
    // Presence: an inception must commit at least one key.
    if k.is_empty() {
        return Err(ValidationError::SignatureFailed { sequence: 0 });
    }

    if i.as_str().starts_with('E') {
        if i.as_str() != d.as_str() {
            return Err(ValidationError::InvalidSaid {
                expected: d.clone(),
                actual: Said::new_unchecked(i.as_str().to_string()),
            });
        }
    } else {
        // Basic-derivation: the prefix IS the single inception key. Without this
        // a `D…`/`1AAI…` prefix could point at an arbitrary key list.
        let i_key = KeriPublicKey::parse(i.as_str())
            .map_err(|_| ValidationError::SignatureFailed { sequence: 0 })?;
        let k0 = k[0]
            .parse()
            .map_err(|_| ValidationError::SignatureFailed { sequence: 0 })?;
        if i_key.as_bytes() != k0.as_bytes() {
            return Err(ValidationError::InvalidSaid {
                expected: Said::new_unchecked(k[0].as_str().to_string()),
                actual: Said::new_unchecked(i.as_str().to_string()),
            });
        }
    }

    Ok(())
}

fn validate_inception(icp: &IcpEvent) -> Result<KeyState, ValidationError> {
    // Self-certification: bind `i` to the event before adopting it as the
    // controller prefix (RT-001). Runs after `verify_event_said` has confirmed
    // `d` is the true SAID, so `i == d` means `i` is the true SAID too.
    verify_inception_self_cert(&icp.i, &icp.d, &icp.k)?;

    // Validate backer uniqueness
    validate_backer_uniqueness(&icp.b)?;

    // Threshold satisfiability (kt over k, nt over n, bt over b).
    validate_thresholds(
        icp.s.value(),
        &icp.kt,
        icp.k.len(),
        &icp.nt,
        icp.n.len(),
        &icp.bt,
        icp.b.len(),
    )?;

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

/// Returns whether the new key list reveals enough prior next-key commitments
/// to satisfy the typed prior `nt` threshold.
///
/// Each prior commitment index `j` counts as "revealed" when some new key
/// hashes to `next_commitment[j]`; the typed [`Threshold::is_satisfied`] then
/// decides over those indices. This replaces the legacy
/// `simple_value().unwrap_or(1)` collapse, which silently reduced any weighted
/// `nt` to a 1-of-N (F-15).
fn prior_commitments_satisfy_threshold(
    next_commitment: &[Said],
    next_threshold: &Threshold,
    new_keys: &[CesrKey],
) -> bool {
    let revealed: Vec<u32> = next_commitment
        .iter()
        .enumerate()
        .filter_map(|(j, commitment)| {
            let matched = new_keys.iter().any(|key| {
                key.parse()
                    .map(|pk| verify_commitment(&pk, commitment))
                    .unwrap_or(false)
            });
            matched.then_some(j as u32)
        })
        .collect();
    next_threshold.is_satisfied(&revealed, next_commitment.len())
}

/// Registrar-backer role designated by an event's config traits.
///
/// `RB` and `NRB` are mutually exclusive backer semantics; the latter wins when
/// both appear (per [`ConfigTrait`] supersedence). `Unspecified` means the
/// event's `c[]` named neither, so the role is inherited rather than changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackerRole {
    Registrar,
    NoRegistrar,
    Unspecified,
}

/// Resolve the registrar-backer role designated by a config-trait list.
fn backer_role(traits: &[ConfigTrait]) -> BackerRole {
    let mut role = BackerRole::Unspecified;
    for t in traits {
        match t {
            ConfigTrait::RegistrarBackers => role = BackerRole::Registrar,
            ConfigTrait::NoRegistrarBackers => role = BackerRole::NoRegistrar,
            _ => {}
        }
    }
    role
}

fn validate_rotation(
    rot: &RotEvent,
    sequence: u128,
    state: &mut KeyState,
) -> Result<(), ValidationError> {
    // Threshold satisfiability for the new establishment config. `br`/`ba` are
    // deltas, so the post-rotation backer count is the prior set minus removals
    // plus additions.
    let post_backer_count =
        state.backers.iter().filter(|b| !rot.br.contains(b)).count() + rot.ba.len();
    validate_thresholds(
        sequence,
        &rot.kt,
        rot.k.len(),
        &rot.nt,
        rot.n.len(),
        &rot.bt,
        post_backer_count,
    )?;

    // Verify all pre-rotation commitments against the typed prior `nt`.
    if !state.next_commitment.is_empty()
        && !prior_commitments_satisfy_threshold(
            &state.next_commitment,
            &state.next_threshold,
            &rot.k,
        )
    {
        return Err(ValidationError::CommitmentMismatch { sequence });
    }

    // Validate backer uniqueness within br and ba.
    validate_backer_uniqueness(&rot.br)?;
    validate_backer_uniqueness(&rot.ba)?;
    // br and ba must not overlap.
    for aid in &rot.ba {
        if rot.br.contains(aid) {
            return Err(ValidationError::DuplicateBacker {
                aid: aid.as_str().to_string(),
            });
        }
    }
    // Each `br` (cut) must be a current backer; each `ba` (add) must not already
    // be a surviving backer. Otherwise apply_rotation's retain+extend would
    // silently corrupt the backer set and `bt` accounting (F-05).
    for aid in &rot.br {
        if !state.backers.contains(aid) {
            return Err(ValidationError::InvalidBackerDelta {
                sequence,
                reason: format!("br entry {} not in prior backers", aid.as_str()),
            });
        }
    }
    let survivors: Vec<_> = state
        .backers
        .iter()
        .filter(|b| !rot.br.contains(b))
        .collect();
    for aid in &rot.ba {
        if survivors.contains(&aid) {
            return Err(ValidationError::InvalidBackerDelta {
                sequence,
                reason: format!("ba entry {} duplicates a surviving backer", aid.as_str()),
            });
        }
    }

    // Reject a silent RB<->NRB role flip that retains prior backers. A
    // non-empty `c[]` naming the opposite role must rebuild `b[]` — cut every
    // prior backer — or a survivor ends up governed by semantics it was never
    // admitted under (F-23). An empty `c[]` inherits the role, so cannot flip.
    if !rot.c.is_empty() {
        let old_role = backer_role(&state.config_traits);
        let new_role = backer_role(&rot.c);
        let is_flip = matches!(
            (old_role, new_role),
            (BackerRole::Registrar, BackerRole::NoRegistrar)
                | (BackerRole::NoRegistrar, BackerRole::Registrar)
        );
        if is_flip && !survivors.is_empty() {
            return Err(ValidationError::BackerRoleFlip {
                sequence,
                reason: format!(
                    "{old_role:?}->{new_role:?} but {} prior backer(s) survive; \
                     a role flip must cut all prior backers",
                    survivors.len()
                ),
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

    // Bilateral delegation binding: the delegator anchored this dip (delegator
    // side) AND the dip's -G source seal points back at that exact anchoring
    // event (delegate side).
    let anchor = lookup.find_seal(&dip.di, &dip.d).ok_or_else(|| {
        ValidationError::DelegatorSealNotFound {
            sequence,
            delegator_aid: dip.di.as_str().to_string(),
        }
    })?;
    enforce_source_seal(dip.source_seal.as_ref(), &anchor, sequence)?;

    // Self-certification (RT-001): a delegated AID's prefix is the SAID of its
    // own inception, so `i == d` must hold here as well.
    verify_inception_self_cert(&dip.i, &dip.d, &dip.k)?;

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
        last_establishment_sequence: dip.s.value(),
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

    // Bilateral delegation binding (as for dip): delegator-anchored seal AND the
    // drt's -G source seal pointing back at that anchoring event.
    let anchor = lookup.find_seal(&drt.di, &drt.d).ok_or_else(|| {
        ValidationError::DelegatorSealNotFound {
            sequence,
            delegator_aid: drt.di.as_str().to_string(),
        }
    })?;
    enforce_source_seal(drt.source_seal.as_ref(), &anchor, sequence)?;

    // Standard rotation commitment/backer checks applied to drt fields.
    if !state.next_commitment.is_empty()
        && !prior_commitments_satisfy_threshold(
            &state.next_commitment,
            &state.next_threshold,
            &drt.k,
        )
    {
        return Err(ValidationError::CommitmentMismatch { sequence });
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
        // Self-certification (`i==d` / `i==k[0]`) is enforced by the shared
        // helper so the append and replay paths cannot drift (RT-001).
        Event::Icp(icp) => verify_inception_self_cert(&icp.i, &icp.d, &icp.k),
        Event::Rot(rot) => {
            let sequence = event.sequence().value();
            let state = current_state.ok_or(ValidationError::SignatureFailed { sequence })?;

            if state.is_abandoned || state.next_commitment.is_empty() {
                return Err(ValidationError::CommitmentMismatch { sequence });
            }

            if rot.k.is_empty() {
                return Err(ValidationError::SignatureFailed { sequence });
            }

            // Verify pre-rotation commitments against the typed prior `nt`.
            if !prior_commitments_satisfy_threshold(
                &state.next_commitment,
                &state.next_threshold,
                &rot.k,
            ) {
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
        // Delegated inception is self-addressing too: enforce `i==d` via the
        // shared helper rather than only a presence check (RT-001).
        Event::Dip(dip) => verify_inception_self_cert(&dip.i, &dip.d, &dip.k),
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

/// Compute the key state after applying `event` on top of `current_state`.
///
/// The single authoritative event→state transition, shared by every KEL
/// store (packed registry, per-prefix witness store) and the replay paths so
/// they cannot drift. Inception events (`icp`/`dip`) require `current_state`
/// to be `None`-compatible (they ignore it); every other event type requires
/// the prior state. A `dip` carries its delegator into
/// [`KeyState::delegator`].
///
/// Args:
/// * `current_state` - The state before this event (`None` before inception).
/// * `event` - The event to apply.
///
/// Usage:
/// ```ignore
/// let next = state_after_event(state.as_ref(), &event)?;
/// ```
pub fn state_after_event(
    current_state: Option<&KeyState>,
    event: &Event,
) -> Result<KeyState, ValidationError> {
    let sequence = event.sequence().value();
    match event {
        Event::Icp(icp) => Ok(KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            icp.kt.clone(),
            icp.nt.clone(),
            icp.d.clone(),
            icp.b.clone(),
            icp.bt.clone(),
            icp.c.clone(),
        )),
        Event::Rot(rot) => {
            let mut state = current_state
                .cloned()
                .ok_or(ValidationError::MissingPriorState { sequence })?;
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
            Ok(state)
        }
        Event::Ixn(ixn) => {
            let mut state = current_state
                .cloned()
                .ok_or(ValidationError::MissingPriorState { sequence })?;
            state.apply_interaction(sequence, ixn.d.clone());
            Ok(state)
        }
        Event::Dip(dip) => {
            let mut state = KeyState::from_inception(
                dip.i.clone(),
                dip.k.clone(),
                dip.n.clone(),
                dip.kt.clone(),
                dip.nt.clone(),
                dip.d.clone(),
                dip.b.clone(),
                dip.bt.clone(),
                dip.c.clone(),
            );
            // A delegated inception CARRIES its delegator; dropping `di` here
            // leaves every downstream key state reporting `delegator: null`,
            // breaking any consumer that proves the chain-to-root off it.
            state.delegator = Some(dip.di.clone());
            Ok(state)
        }
        Event::Drt(drt) => {
            let mut state = current_state
                .cloned()
                .ok_or(ValidationError::MissingPriorState { sequence })?;
            state.apply_rotation(
                drt.k.clone(),
                drt.n.clone(),
                drt.kt.clone(),
                drt.nt.clone(),
                sequence,
                drt.d.clone(),
                &drt.br,
                &drt.ba,
                drt.bt.clone(),
                drt.c.clone(),
            );
            Ok(state)
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

/// Serialize a finalized event for signing.
///
/// KERI signs over the fully-formed event bytes — `d` (SAID) and `i` (prefix)
/// already populated by `finalize_*_event`, and the version string declaring
/// the true body length. A spec verifier (KERIpy/KERIox) parses `v` first and
/// frames the body by that length, so the signed bytes MUST equal the wire
/// bytes. (The prior implementation cleared `d`/`i` after finalization, making
/// the signed body shorter than `v` claimed — a hard interop break.)
///
/// Args:
/// * `event` - The finalized event to serialize for signing.
pub fn serialize_for_signing(event: &Event) -> Result<Vec<u8>, ValidationError> {
    serde_json::to_vec(event).map_err(|e| ValidationError::Serialization(e.to_string()))
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
        let n_len = state.next_commitment.len();

        // Bind each verifying signature to the prior commitment it reveals: the
        // new key `k[index]` must hash to `n[prior_index]` (or `n[index]` for a
        // single-index sig, where keripy emits code `A` with ondex == index). The
        // prior `nt` must then be met over the DISTINCT prior-commitment indices.
        let mut verified_prior: Vec<u32> = Vec::new();
        for sig in &signed.signatures {
            let Some(key) = keys.get(sig.index as usize) else {
                continue;
            };
            let Ok(pk) = key.parse() else {
                continue;
            };
            if pk.verify_signature(&canonical, &sig.sig).is_err() {
                continue;
            }
            let j = sig.prior_index.unwrap_or(sig.index) as usize;
            let Some(commitment) = state.next_commitment.get(j) else {
                continue;
            };
            if crate::crypto::verify_commitment(&pk, commitment) {
                verified_prior.push(j as u32);
            }
        }

        // A cardinality-changing rotation in which NO signature revealed a prior
        // commitment is unbindable — surface the diagnostic rather than a generic
        // signature failure. (A well-formed removal binds at least one; a single
        // signer at prior slot 0 binds via the index == ondex fallback.)
        if n_len != keys.len() && verified_prior.is_empty() {
            return Err(ValidationError::AsymmetricKeyRotation {
                sequence,
                prior_next_count: n_len,
                new_key_count: keys.len(),
            });
        }

        if !state.next_threshold.is_satisfied(&verified_prior, n_len) {
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

/// Create a delegated inception (`dip`) event with a properly computed SAID.
///
/// Mirrors [`finalize_icp_event`] for `dip`: a delegated AID's prefix is
/// self-addressing (the SAID of its own inception event), so `i` is set to `d`.
///
/// Args:
/// * `dip` - The delegated inception event to finalize (with `di` set to the delegator).
pub fn finalize_dip_event(
    mut dip: crate::events::DipEvent,
) -> Result<crate::events::DipEvent, ValidationError> {
    let value = serde_json::to_value(Event::Dip(dip.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;

    dip.d = said.clone();
    // A delegated AID is self-addressing: its prefix is the SAID of the dip.
    if dip.i.is_empty() || dip.i.as_str().starts_with('E') {
        dip.i = Prefix::new_unchecked(said.into_inner());
    }

    let final_bytes = serde_json::to_vec(&Event::Dip(dip.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    dip.v = crate::types::VersionString::json(final_bytes.len() as u32);

    Ok(dip)
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

/// Create a delegated rotation (`drt`) event with a properly computed SAID.
///
/// Mirrors [`finalize_rot_event`]. A `drt` is **not** self-addressing — its `i`
/// is the existing delegated AID prefix — so only `d` and `v` are set (`i` is
/// left unchanged, unlike `dip`).
///
/// Args:
/// * `drt` - The delegated rotation event to finalize.
pub fn finalize_drt_event(
    mut drt: crate::events::DrtEvent,
) -> Result<crate::events::DrtEvent, ValidationError> {
    let value = serde_json::to_value(Event::Drt(drt.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    let said = compute_said(&value).map_err(|e| ValidationError::Serialization(e.to_string()))?;
    drt.d = said;

    let final_bytes = serde_json::to_vec(&Event::Drt(drt.clone()))
        .map_err(|e| ValidationError::Serialization(e.to_string()))?;
    drt.v = crate::types::VersionString::json(final_bytes.len() as u32);

    Ok(drt)
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
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn gen_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn encode_pubkey(kp: &Ed25519KeyPair) -> String {
        crate::cesr_encode::encode_verkey(kp.public_key().as_ref(), cesride::matter::Codex::Ed25519)
            .unwrap()
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
        let key_encoded = encode_pubkey(&keypair);

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
        let mut ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: KeriSequence::new(0),
            p: Said::new_unchecked("EPrev".to_string()),
            a: vec![],
        };
        // Compute a valid SAID so verify_event_said passes — the test
        // should fail on NotInception, not on SaidMismatch.
        let event = Event::Ixn(ixn.clone());
        if let Ok(said) = compute_event_said(&event) {
            ixn.d = said;
        }
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

    // RT-001 (A.2): forged-inception self-certification on the replay path.
    // `compute_said` blanks `i` before hashing, so a valid SAID `d` does NOT
    // bind the controller prefix `i`. Without the `i==d` / `i==k[0]` check a KEL
    // handed to a stateless verifier could claim an arbitrary prefix with
    // attacker keys. These two tests are red before A.2 and green after.

    #[test]
    fn rejects_forged_inception_prefix_mismatch() {
        // Self-addressing arm: replace a finalized inception's prefix `i` with a
        // DIFFERENT well-formed `E…` prefix. The SAID `d` still verifies
        // (compute_said blanks `i`); only the `i == d` self-cert check catches it.
        let (icp, _kp) = make_signed_icp();
        assert_eq!(
            icp.i.as_str(),
            icp.d.as_str(),
            "a finalized inception is self-addressing"
        );

        let (other, _kp2) = make_signed_icp();
        assert_ne!(other.i.as_str(), icp.d.as_str());

        let mut forged = icp;
        forged.i = other.i;
        let result = validate_kel(&[Event::Icp(forged)]);
        assert!(
            matches!(result, Err(ValidationError::InvalidSaid { .. })),
            "forged inception (i != d) must be rejected, got {result:?}"
        );
    }

    #[test]
    fn rejects_forged_inception_basic_derivation() {
        // Basic-derivation arm: a non-`E` prefix IS the inception key, so `i`
        // must equal `k[0]`. Forge an inception whose prefix names a DIFFERENT
        // key than the one it commits.
        let prefix_key = encode_pubkey(&gen_keypair());
        let committed_key = encode_pubkey(&gen_keypair());
        assert_ne!(prefix_key, committed_key);
        assert!(!prefix_key.starts_with('E'));

        let mut icp = make_raw_icp(&committed_key, "ENext1");
        icp.i = Prefix::new_unchecked(prefix_key);
        // Valid SAID (compute_said blanks `i` for icp), so verify_event_said
        // passes and only the `i == k[0]` self-cert check should reject.
        let value = serde_json::to_value(Event::Icp(icp.clone())).unwrap();
        icp.d = compute_said(&value).unwrap();

        let result = validate_kel(&[Event::Icp(icp)]);
        assert!(
            matches!(result, Err(ValidationError::InvalidSaid { .. })),
            "basic-derivation inception with i != k[0] must be rejected, got {result:?}"
        );
    }

    // `validate_signed_kel` is the AUTHENTICATED replay — it verifies each event's
    // signature against the controlling key-state, so a forged unsigned /
    // wrong-signer `ixn`/`rot`/`icp` is rejected (tests below).
    // The structural `validate_kel`/`replay_kel_gated` remain for the trusted-local
    // path (replaying a KEL already authenticated on write to the registry), where
    // they authorize by log structure only. The stateless verify entrypoints that
    // ingest an untrusted KEL DO authenticate: the identity bundle carries a CESR
    // signature attachment per event and the bundle/WASM paths call
    // `validate_signed_kel` (see `auths-verifier` `commit_bundle.rs` and `wasm.rs`,
    // and the forged/stripped-signature rejection tests there). Do not mistake the
    // structural path for authentication — it is the trusted-local replay only.

    fn sign_event(event: &Event, kp: &Ed25519KeyPair) -> SignedEvent {
        let sig = kp
            .sign(&serialize_for_signing(event).unwrap())
            .as_ref()
            .to_vec();
        SignedEvent::new(
            event.clone(),
            vec![IndexedSignature {
                index: 0,
                prior_index: None,
                sig,
            }],
        )
    }

    #[test]
    fn validate_signed_kel_accepts_correctly_signed_kel() {
        let (icp, kp) = make_signed_icp();
        let signed_icp = sign_event(&Event::Icp(icp.clone()), &kp);
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &kp);
        let signed_ixn = sign_event(&Event::Ixn(ixn), &kp);

        let state = validate_signed_kel(&[signed_icp, signed_ixn], None)
            .expect("a correctly-signed KEL must validate");
        assert_eq!(state.sequence, 1);
    }

    #[test]
    fn validate_signed_kel_rejects_unsigned_ixn() {
        // RT-002: a structurally-valid but UNSIGNED ixn (e.g. anchoring a forged
        // delegation/scope seal) must be rejected by the authenticated replay.
        let (icp, kp) = make_signed_icp();
        let signed_icp = sign_event(&Event::Icp(icp.clone()), &kp);
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &kp);
        let unsigned_ixn = SignedEvent::new(Event::Ixn(ixn), vec![]);

        let result = validate_signed_kel(&[signed_icp, unsigned_ixn], None);
        assert!(
            matches!(result, Err(ValidationError::SignatureFailed { .. })),
            "unsigned ixn must be rejected, got {result:?}"
        );
    }

    #[test]
    fn validate_signed_kel_rejects_wrong_signer_ixn() {
        // RT-002: an ixn signed by a key OTHER than the controlling key-state
        // must be rejected — a forged interaction cannot be smuggled in.
        let (icp, kp) = make_signed_icp();
        let signed_icp = sign_event(&Event::Icp(icp.clone()), &kp);
        let ixn = make_signed_ixn(&icp.i, &icp.d, 1, &kp);
        let attacker = gen_keypair();
        let forged_ixn = sign_event(&Event::Ixn(ixn), &attacker);

        let result = validate_signed_kel(&[signed_icp, forged_ixn], None);
        assert!(
            matches!(result, Err(ValidationError::SignatureFailed { .. })),
            "wrong-signer ixn must be rejected, got {result:?}"
        );
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
        let signed = SignedEvent::new(
            event,
            vec![IndexedSignature {
                index: 0,
                prior_index: None,
                sig,
            }],
        );

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
                prior_index: None,
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
                prior_index: None,
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
        let key_encoded = encode_pubkey(&keypair);

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
        let commitment2 = crate::crypto::compute_next_commitment(
            &crate::keys::KeriPublicKey::ed25519(kp2.public_key().as_ref()).unwrap(),
        );
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
            let key_encoded = encode_pubkey(&keypair);

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
            let key_encoded = encode_pubkey(&keypair);

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
        // `bt=2` over zero backers is now caught by the stricter structural
        // threshold-satisfiability guard (A.4) before the legacy
        // empty-backers/bt!=0 check.
        assert!(
            matches!(result, Err(ValidationError::ThresholdNotSatisfiable { .. })),
            "expected ThresholdNotSatisfiable, got: {result:?}"
        );
    }

    #[test]
    fn sign_over_finalized_bytes_roundtrips() {
        // A.2: the bytes handed to the signer must equal the wire bytes, whose
        // length the version string `v` declares. (Previously d/i were cleared
        // after finalize, making the signed body shorter than `v` claimed.)
        let (icp, _kp) = make_signed_icp();
        let bytes = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
        assert_eq!(
            bytes.len() as u32,
            icp.v.size,
            "signed byte length must equal the version-string size field"
        );
        let reparsed: Event = serde_json::from_slice(&bytes).unwrap();
        assert!(reparsed.is_inception());
    }

    #[test]
    fn threshold_rejects_kt_gt_k() {
        // A.4: a signing threshold larger than the key-list length is
        // structurally unsatisfiable and must be rejected at validation.
        let kp = gen_keypair();
        let key = encode_pubkey(&kp);
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(5),
            k: vec![CesrKey::new_unchecked(key)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let result = validate_kel(&[Event::Icp(finalized)]);
        assert!(
            matches!(result, Err(ValidationError::ThresholdNotSatisfiable { .. })),
            "expected ThresholdNotSatisfiable, got: {result:?}"
        );
    }

    #[test]
    fn rotation_rejects_br_not_in_prior() {
        // A.10 (F-05): a rotation that cuts a backer not in the prior set, or
        // adds a backer that already survives, must be rejected before
        // apply_rotation corrupts the backer set.
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![CesrKey::new_unchecked("DKey1".to_string())],
            vec![], // empty next_commitment -> commitment check skipped
            Threshold::Simple(1),
            Threshold::Simple(0),
            Said::new_unchecked("ESAID".to_string()),
            vec![Prefix::new_unchecked("BWit1".to_string())],
            Threshold::Simple(0),
            vec![],
        );

        let make_rot = |br: Vec<Prefix>, ba: Vec<Prefix>| RotEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("ESAID".to_string()),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey2".to_string())],
            nt: Threshold::Simple(0),
            n: vec![],
            bt: Threshold::Simple(0),
            br,
            ba,
            c: vec![],
            a: vec![],
        };

        // br entry not in prior backers -> rejected.
        let bad_cut = make_rot(vec![Prefix::new_unchecked("BWitX".to_string())], vec![]);
        assert!(matches!(
            validate_rotation(&bad_cut, 1, &mut state.clone()),
            Err(ValidationError::InvalidBackerDelta { .. })
        ));

        // ba entry duplicating a surviving backer -> rejected.
        let bad_add = make_rot(vec![], vec![Prefix::new_unchecked("BWit1".to_string())]);
        assert!(matches!(
            validate_rotation(&bad_add, 1, &mut state.clone()),
            Err(ValidationError::InvalidBackerDelta { .. })
        ));

        // valid delta (cut the existing backer) -> ok.
        let ok = make_rot(vec![Prefix::new_unchecked("BWit1".to_string())], vec![]);
        assert!(validate_rotation(&ok, 1, &mut state.clone()).is_ok());
    }

    #[test]
    fn rotation_rejects_silent_backer_role_flip() {
        // A.13 (F-23): flipping RB<->NRB while a prior backer survives is
        // rejected; the same flip is allowed once every prior backer is cut
        // (b[] rebuilt). An empty c[] inherits the role and never flips.
        let nrb_state = || {
            KeyState::from_inception(
                Prefix::new_unchecked("EPrefix".to_string()),
                vec![CesrKey::new_unchecked("DKey1".to_string())],
                vec![],
                Threshold::Simple(1),
                Threshold::Simple(0),
                Said::new_unchecked("ESAID".to_string()),
                vec![Prefix::new_unchecked("BWit1".to_string())],
                Threshold::Simple(0),
                vec![ConfigTrait::NoRegistrarBackers],
            )
        };

        let make_rot = |br: Vec<Prefix>, ba: Vec<Prefix>, c: Vec<ConfigTrait>| RotEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("ESAID".to_string()),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey2".to_string())],
            nt: Threshold::Simple(0),
            n: vec![],
            bt: Threshold::Simple(0),
            br,
            ba,
            c,
            a: vec![],
        };

        // Flip NRB->RB while BWit1 survives -> rejected.
        let flip_keep = make_rot(vec![], vec![], vec![ConfigTrait::RegistrarBackers]);
        assert!(matches!(
            validate_rotation(&flip_keep, 1, &mut nrb_state()),
            Err(ValidationError::BackerRoleFlip { .. })
        ));

        // Flip NRB->RB after cutting every prior backer -> ok (b[] rebuilt).
        let flip_rebuild = make_rot(
            vec![Prefix::new_unchecked("BWit1".to_string())],
            vec![],
            vec![ConfigTrait::RegistrarBackers],
        );
        assert!(validate_rotation(&flip_rebuild, 1, &mut nrb_state()).is_ok());

        // Same role kept (NRB->NRB) with the backer surviving -> ok (no flip).
        let same_role = make_rot(vec![], vec![], vec![ConfigTrait::NoRegistrarBackers]);
        assert!(validate_rotation(&same_role, 1, &mut nrb_state()).is_ok());

        // Empty c[] inherits the role -> ok even though the backer survives.
        let inherit = make_rot(vec![], vec![], vec![]);
        assert!(validate_rotation(&inherit, 1, &mut nrb_state()).is_ok());
    }

    // ── D.6: receipt-gated replay ────────────────────────────────────────────

    use crate::witness::WitnessReceipt;

    /// Said-keyed witness-receipt source for replay-gate tests.
    struct MapReceipts {
        by_said: std::collections::HashMap<String, Vec<WitnessReceipt>>,
    }

    impl WitnessReceiptLookup for MapReceipts {
        fn receipts_for(
            &self,
            _controller: &Prefix,
            _sn: KeriSequence,
            said: &Said,
        ) -> Vec<WitnessReceipt> {
            self.by_said.get(said.as_str()).cloned().unwrap_or_default()
        }
    }

    fn witness_aid(aid: &str) -> Prefix {
        Prefix::new_unchecked(aid.to_string())
    }

    fn receipt_from(aid: &str) -> WitnessReceipt {
        WitnessReceipt {
            witness: witness_aid(aid),
            signature: vec![],
        }
    }

    fn receipts_under(said: &Said, aids: &[&str]) -> MapReceipts {
        let mut by_said = std::collections::HashMap::new();
        by_said.insert(
            said.as_str().to_string(),
            aids.iter().map(|a| receipt_from(a)).collect(),
        );
        MapReceipts { by_said }
    }

    /// A finalized inception designating `aids` as backers with threshold `bt`.
    fn icp_with_backers(aids: &[&str], bt: u64) -> IcpEvent {
        let backers: Vec<Prefix> = aids.iter().map(|a| witness_aid(a)).collect();
        let (icp, _kp) = make_custom_signed_icp(|icp| {
            icp.b = backers.clone();
            icp.bt = Threshold::Simple(bt);
        });
        icp
    }

    #[test]
    fn replay_bt_zero_accepts_without_receipts() {
        let (icp, _kp) = make_signed_icp(); // bt=0, b=[]
        let events = vec![Event::Icp(icp)];
        let lookup = MapReceipts {
            by_said: std::collections::HashMap::new(),
        };
        let outcome = validate_kel_with_receipts(&events, None, &lookup).unwrap();
        assert!(matches!(outcome, WitnessedReplay::Accepted(_)));
    }

    #[test]
    fn replay_at_quorum_accepts() {
        let icp = icp_with_backers(&["BWit1", "BWit2"], 2);
        let said = icp.d.clone();
        let lookup = receipts_under(&said, &["BWit1", "BWit2"]);
        let events = vec![Event::Icp(icp)];
        let outcome = validate_kel_with_receipts(&events, None, &lookup).unwrap();
        assert!(matches!(outcome, WitnessedReplay::Accepted(_)));
    }

    #[test]
    fn replay_under_quorum_is_pending() {
        let icp = icp_with_backers(&["BWit1", "BWit2"], 2);
        let said = icp.d.clone();
        let lookup = receipts_under(&said, &["BWit1"]); // only 1 of 2 required
        let events = vec![Event::Icp(icp)];
        match validate_kel_with_receipts(&events, None, &lookup).unwrap() {
            WitnessedReplay::Pending {
                sequence,
                collected,
                ..
            } => {
                assert_eq!(sequence, 0);
                assert_eq!(collected, 1);
            }
            WitnessedReplay::Accepted(_) => panic!("expected Pending under quorum"),
        }
    }

    #[test]
    fn replay_ignores_duplicate_witness_receipts() {
        let icp = icp_with_backers(&["BWit1", "BWit2", "BWit3"], 2);
        let said = icp.d.clone();
        let lookup = receipts_under(&said, &["BWit1", "BWit1"]); // same witness twice
        let events = vec![Event::Icp(icp)];
        assert!(matches!(
            validate_kel_with_receipts(&events, None, &lookup).unwrap(),
            WitnessedReplay::Pending { .. }
        ));
    }

    #[test]
    fn replay_ignores_receipt_for_wrong_said() {
        let icp = icp_with_backers(&["BWit1", "BWit2"], 2);
        // Receipts stored under a different event SAID must never satisfy this event.
        let wrong = Said::new_unchecked("EWrongEventSaid".to_string());
        let lookup = receipts_under(&wrong, &["BWit1", "BWit2"]);
        let events = vec![Event::Icp(icp)];
        match validate_kel_with_receipts(&events, None, &lookup).unwrap() {
            WitnessedReplay::Pending { collected, .. } => assert_eq!(collected, 0),
            WitnessedReplay::Accepted(_) => panic!("wrong-SAID receipts must not count"),
        }
    }

    #[test]
    fn replay_uses_witness_set_in_force_at_seq() {
        // icp designates {BWit1} bt=1; rot at seq 1 cuts BWit1, adds BWit2, bt=1.
        // The seq-1 gate must use the post-rotation set {BWit2}.
        let kp2 = gen_keypair();
        let kp3 = gen_keypair();
        let commitment2 = crate::crypto::compute_next_commitment(
            &crate::keys::KeriPublicKey::ed25519(kp2.public_key().as_ref()).unwrap(),
        );
        let commitment3 = crate::crypto::compute_next_commitment(
            &crate::keys::KeriPublicKey::ed25519(kp3.public_key().as_ref()).unwrap(),
        );
        let (icp, _kp1) = make_custom_signed_icp(|icp| {
            icp.b = vec![witness_aid("BWit1")];
            icp.bt = Threshold::Simple(1);
            icp.n = vec![commitment2.clone()];
        });
        let prefix = icp.i.clone();
        let icp_said = icp.d.clone();

        let mut rot = RotEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prefix.clone(),
            s: KeriSequence::new(1),
            p: icp_said.clone(),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(encode_pubkey(&kp2))],
            nt: Threshold::Simple(1),
            n: vec![commitment3.clone()],
            bt: Threshold::Simple(1),
            br: vec![witness_aid("BWit1")],
            ba: vec![witness_aid("BWit2")],
            c: vec![],
            a: vec![],
        };
        let val = serde_json::to_value(Event::Rot(rot.clone())).unwrap();
        rot.d = compute_said(&val).unwrap();
        let rot_said = rot.d.clone();

        let mut by_said = std::collections::HashMap::new();
        by_said.insert(icp_said.as_str().to_string(), vec![receipt_from("BWit1")]);
        by_said.insert(rot_said.as_str().to_string(), vec![receipt_from("BWit2")]);
        let lookup = MapReceipts { by_said };

        let events = vec![Event::Icp(icp), Event::Rot(rot)];
        // BWit2 is only in the post-rotation set; acceptance proves the in-force
        // set (not the stale {BWit1}) gated the rotation.
        assert!(matches!(
            validate_kel_with_receipts(&events, None, &lookup).unwrap(),
            WitnessedReplay::Accepted(_)
        ));
    }

    #[test]
    fn validate_kel_advances_without_receipt_gate() {
        // Back-compat: plain validate_kel ignores receipts and advances a bt>0 KEL.
        let icp = icp_with_backers(&["BWit1", "BWit2"], 2);
        let events = vec![Event::Icp(icp)];
        assert!(validate_kel(&events).is_ok());
    }
}

// =============================================================================
// Time-aware policy validation — rotation cooldown, clock-skew, emergency
// override. `validate_kel` stays pure / clock-free (structural invariants
// only); callers who want time-aware checks reach for
// `validate_kel_with_policy`.
// =============================================================================

/// Configurable policy for time-aware KEL validation. Defaults match
/// the plan text: 24h minimum rotation interval, 60s clock-skew
/// tolerance, no emergency-override identifier.
#[derive(Debug, Clone)]
pub struct KelPolicy {
    /// Minimum wall-clock interval between two consecutive rotation
    /// events. Default: 24 hours.
    pub min_rotation_interval: chrono::Duration,
    /// Maximum allowed skew between an event's `dt` and the wall
    /// clock used for validation. Default: 60 seconds.
    pub clock_skew_tolerance: chrono::Duration,
    /// AID that is permitted to skip the rotation-cooldown check
    /// (e.g. the controller's emergency-rotation key). `None` means
    /// no override is configured and every rotation must respect
    /// the cooldown.
    pub emergency_override_did: Option<crate::types::Prefix>,
}

impl Default for KelPolicy {
    fn default() -> Self {
        Self {
            min_rotation_interval: chrono::Duration::hours(24),
            clock_skew_tolerance: chrono::Duration::seconds(60),
            emergency_override_did: None,
        }
    }
}

/// Validate a KEL against a time-aware [`KelPolicy`].
///
/// Runs the structural [`validate_kel`] first; on success, layers on
/// three additional checks that depend on the `dt` field added to
/// establishment and interaction events:
///
/// 1. Every event MUST carry a `dt`. Pre-`dt`-migration events
///    (where `dt` is `None`) fail with
///    [`ValidationError::MissingTimestamp`].
/// 2. `dt` MUST be monotonically non-decreasing across consecutive
///    events. Backward-moving timestamps are evidence of tampering.
/// 3. Consecutive rotation events MUST be at least
///    [`KelPolicy::min_rotation_interval`] apart (unless the event's
///    controller matches [`KelPolicy::emergency_override_did`]).
/// 4. Every `dt` must be within
///    [`KelPolicy::clock_skew_tolerance`] of `now`.
///
/// Args:
/// * `events`: The ordered KEL.
/// * `policy`: [`KelPolicy`] governing the time checks.
/// * `now`: The daemon's wall clock at validation time. Inject via
///   [`chrono::Utc::now`] at the presentation boundary; domain layers
///   pass a clock.
pub(crate) fn validate_kel_with_policy(
    events: &[Event],
    timestamps: &[Option<chrono::DateTime<chrono::Utc>>],
    policy: &KelPolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<KeyState, ValidationError> {
    let state = validate_kel(events)?;

    let mut last_rotation_dt: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut last_any_dt: Option<chrono::DateTime<chrono::Utc>> = None;

    for (idx, evt) in events.iter().enumerate() {
        let seq = idx as u128;
        let (is_rotation, controller) = match evt {
            Event::Icp(e) => (false, &e.i),
            Event::Rot(e) => (true, &e.i),
            Event::Ixn(e) => (false, &e.i),
            Event::Dip(e) => (false, &e.i),
            Event::Drt(e) => (true, &e.i),
        };
        let Some(dt) = timestamps.get(idx).copied().flatten() else {
            return Err(ValidationError::MissingTimestamp { sequence: seq });
        };
        // Monotonicity.
        if let Some(prev) = last_any_dt
            && dt < prev
        {
            return Err(ValidationError::NonMonotonicTimestamp {
                sequence: seq,
                prev: prev.to_rfc3339(),
                curr: dt.to_rfc3339(),
            });
        }
        // Clock skew.
        let skew = (dt - now).num_seconds();
        if skew.abs() > policy.clock_skew_tolerance.num_seconds() {
            return Err(ValidationError::ClockSkew {
                sequence: seq,
                skew_secs: skew,
                tolerance_secs: policy.clock_skew_tolerance.num_seconds(),
            });
        }
        // Cooldown on rotations.
        if is_rotation && let Some(prev) = last_rotation_dt {
            let interval = dt - prev;
            let is_override = policy
                .emergency_override_did
                .as_ref()
                .is_some_and(|ov| ov == controller);
            if !is_override && interval < policy.min_rotation_interval {
                return Err(ValidationError::RotationCooldown {
                    sequence: seq,
                    interval_secs: interval.num_seconds(),
                    min_secs: policy.min_rotation_interval.num_seconds(),
                });
            }
        }
        last_any_dt = Some(dt);
        if is_rotation {
            last_rotation_dt = Some(dt);
        }
    }

    Ok(state)
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};

    fn base_now() -> chrono::DateTime<chrono::Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn policy_rejects_missing_dt_via_empty_kel_path() {
        // Structural validation fires first; empty KEL is rejected
        // before any policy check runs. Locks in that the policy
        // validator doesn't accidentally accept an empty KEL.
        let events: Vec<crate::events::Event> = vec![];
        let r = validate_kel_with_policy(&events, &[], &KelPolicy::default(), base_now());
        assert!(matches!(r, Err(ValidationError::EmptyKel)));
    }

    #[test]
    fn policy_default_values_match_plan() {
        let p = KelPolicy::default();
        assert_eq!(p.min_rotation_interval, ChronoDuration::hours(24));
        assert_eq!(p.clock_skew_tolerance, ChronoDuration::seconds(60));
        assert!(p.emergency_override_did.is_none());
    }
}
