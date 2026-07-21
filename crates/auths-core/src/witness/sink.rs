//! KEL sink — the write bridge from receipting to the served KEL store.
//!
//! Accepting an event in the witness's `kel` role must also persist it to the
//! per-prefix KEL store the witness serves ("serve what you witness"). The
//! server stays storage-agnostic: it calls this trait after its own wire
//! validation and first-seen check, and the embedding node (auths-witness-node)
//! injects the concrete store. The sink runs the *full* KERI ruleset — SAID,
//! sequence, prior-digest chain, pre-rotation commitment, attachment
//! signatures — so routing through it upgrades validation beyond the wire's
//! inception-only self-signature check.

use auths_keri::Prefix;

/// Outcome of routing an accepted event into the KEL store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelSinkOutcome {
    /// The event extended the stored KEL.
    Appended,
    /// The identical event was already stored — idempotent re-submission.
    AlreadyStored,
}

/// A failure routing an accepted event into the KEL store.
#[derive(Debug, thiserror::Error)]
pub enum KelSinkError {
    /// A different event already occupies this sequence — equivocation
    /// evidence, refused rather than forked.
    #[error("conflicting event at an occupied sequence")]
    Conflict {
        /// SAID of the event already stored at the sequence, when known.
        existing_said: Option<String>,
    },

    /// The event failed the full KERI ruleset (chain, commitment, signatures).
    #[error("event rejected by KEL store: {0}")]
    Invalid(String),

    /// The store itself failed (I/O, repository fault).
    #[error("KEL store failure: {0}")]
    Storage(String),
}

/// The write bridge a witness node injects into the server.
///
/// Implementations validate and persist the event under the per-prefix store
/// the node serves. Re-submission of an already-stored event must be a no-op
/// ([`KelSinkOutcome::AlreadyStored`]), never a fork.
pub trait KelSink: Send + Sync {
    /// Validate and persist an accepted event.
    ///
    /// Args:
    /// * `prefix`: The member prefix the event was submitted under.
    /// * `event`: The event body as received on the wire.
    /// * `attachment`: CESR attachment bytes from the submit envelope.
    ///
    /// Usage:
    /// ```ignore
    /// sink.append_signed_event(&prefix, &event, &attachment)?;
    /// ```
    fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &serde_json::Value,
        attachment: &[u8],
    ) -> Result<KelSinkOutcome, KelSinkError>;
}
