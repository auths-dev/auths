//! The node's write bridge: accepted KEL events persist to the per-prefix
//! store the node serves.
//!
//! Implements `auths_core::witness::KelSink` over
//! `auths_sdk::storage::PerPrefixKelStore`, so the `kel` role's receipting and
//! the `registry` role's serving share one git source of truth — "serve what
//! you witness". The store re-runs the full KERI ruleset (SAID, sequence,
//! prior-digest chain, pre-rotation commitment, attachment signatures) before
//! anything is written; the node demands the envelope dialect so every stored
//! event carries verifiable signature evidence.

use auths_core::witness::{KelSink, KelSinkError, KelSinkOutcome};
use auths_keri::{Event, Prefix};
use auths_sdk::ports::RegistryError;
use auths_sdk::storage::{KelAppendOutcome, PerPrefixKelStore};

/// [`KelSink`] adapter over the per-prefix KEL store.
pub struct KelStoreSink {
    store: PerPrefixKelStore,
}

impl KelStoreSink {
    /// Create a sink over the node's registry repository.
    ///
    /// Args:
    /// * `store`: The per-prefix store rooted at the `--registry` dir.
    ///
    /// Usage:
    /// ```ignore
    /// let sink = KelStoreSink::new(PerPrefixKelStore::open(&args.registry));
    /// ```
    pub fn new(store: PerPrefixKelStore) -> Self {
        Self { store }
    }

    /// SAID of the event already stored at a sequence, for conflict evidence.
    fn stored_said_at(&self, prefix: &Prefix, seq: u128) -> Option<String> {
        self.store
            .get_event(prefix, seq)
            .ok()
            .map(|e| e.said().to_string())
    }
}

impl KelSink for KelStoreSink {
    fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &serde_json::Value,
        attachment: &[u8],
    ) -> Result<KelSinkOutcome, KelSinkError> {
        if attachment.is_empty() {
            return Err(KelSinkError::Invalid(
                "this witness requires the envelope dialect — submit \
                 {\"event\": …, \"attachment_b64\": …} with CESR signatures"
                    .to_string(),
            ));
        }
        let event: Event = serde_json::from_value(event.clone())
            .map_err(|e| KelSinkError::Invalid(format!("not a KERI event: {e}")))?;
        let seq = event.sequence().value();

        match self.store.append_signed_event(prefix, &event, attachment) {
            Ok(KelAppendOutcome::Appended) => Ok(KelSinkOutcome::Appended),
            Ok(KelAppendOutcome::AlreadyStored) => Ok(KelSinkOutcome::AlreadyStored),
            Err(RegistryError::EventExists { .. }) => Err(KelSinkError::Conflict {
                existing_said: self.stored_said_at(prefix, seq),
            }),
            Err(
                e @ (RegistryError::SequenceGap { .. }
                | RegistryError::SaidMismatch { .. }
                | RegistryError::InvalidPrefix { .. }
                | RegistryError::InvalidEvent { .. }),
            ) => Err(KelSinkError::Invalid(e.to_string())),
            Err(other) => Err(KelSinkError::Storage(other.to_string())),
        }
    }
}
