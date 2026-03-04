use crate::error::StorageError;
use auths_verifier::core::{Attestation, VerifiedAttestation};
use std::sync::Arc;

/// Function signature for encoding an attestation into bytes.
pub type AttestationEncoder =
    Arc<dyn Fn(&Attestation) -> Result<Vec<u8>, StorageError> + Send + Sync>;

/// Trait for destinations that can accept and store an attestation.
pub trait AttestationSink {
    /// Export/Save a verified attestation to the configured destination.
    ///
    /// Accepts a [`VerifiedAttestation`] to enforce at the type level that
    /// signatures were checked before storage.
    fn export(&self, attestation: &VerifiedAttestation) -> Result<(), StorageError>;

    /// Update any secondary index after an attestation mutation.
    ///
    /// The default implementation is a no-op. Adapters backed by a searchable
    /// index (e.g. SQLite) override this to keep their index consistent.
    /// Callers invoke this unconditionally after every mutation — no feature
    /// flags are needed in orchestration code.
    fn sync_index(&self, _attestation: &Attestation) {}
}
