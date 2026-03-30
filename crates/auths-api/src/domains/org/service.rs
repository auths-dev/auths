//! Organization membership workflows: add, revoke, update, and list members.
//!
//! All workflows accept trait injections for infrastructure adapters
//! (registry, clock, signer, passphrase provider, attestation sink).

use auths_core::ports::clock::ClockProvider;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::identity::IdentityStorage;

pub use auths_sdk::OrgError;

/// Service for organization operations.
///
/// - `identity_storage`: For loading organization identity records.
/// - `attestation_sink`: For persisting member attestations.
/// - `clock`: For timestamping member operations.
#[allow(dead_code)]
pub struct OrgService<I, K, C> {
    identity_storage: I,
    attestation_sink: K,
    clock: C,
}

impl<I: IdentityStorage, K: AttestationSink, C: ClockProvider> OrgService<I, K, C> {
    /// Create a new organization service.
    ///
    /// Args:
    /// * `identity_storage`: Storage for organization identity records.
    /// * `attestation_sink`: Sink for persisting member attestations.
    /// * `clock`: Clock for timestamping.
    ///
    /// Usage:
    /// ```ignore
    /// let service = OrgService::new(storage, sink, clock);
    /// ```
    pub fn new(identity_storage: I, attestation_sink: K, clock: C) -> Self {
        Self {
            identity_storage,
            attestation_sink,
            clock,
        }
    }
}
