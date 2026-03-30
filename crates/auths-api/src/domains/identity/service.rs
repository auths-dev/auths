//! Identity provisioning and management.
//!
//! Handles setup of new identities (developer, CI, agent) with injected trait dependencies.

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;

// Re-export identity setup functions from auths-sdk
pub use auths_sdk::domains::identity::service::{initialize, install_registry_hook};

/// Service for identity operations.
///
/// - `identity_storage`: For loading/storing identity records.
/// - `attestation_source`: For loading existing attestations.
/// - `attestation_sink`: For persisting new attestations.
/// - `clock`: For timestamping operations.
/// - `uuid_provider`: For generating resource IDs.
#[allow(dead_code)]
pub struct IdentityService<S, A, K, C, U> {
    identity_storage: S,
    attestation_source: A,
    attestation_sink: K,
    clock: C,
    uuid_provider: U,
}

impl<
    S: IdentityStorage,
    A: AttestationSource,
    K: AttestationSink,
    C: ClockProvider,
    U: UuidProvider,
> IdentityService<S, A, K, C, U>
{
    /// Create a new identity service.
    ///
    /// Args:
    /// * `identity_storage`: Storage for identity records.
    /// * `attestation_source`: Source for loading attestations.
    /// * `attestation_sink`: Sink for persisting attestations.
    /// * `clock`: Clock for timestamping.
    /// * `uuid_provider`: UUID generator.
    ///
    /// Usage:
    /// ```ignore
    /// let service = IdentityService::new(storage, source, sink, clock, uuid_provider);
    /// ```
    pub fn new(
        identity_storage: S,
        attestation_source: A,
        attestation_sink: K,
        clock: C,
        uuid_provider: U,
    ) -> Self {
        Self {
            identity_storage,
            attestation_source,
            attestation_sink,
            clock,
            uuid_provider,
        }
    }
}
