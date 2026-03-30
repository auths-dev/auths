//! Device linking and management.
//!
//! Handles device attestation lifecycle: link, revoke, extend.

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::SecureSigner;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;

pub use auths_sdk::{
    DeviceError, DeviceExtensionConfig, DeviceExtensionResult, DeviceLinkConfig, DeviceLinkResult,
};

// Re-export device workflow functions from SDK
pub use crate::domains::device::workflows::{extend_device, link_device, revoke_device};

/// Service for device operations.
///
/// - `attestation_source`: For loading existing device attestations.
/// - `attestation_sink`: For persisting device attestations.
/// - `signer`: For cryptographic signing of attestations.
/// - `clock`: For timestamping operations.
/// - `uuid_provider`: For generating resource IDs.
#[allow(dead_code)]
pub struct DeviceService<A, K, S, C, U> {
    attestation_source: A,
    attestation_sink: K,
    signer: S,
    clock: C,
    uuid_provider: U,
}

impl<A: AttestationSource, K: AttestationSink, S: SecureSigner, C: ClockProvider, U: UuidProvider>
    DeviceService<A, K, S, C, U>
{
    /// Create a new device service.
    ///
    /// Args:
    /// * `attestation_source`: Source for loading device attestations.
    /// * `attestation_sink`: Sink for persisting device attestations.
    /// * `signer`: Signer for creating cryptographic signatures.
    /// * `clock`: Clock for timestamping.
    /// * `uuid_provider`: UUID generator for resource IDs.
    ///
    /// Usage:
    /// ```ignore
    /// let service = DeviceService::new(source, sink, signer, clock, uuid_provider);
    /// ```
    pub fn new(
        attestation_source: A,
        attestation_sink: K,
        signer: S,
        clock: C,
        uuid_provider: U,
    ) -> Self {
        Self {
            attestation_source,
            attestation_sink,
            signer,
            clock,
            uuid_provider,
        }
    }
}
