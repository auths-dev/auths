//! Signing pipeline orchestration.
//!
//! Composed pipeline: validate freeze → sign data → format SSHSIG.
//! Agent communication and passphrase prompting remain in the CLI.

use auths_core::ports::clock::ClockProvider;
use auths_core::signing::SecureSigner;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;

// Re-export artifact signing types and functions from SDK
pub use crate::domains::signing::workflows::{
    ArtifactSigningParams, ArtifactSigningResult, SigningKeyMaterial, sign_artifact,
};

// Re-export error types from SDK
pub use auths_sdk::{ArtifactSigningError, SigningError};

/// Service for signing operations.
///
/// - `attestation_source`: For loading existing attestations.
/// - `attestation_sink`: For persisting new attestations.
/// - `signer`: For creating cryptographic signatures.
/// - `clock`: For timestamping operations.
#[allow(dead_code)]
pub struct SigningService<A, S, K, C> {
    attestation_source: A,
    attestation_sink: S,
    signer: K,
    clock: C,
}

impl<A: AttestationSource, S: AttestationSink, K: SecureSigner, C: ClockProvider>
    SigningService<A, S, K, C>
{
    /// Create a new signing service.
    ///
    /// Args:
    /// * `attestation_source`: Source for loading existing attestations.
    /// * `attestation_sink`: Sink for persisting new attestations.
    /// * `signer`: Signer for cryptographic operations.
    /// * `clock`: Clock for timestamping.
    ///
    /// Usage:
    /// ```ignore
    /// let service = SigningService::new(source, sink, signer, clock);
    /// ```
    pub fn new(attestation_source: A, attestation_sink: S, signer: K, clock: C) -> Self {
        Self {
            attestation_source,
            attestation_sink,
            signer,
            clock,
        }
    }
}
