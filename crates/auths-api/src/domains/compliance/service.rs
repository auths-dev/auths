//! Approval workflow functions.
//!
//! Three-phase design:
//! 1. `build_approval_attestation` — pure, deterministic attestation construction.
//! 2. `apply_approval` — side-effecting: consume nonce, remove pending request.
//! 3. `grant_approval` — high-level orchestrator (calls load → build → apply).

use auths_core::ports::clock::ClockProvider;
use auths_id::storage::attestation::AttestationSource;

/// Service for compliance and approval operations.
///
/// - `attestation_source`: For loading existing attestations to verify approval state.
/// - `clock`: For timestamping approval operations.
#[allow(dead_code)]
pub struct ComplianceService<A, C> {
    attestation_source: A,
    clock: C,
}

impl<A: AttestationSource, C: ClockProvider> ComplianceService<A, C> {
    /// Create a new compliance service.
    ///
    /// Args:
    /// * `attestation_source`: Source for loading attestations.
    /// * `clock`: Clock for timestamping.
    ///
    /// Usage:
    /// ```ignore
    /// let service = ComplianceService::new(source, clock);
    /// ```
    pub fn new(attestation_source: A, clock: C) -> Self {
        Self {
            attestation_source,
            clock,
        }
    }
}
