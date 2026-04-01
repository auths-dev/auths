use std::sync::Mutex;

use auths_verifier::core::{Attestation, VerifiedAttestation};
use auths_verifier::types::DeviceDID;

use crate::attestation::export::AttestationSink;
use crate::error::StorageError;
use crate::storage::attestation::AttestationSource;

/// In-memory `AttestationSink` for use in tests.
pub struct FakeAttestationSink {
    stored: Mutex<Vec<Attestation>>,
}

impl FakeAttestationSink {
    /// Create an empty `FakeAttestationSink`.
    pub fn new() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
        }
    }
}

impl Default for FakeAttestationSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationSink for FakeAttestationSink {
    fn export(&self, attestation: &VerifiedAttestation) -> Result<(), StorageError> {
        self.stored
            .lock()
            .unwrap()
            .push(attestation.inner().clone());
        Ok(())
    }
}

/// In-memory `AttestationSource` for use in tests.
pub struct FakeAttestationSource {
    attestations: Mutex<Vec<Attestation>>,
}

impl FakeAttestationSource {
    /// Create an empty `FakeAttestationSource`.
    pub fn new() -> Self {
        Self {
            attestations: Mutex::new(Vec::new()),
        }
    }
}

impl Default for FakeAttestationSource {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationSource for FakeAttestationSource {
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError> {
        let guard = self.attestations.lock().unwrap();
        Ok(guard
            .iter()
            .filter(|a| a.subject.as_str() == device_did.as_str())
            .cloned()
            .collect())
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, StorageError> {
        Ok(self.attestations.lock().unwrap().clone())
    }

    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, StorageError> {
        let guard = self.attestations.lock().unwrap();
        let dids: std::collections::HashSet<DeviceDID> = guard
            .iter()
            .filter_map(|a| DeviceDID::parse(a.subject.as_str()).ok())
            .collect();
        Ok(dids.into_iter().collect())
    }
}
