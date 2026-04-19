use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;

use std::collections::BTreeMap;

use super::enriched::EnrichedAttestation;

/// A group of attestations indexed by device DID (subject).
#[derive(Debug)]
pub struct AttestationGroup {
    /// Map of device DID string (subject) → list of attestations
    pub by_device: BTreeMap<String, Vec<Attestation>>,
}

impl AttestationGroup {
    /// Groups a list of attestations by their `subject` field (device DID).
    pub fn from_list(attestations: Vec<Attestation>) -> Self {
        let mut map: BTreeMap<String, Vec<Attestation>> = BTreeMap::new();

        for att in attestations {
            // Use the new field name 'subject'
            let key = att.subject.as_str().to_owned();
            map.entry(key).or_default().push(att);
        }

        Self { by_device: map }
    }

    /// Returns the number of distinct devices (subjects) found.
    pub fn device_count(&self) -> usize {
        self.by_device.len()
    }

    /// Flattens into all attestations in sorted key order.
    pub fn all(&self) -> Vec<&Attestation> {
        self.by_device.values().flat_map(|v| v.iter()).collect()
    }

    /// Returns the attestations for a specific device DID string (subject).
    pub fn get(&self, device_did_str: &str) -> Option<&Vec<Attestation>> {
        self.by_device.get(device_did_str)
    }

    /// Returns the most recent attestation for the given device DID (subject).
    pub fn latest(&self, device_did: &DeviceDID) -> Option<&Attestation> {
        self.by_device
            .get(device_did.as_str())
            .and_then(|list| list.last())
    }
}

/// Attestation group carrying enriched (SAID + anchor status) entries.
#[derive(Debug)]
pub struct EnrichedAttestationGroup {
    pub by_device: BTreeMap<String, Vec<EnrichedAttestation>>,
}

impl EnrichedAttestationGroup {
    /// Groups enriched attestations by their `subject` field (device DID).
    pub fn from_enriched(attestations: Vec<EnrichedAttestation>) -> Self {
        let mut map: BTreeMap<String, Vec<EnrichedAttestation>> = BTreeMap::new();
        for att in attestations {
            let key = att.attestation.subject.as_str().to_owned();
            map.entry(key).or_default().push(att);
        }
        Self { by_device: map }
    }

    /// Returns the number of distinct devices (subjects) found.
    pub fn device_count(&self) -> usize {
        self.by_device.len()
    }

    /// Returns the most recent enriched attestation for the given device DID.
    pub fn latest(&self, device_did: &DeviceDID) -> Option<&EnrichedAttestation> {
        self.by_device
            .get(device_did.as_str())
            .and_then(|list| list.last())
    }
}
