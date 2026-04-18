//! Attestation enrichment with KEL anchor status.
//!
//! Provides [`EnrichedAttestation`] — an attestation paired with its canonical
//! SAID and KEL anchor status. The enrichment is computed once at load time;
//! downstream code works with the enriched type and never re-hashes.

use std::collections::HashSet;

use auths_keri::{AnchorStatus, Said};
use auths_verifier::core::Attestation;

use crate::error::StorageError;
use crate::storage::attestation::AttestationSource;

/// Attestation enriched with its canonical SAID and KEL anchor status.
#[derive(Debug, Clone)]
pub struct EnrichedAttestation {
    pub attestation: Attestation,
    pub said: Said,
    pub anchor: AnchorStatus,
}

/// Compute the canonical SAID of a serializable value.
pub fn canonical_said<T: serde::Serialize>(data: &T) -> Option<Said> {
    let canonical = json_canon::to_string(data).ok()?;
    let value: serde_json::Value = serde_json::from_str(&canonical).ok()?;
    auths_keri::compute_said(&value).ok()
}

/// Build the set of all SAIDs anchored in the KEL via ixn digest seals.
///
/// One KEL walk — O(events). The returned set supports O(1) membership checks.
pub fn build_anchor_set(
    backend: &dyn crate::storage::registry::backend::RegistryBackend,
    controller_prefix: &auths_keri::Prefix,
) -> HashSet<Said> {
    crate::keri::resolve_anchored_saids_via_backend(backend, controller_prefix, None)
        .unwrap_or_default()
        .into_iter()
        .map(|(_seq, said)| said)
        .collect()
}

/// Enrich a single attestation against a pre-built anchor set. No I/O.
pub fn enrich_attestation(
    attestation: Attestation,
    anchor_set: &HashSet<Said>,
) -> EnrichedAttestation {
    let said = canonical_said(&attestation).unwrap_or_default();
    let anchor = if anchor_set.contains(&said) {
        AnchorStatus::Anchored
    } else {
        AnchorStatus::NotAnchored
    };
    EnrichedAttestation {
        attestation,
        said,
        anchor,
    }
}

/// Enrich a batch of attestations. One set lookup per attestation.
pub fn enrich_all(
    attestations: Vec<Attestation>,
    anchor_set: &HashSet<Said>,
) -> Vec<EnrichedAttestation> {
    attestations
        .into_iter()
        .map(|att| enrich_attestation(att, anchor_set))
        .collect()
}

/// Load attestations from storage and enrich with KEL anchor status.
///
/// Composes `load_all_attestations` + `build_anchor_set` + `enrich_all`.
pub fn load_enriched_attestations(
    source: &dyn AttestationSource,
    backend: &dyn crate::storage::registry::backend::RegistryBackend,
    controller_prefix: &auths_keri::Prefix,
) -> Result<Vec<EnrichedAttestation>, StorageError> {
    let attestations = source.load_all_attestations()?;
    let anchor_set = build_anchor_set(backend, controller_prefix);
    Ok(enrich_all(attestations, &anchor_set))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(subject: &str) -> Attestation {
        auths_verifier::AttestationBuilder::default()
            .subject(subject)
            .build()
    }

    #[test]
    fn enrich_marks_anchored_when_said_in_set() {
        let att = make_attestation("did:key:device1");
        let said = canonical_said(&att).unwrap();

        let mut anchor_set = HashSet::new();
        anchor_set.insert(said.clone());

        let enriched = enrich_attestation(att, &anchor_set);
        assert_eq!(enriched.anchor, AnchorStatus::Anchored);
        assert_eq!(enriched.said, said);
    }

    #[test]
    fn enrich_marks_not_anchored_when_said_absent() {
        let att = make_attestation("did:key:device2");

        let anchor_set = HashSet::new();

        let enriched = enrich_attestation(att, &anchor_set);
        assert_eq!(enriched.anchor, AnchorStatus::NotAnchored);
    }

    #[test]
    fn enrich_all_processes_batch() {
        let att1 = make_attestation("did:key:d1");
        let att2 = make_attestation("did:key:d2");
        let said1 = canonical_said(&att1).unwrap();

        let mut anchor_set = HashSet::new();
        anchor_set.insert(said1);

        let enriched = enrich_all(vec![att1, att2], &anchor_set);
        assert_eq!(enriched.len(), 2);
        assert_eq!(enriched[0].anchor, AnchorStatus::Anchored);
        assert_eq!(enriched[1].anchor, AnchorStatus::NotAnchored);
    }

    #[test]
    fn canonical_said_is_deterministic() {
        let att = make_attestation("did:key:device1");
        let s1 = canonical_said(&att);
        let s2 = canonical_said(&att);
        assert_eq!(s1, s2);
    }
}
