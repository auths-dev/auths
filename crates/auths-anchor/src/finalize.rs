//! Threshold finalization — assembly and verification (A4, I-FINAL-1/2).
//!
//! A [`FinalizedAnchor`] is verified by value and offline: ≥ `t` distinct
//! cosignatures, every cosigner inside the *declared* set resolved from the KEL,
//! each signature valid over the anchor's cosign message, and each inclusion
//! proof valid against its stated root. The honesty-ceiling of the actual
//! quorum reuses the shipped `witness::independence` engine — the diversity math
//! is not re-derived here.

use auths_crypto::CurveType;
use auths_keri::witness::independence::{
    EquivocationDetection, HonestyCeiling, Independence, IndependencePolicy, Infrastructure,
    Jurisdiction, OperatorAttributes, OperatorId, Organization, honesty_ceiling, spans_distinct,
};

use crate::error::AnchorError;
use crate::types::FinalizedAnchor;
use crate::verify::verify_signature;

/// Verify a finalized anchor from scratch, offline and by value (I-VERIFY-1).
///
/// Enforces, in order: the resolved set matches the SAID the anchor commits to
/// (I-TRUST-3); every cosignature is from a declared member and verifies over
/// [`crate::types::Anchor::cosign_bytes`]; the count of *distinct* valid
/// cosigners meets the threshold (I-FINAL-1); and every inclusion proof verifies
/// against the anchor leaf.
///
/// Args:
/// * `finalized`: the finalized anchor to check.
///
/// Usage:
/// ```ignore
/// verify_finalized(&finalized)?; // an RP can run this with no network
/// ```
pub fn verify_finalized(finalized: &FinalizedAnchor) -> Result<(), AnchorError> {
    let committed = &finalized.anchor.witness_set.said;
    if &finalized.witness_set.said != committed {
        return Err(AnchorError::WitnessSetMismatch {
            committed: committed.clone(),
            resolved: finalized.witness_set.said.clone(),
        });
    }

    let threshold = finalized.anchor.witness_set.threshold;
    let cosign_message = finalized.anchor.cosign_bytes()?;

    let mut distinct: Vec<&str> = Vec::new();
    for cosig in &finalized.cosignatures {
        let member = finalized
            .witness_set
            .member(&cosig.witness_name)
            .ok_or_else(|| AnchorError::CosignerOutsideSet {
                name: cosig.witness_name.clone(),
            })?;

        // Verify under the *declared* member key, never the self-reported key in
        // the cosignature: the trust anchor is the KEL-resolved set.
        let valid = verify_signature(
            CurveType::Ed25519,
            &member.public_key,
            &cosign_message,
            cosig.signature.as_bytes(),
        )?;
        if !valid {
            return Err(AnchorError::CosignatureInvalid {
                name: cosig.witness_name.clone(),
            });
        }
        if !distinct.contains(&cosig.witness_name.as_str()) {
            distinct.push(&cosig.witness_name);
        }
    }

    let got = distinct.len() as u32;
    if got < threshold {
        return Err(AnchorError::ThresholdNotMet { got, threshold });
    }

    let leaf = auths_transparency::hash_leaf(&cosign_message);
    for proof in &finalized.inclusion {
        proof
            .verify(&leaf)
            .map_err(|e| AnchorError::InclusionInvalid(e.to_string()))?;
    }

    Ok(())
}

/// The independence verdict of the *actual* co-signing quorum (not the roster).
///
/// Maps each cosigner's operator metadata onto the shipped
/// [`OperatorAttributes`] and runs [`spans_distinct`]. Cosigners without
/// operator metadata contribute nothing to the diversity count (fail-closed:
/// unproven diversity never inflates the ceiling).
///
/// Args:
/// * `finalized`: the finalized anchor whose quorum is assessed.
/// * `policy`: the independence floors to test against.
pub fn quorum_independence(
    finalized: &FinalizedAnchor,
    policy: &IndependencePolicy,
) -> Result<Independence, AnchorError> {
    let mut attrs = Vec::new();
    for cosig in &finalized.cosignatures {
        let member = finalized
            .witness_set
            .member(&cosig.witness_name)
            .ok_or_else(|| AnchorError::CosignerOutsideSet {
                name: cosig.witness_name.clone(),
            })?;
        let Some(operator) = &member.operator else {
            continue;
        };
        let map_err = |e: auths_keri::witness::independence::IndependenceError| {
            AnchorError::MalformedMaterial(e.to_string())
        };
        attrs.push(OperatorAttributes {
            operator: OperatorId::new(operator.operator.as_str()).map_err(map_err)?,
            organization: Organization::new(operator.organization.as_str()).map_err(map_err)?,
            jurisdiction: Jurisdiction::new(operator.jurisdiction.as_str()).map_err(map_err)?,
            infrastructure: Infrastructure::new(operator.infrastructure.as_str())
                .map_err(map_err)?,
            key: hex::encode(&member.public_key),
        });
    }
    Ok(spans_distinct(&attrs, policy))
}

/// The honesty ceiling of a finalized anchor's quorum: how many parties would
/// have to collude before the accountability guarantee breaks.
///
/// Args:
/// * `finalized`: the finalized anchor to assess.
/// * `policy`: the independence floors.
/// * `equivocation`: whether cross-witness equivocation is sampled or
///   non-repudiable at the observing tier.
pub fn honesty_ceiling_of(
    finalized: &FinalizedAnchor,
    policy: &IndependencePolicy,
    equivocation: EquivocationDetection,
) -> Result<HonestyCeiling, AnchorError> {
    let independence = quorum_independence(finalized, policy)?;
    Ok(honesty_ceiling(&independence, equivocation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{finalized_sample, with_cosigners};

    #[test]
    fn threshold_met_verifies() {
        let finalized = finalized_sample(3, 2); // 3 witnesses, t=2
        verify_finalized(&finalized).unwrap();
    }

    #[test]
    fn below_threshold_rejected() {
        let finalized = with_cosigners(finalized_sample(3, 3), 2); // only 2 of t=3
        assert!(matches!(
            verify_finalized(&finalized),
            Err(AnchorError::ThresholdNotMet {
                got: 2,
                threshold: 3
            })
        ));
    }

    #[test]
    fn duplicate_cosigner_does_not_count_twice() {
        let mut finalized = finalized_sample(3, 2);
        // Re-append the first cosignature: still only one distinct witness here.
        let first = finalized.cosignatures[0].clone();
        finalized.cosignatures = vec![first.clone(), first];
        assert!(matches!(
            verify_finalized(&finalized),
            Err(AnchorError::ThresholdNotMet {
                got: 1,
                threshold: 2
            })
        ));
    }
}
