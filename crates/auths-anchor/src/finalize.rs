//! Threshold finalization — assembly and verification (A4, I-FINAL-1/2).
//!
//! A [`FinalizedAnchor`] is verified by value and offline: ≥ `t` distinct
//! cosignatures, every cosigner inside the *declared* set resolved from the KEL,
//! each signature valid over the anchor's cosign message, and each inclusion
//! proof valid against its stated root. The honesty-ceiling of the actual
//! quorum reuses the shipped `witness::independence` engine — the diversity math
//! is not re-derived here.

use auths_keri::witness::independence::{
    EquivocationDetection, HonestyCeiling, Independence, IndependencePolicy, Infrastructure,
    Jurisdiction, OperatorAttributes, OperatorId, Organization, honesty_ceiling, spans_distinct,
};

use crate::error::AnchorError;
use crate::types::FinalizedAnchor;
use crate::verify::verify_signature;

/// Verify a finalized anchor from scratch, offline and by value (I-VERIFY-1).
///
/// Enforces, in order:
/// 1. the resolved set is structurally valid and **self-addressing** — its
///    canonical content hashes to the SAID the *party-signed* anchor commits
///    to, so the set cannot be substituted after the fact;
/// 2. when the caller supplies `declared_said` (resolved independently, e.g.
///    from the principal's KEL), the committed SAID must equal it — this is
///    what closes witness-set equivocation once a KEL seal exists;
/// 3. every cosignature is from a declared member and verifies over
///    [`crate::types::Anchor::cosign_bytes`] under the *declared* member key;
/// 4. a cosigner counts toward the threshold only with a valid
///    [`crate::types::LoggedInclusion`]: a checkpoint signed by that member
///    whose root the inclusion proof reaches from the anchor leaf — an
///    unlogged cosignature is not finalization-grade;
/// 5. the count of distinct, logged, valid cosigners meets the threshold.
///
/// Args:
/// * `finalized`: the finalized anchor to check.
/// * `declared_said`: the witness-set SAID resolved from an independent
///   source (the principal's KEL), when the caller has one. `None` verifies
///   self-addressing only — sufficient against substitution, not against a
///   principal declaring different sets to different verifiers.
///
/// Usage:
/// ```ignore
/// verify_finalized(&finalized, Some(&kel_declared_said))?; // no network
/// ```
pub fn verify_finalized(
    finalized: &FinalizedAnchor,
    declared_said: Option<&str>,
) -> Result<(), AnchorError> {
    finalized.witness_set.validate()?;

    let committed = &finalized.anchor.witness_set.said;
    if &finalized.witness_set.said != committed {
        return Err(AnchorError::WitnessSetMismatch {
            committed: committed.clone(),
            resolved: finalized.witness_set.said.clone(),
        });
    }
    let computed = finalized.witness_set.computed_said()?;
    if &computed != committed {
        return Err(AnchorError::SetSaidMismatch {
            claimed: committed.clone(),
            computed,
        });
    }
    if let Some(declared) = declared_said
        && declared != committed
    {
        return Err(AnchorError::WitnessSetMismatch {
            committed: committed.clone(),
            resolved: declared.to_string(),
        });
    }

    let threshold = finalized.anchor.witness_set.threshold;
    let cosign_message = finalized.anchor.cosign_bytes()?;
    let leaf = auths_transparency::hash_leaf(&cosign_message);

    let mut counted: Vec<&str> = Vec::new();
    for cosig in &finalized.cosignatures {
        let member = finalized
            .witness_set
            .member(&cosig.witness_name)
            .ok_or_else(|| AnchorError::CosignerOutsideSet {
                name: cosig.witness_name.clone(),
            })?;

        // Verify under the *declared* member key, never the self-reported key in
        // the cosignature: the trust anchor is the self-addressed declared set.
        // Dispatch on the member's own in-band curve tag (validation already
        // refused any curve the cosignature format cannot carry).
        let valid = verify_signature(
            member.curve,
            &member.public_key,
            &cosign_message,
            cosig.signature.as_bytes(),
        )?;
        if !valid {
            return Err(AnchorError::CosignatureInvalid {
                name: cosig.witness_name.clone(),
            });
        }
        verify_logged_inclusion(finalized, member, &leaf, &cosig.witness_name)?;
        if !counted.contains(&cosig.witness_name.as_str()) {
            counted.push(&cosig.witness_name);
        }
    }

    let got = counted.len() as u32;
    if got < threshold {
        return Err(AnchorError::ThresholdNotMet { got, threshold });
    }

    Ok(())
}

/// Verify one cosigner's logged inclusion: a checkpoint signed under the
/// declared member key whose root the anchor-leaf inclusion proof reaches.
///
/// A bare Merkle proof against a self-stated root proves membership in *some*
/// tree anyone could build; the member-signed checkpoint is what ties the
/// anchor to that witness's own append-only log.
fn verify_logged_inclusion(
    finalized: &FinalizedAnchor,
    member: &crate::types::WitnessRef,
    leaf: &auths_transparency::MerkleHash,
    name: &str,
) -> Result<(), AnchorError> {
    let logged = finalized
        .inclusion
        .iter()
        .find(|l| l.witness_name == name)
        .ok_or_else(|| AnchorError::InclusionMissing {
            name: name.to_string(),
        })?;

    let key_bytes: [u8; 32] = member.public_key.as_slice().try_into().map_err(|_| {
        AnchorError::CheckpointUnverifiable {
            name: name.to_string(),
            detail: "declared member key is not 32-byte Ed25519".to_string(),
        }
    })?;
    let pinned = auths_verifier::Ed25519PublicKey::from_bytes(key_bytes);
    logged
        .checkpoint
        .verify_log_signature(&pinned)
        .map_err(|e| AnchorError::CheckpointUnverifiable {
            name: name.to_string(),
            detail: e.to_string(),
        })?;

    if logged.proof.root != logged.checkpoint.checkpoint.root
        || logged.proof.size != logged.checkpoint.checkpoint.size
    {
        return Err(AnchorError::CheckpointUnverifiable {
            name: name.to_string(),
            detail: "inclusion proof is not rooted in the signed checkpoint".to_string(),
        });
    }
    logged
        .proof
        .verify(leaf)
        .map_err(|e| AnchorError::InclusionInvalid(format!("{name}: {e}")))
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
        verify_finalized(&finalized, None).unwrap();
    }

    #[test]
    fn below_threshold_rejected() {
        let finalized = with_cosigners(finalized_sample(3, 3), 2); // only 2 of t=3
        assert!(matches!(
            verify_finalized(&finalized, None),
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
            verify_finalized(&finalized, None),
            Err(AnchorError::ThresholdNotMet {
                got: 1,
                threshold: 2
            })
        ));
    }

    #[test]
    fn forged_set_content_with_matching_said_strings_is_refused() {
        // The attack the SAID exists to kill: swap in a different member set
        // and stamp the anchor's committed SAID string onto it.
        let real = finalized_sample(3, 2);
        let mut forged = finalized_sample(3, 2);
        forged.witness_set.members[0].name = "attacker".to_string();
        forged.witness_set.said = real.anchor.witness_set.said.clone();
        assert!(matches!(
            verify_finalized(&forged, None),
            Err(AnchorError::SetSaidMismatch { .. }) | Err(AnchorError::CosignerOutsideSet { .. })
        ));
    }

    #[test]
    fn caller_declared_said_must_match() {
        let finalized = finalized_sample(3, 2);
        verify_finalized(&finalized, Some(&finalized.anchor.witness_set.said)).unwrap();
        assert!(matches!(
            verify_finalized(&finalized, Some("EIndependentlyResolvedOther")),
            Err(AnchorError::WitnessSetMismatch { .. })
        ));
    }

    #[test]
    fn cosigner_without_logged_inclusion_does_not_count() {
        let mut finalized = finalized_sample(3, 2);
        finalized.inclusion.remove(0);
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::InclusionMissing { .. })
        ));
    }

    #[test]
    fn inclusion_rooted_outside_the_signed_checkpoint_is_refused() {
        let mut finalized = finalized_sample(3, 2);
        // Self-rooted proof: valid Merkle math over a tree the checkpoint
        // never signed.
        let other_leaf = auths_transparency::hash_leaf(b"some other anchor");
        finalized.inclusion[0].proof.root = auths_transparency::compute_root(&[other_leaf]);
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::CheckpointUnverifiable { .. })
        ));
    }

    #[test]
    fn duplicate_member_names_are_refused() {
        let mut finalized = finalized_sample(3, 2);
        finalized.witness_set.members[1].name = finalized.witness_set.members[0].name.clone();
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::SetInvalid(_))
        ));
    }

    #[test]
    fn flipped_cosig_byte_rejected() {
        // A single flipped byte in a cosignature no longer verifies over the
        // cosign message — the quorum fails whole.
        let mut finalized = finalized_sample(3, 2);
        let mut bytes = *finalized.cosignatures[0].signature.as_bytes();
        bytes[0] ^= 0x01;
        finalized.cosignatures[0].signature = auths_verifier::Ed25519Signature::from_bytes(bytes);
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::CosignatureInvalid { .. })
        ));
    }

    #[test]
    fn foreign_witness_cosig_rejected() {
        // A cosignature attributed to a name outside the declared set is refused
        // — cosigners must be inside the declared witness set.
        let mut finalized = finalized_sample(3, 2);
        finalized.cosignatures[0].witness_name = "outsider".to_string();
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::CosignerOutsideSet { .. })
        ));
    }

    #[test]
    fn threshold_above_member_count_rejected() {
        // A threshold above the declared member count is a structurally invalid
        // set — refused before any key it declares is trusted.
        let finalized = finalized_sample(3, 5);
        assert!(matches!(
            verify_finalized(&finalized, None),
            Err(AnchorError::SetInvalid(_))
        ));
    }
}
