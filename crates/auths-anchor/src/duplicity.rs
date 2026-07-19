//! Duplicity proofs — equivocation made into a publishable, offline-verifiable
//! artifact (A6, I-DUP-2).
//!
//! A duplicity proof is self-contained: it carries both conflicting anchors,
//! each with the party signature inside, so a stranger with no KEL access and
//! no contact with the emitting witness can confirm the contradiction. The
//! claim it proves is unconditional: *one party key signed two different heads
//! at the same `(seed_id, index)`.* Cross-key equivocation across a rotation is
//! a KEL-resolved question handled by `auths-core::witness` duplicity
//! detection; this proof needs nothing but itself.

use serde::{Deserialize, Serialize};

use crate::error::AnchorError;
use crate::types::{Anchor, SeedId};
use crate::verify::verify_signature;

/// A publishable proof that a single party equivocated at one index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicityProof {
    /// The spend chain the equivocation is on.
    pub seed_id: SeedId,
    /// The index at which two heads were signed.
    pub index: u64,
    /// The two conflicting anchors, in canonical (head-ascending) order so the
    /// proof is byte-stable regardless of which side observed first.
    pub anchor_a: Anchor,
    /// The second conflicting anchor.
    pub anchor_b: Anchor,
}

impl DuplicityProof {
    /// Construct a proof from two conflicting anchors.
    ///
    /// Fails if the two are not a genuine same-party fork: same `seed_id`, same
    /// `index`, same party key, and *different* heads.
    ///
    /// Args:
    /// * `a`: one observed anchor.
    /// * `b`: the conflicting observed anchor.
    ///
    /// Usage:
    /// ```ignore
    /// let proof = DuplicityProof::new(&observed_a, &observed_b)?;
    /// proof.verify()?; // a stranger can re-run this offline
    /// ```
    pub fn new(a: &Anchor, b: &Anchor) -> Result<Self, AnchorError> {
        if a.seed_id != b.seed_id {
            return Err(AnchorError::InvalidDuplicityProof(
                "anchors are for different seeds".into(),
            ));
        }
        if a.index != b.index {
            return Err(AnchorError::InvalidDuplicityProof(
                "anchors are at different indices".into(),
            ));
        }
        if a.head == b.head {
            return Err(AnchorError::InvalidDuplicityProof(
                "anchors share a head — not a fork".into(),
            ));
        }
        if a.sig_party.curve != b.sig_party.curve
            || a.sig_party.public_key != b.sig_party.public_key
        {
            return Err(AnchorError::InvalidDuplicityProof(
                "anchors were signed by different party keys".into(),
            ));
        }
        let (anchor_a, anchor_b) = if a.head.as_bytes() <= b.head.as_bytes() {
            (a.clone(), b.clone())
        } else {
            (b.clone(), a.clone())
        };
        Ok(Self {
            seed_id: a.seed_id,
            index: a.index,
            anchor_a,
            anchor_b,
        })
    }

    /// Verify the proof from scratch, offline, with no external input.
    ///
    /// Checks the structural contradiction (same seed/index/party-key, different
    /// heads) and that *both* embedded party signatures verify.
    pub fn verify(&self) -> Result<(), AnchorError> {
        if self.anchor_a.seed_id != self.seed_id || self.anchor_b.seed_id != self.seed_id {
            return Err(AnchorError::InvalidDuplicityProof(
                "embedded anchor seed does not match the proof".into(),
            ));
        }
        if self.anchor_a.index != self.index || self.anchor_b.index != self.index {
            return Err(AnchorError::InvalidDuplicityProof(
                "embedded anchor index does not match the proof".into(),
            ));
        }
        if self.anchor_a.head == self.anchor_b.head {
            return Err(AnchorError::InvalidDuplicityProof(
                "embedded anchors share a head — no contradiction".into(),
            ));
        }
        let (ka, kb) = (&self.anchor_a.sig_party, &self.anchor_b.sig_party);
        if ka.curve != kb.curve || ka.public_key != kb.public_key {
            return Err(AnchorError::InvalidDuplicityProof(
                "embedded anchors were signed by different keys".into(),
            ));
        }
        for anchor in [&self.anchor_a, &self.anchor_b] {
            let message = anchor.party_signing_bytes()?;
            let valid = verify_signature(
                anchor.sig_party.curve,
                &anchor.sig_party.public_key,
                &message,
                &anchor.sig_party.signature,
            )?;
            if !valid {
                return Err(AnchorError::InvalidDuplicityProof(
                    "a party signature does not verify".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{sample_anchor, sample_anchor_with_head};

    #[test]
    fn genuine_fork_proves_and_verifies() {
        let a = sample_anchor_with_head(5, [1u8; 32]);
        let b = sample_anchor_with_head(5, [2u8; 32]);
        let proof = super::DuplicityProof::new(&a, &b).unwrap();
        proof.verify().unwrap();
    }

    #[test]
    fn same_head_is_not_a_fork() {
        let a = sample_anchor_with_head(5, [1u8; 32]);
        let b = sample_anchor_with_head(5, [1u8; 32]);
        assert!(super::DuplicityProof::new(&a, &b).is_err());
    }

    #[test]
    fn different_index_is_not_a_fork() {
        let a = sample_anchor(5);
        let b = sample_anchor(6);
        assert!(super::DuplicityProof::new(&a, &b).is_err());
    }

    #[test]
    fn proof_is_head_order_stable() {
        let a = sample_anchor_with_head(5, [9u8; 32]);
        let b = sample_anchor_with_head(5, [1u8; 32]);
        let p1 = super::DuplicityProof::new(&a, &b).unwrap();
        let p2 = super::DuplicityProof::new(&b, &a).unwrap();
        assert_eq!(p1, p2);
    }
}
