//! The anchor role — a witness's spend-anchor service (C2, phase-0 core).
//!
//! This is the I/O-orchestration half above the pure protocol core: it resolves
//! prior state through the [`AnchorStore`], runs the pure `accept_anchor` rule,
//! and — on acceptance — CAS-stores and cosigns. The store is the serialization
//! point, so a concurrent fork is caught as a lost CAS and re-run against the
//! winner, which yields a duplicity proof if the heads differ (I-DUP-1). The
//! node never forks the rule; it composes it.

use auths_anchor::{
    Acceptance, Anchor, AnchorError, AnchorStore, CasOutcome, ControllerKeys, DuplicityProof,
    StoreError, WitnessCosignature, accept_anchor,
};
use chrono::{DateTime, Utc};

use crate::signer::Signer;

/// What the service decided for one submission.
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// The anchor was accepted, stored, and cosigned.
    CoSigned {
        /// The stored anchor.
        anchor: Box<Anchor>,
        /// This witness's cosignature over the anchor's cosign message.
        cosignature: Box<WitnessCosignature>,
    },
    /// The anchor equivocated against the co-signed prior — refused, with the
    /// publishable proof (I-DUP-2).
    Duplicity(Box<DuplicityProof>),
}

/// A failure serving one submission.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    /// The pure acceptance rule rejected the request (non-monotone, bad sig, …).
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// The anchor store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A concurrent writer won the CAS with a non-conflicting anchor; the caller
    /// should retry against fresh prior state.
    #[error("lost a compare-and-set race without a fork — retry")]
    Contended,
}

/// A witness's anchor-acceptance service over a signer and a store.
pub struct AnchorService<S, T> {
    signer: S,
    store: T,
}

impl<S: Signer, T: AnchorStore> AnchorService<S, T> {
    /// Build a service from a signer and a store.
    ///
    /// Args:
    /// * `signer`: the witness cosigning identity.
    /// * `store`: the per-seed latest-anchor store.
    pub fn new(signer: S, store: T) -> Self {
        Self { signer, store }
    }

    /// Decide, store, and (on acceptance) cosign one anchor request.
    ///
    /// Args:
    /// * `req`: the incoming anchor request.
    /// * `keys`: the controller's current keys (resolved from the KEL upstream).
    /// * `now`: injected clock.
    ///
    /// Usage:
    /// ```ignore
    /// match service.submit(&req, &keys, clock.now())? {
    ///     SubmitOutcome::CoSigned { cosignature, .. } => respond(cosignature),
    ///     SubmitOutcome::Duplicity(proof) => refuse_and_publish(proof),
    /// }
    /// ```
    pub fn submit(
        &self,
        req: &Anchor,
        keys: &ControllerKeys,
        now: DateTime<Utc>,
    ) -> Result<SubmitOutcome, ServiceError> {
        let prior = self.store.latest(&req.seed_id)?;
        match accept_anchor(req, keys, prior.as_ref(), now)? {
            Acceptance::Duplicity(proof) => Ok(SubmitOutcome::Duplicity(proof)),
            Acceptance::CoSign(anchor) => {
                let expected = prior.as_ref().map(|p| p.index);
                match self
                    .store
                    .compare_and_set(&req.seed_id, expected, &anchor)?
                {
                    CasOutcome::Won => {
                        let cosignature = self.cosign(&anchor, now)?;
                        Ok(SubmitOutcome::CoSigned {
                            anchor,
                            cosignature: Box::new(cosignature),
                        })
                    }
                    CasOutcome::Lost(winner) => {
                        match accept_anchor(req, keys, Some(&winner), now)? {
                            Acceptance::Duplicity(proof) => Ok(SubmitOutcome::Duplicity(proof)),
                            Acceptance::CoSign(_) => Err(ServiceError::Contended),
                        }
                    }
                }
            }
        }
    }

    /// The latest co-signed anchor for a seed (FR-7 read surface).
    ///
    /// Args:
    /// * `seed`: the spend chain to read.
    pub fn latest(&self, seed: &auths_anchor::SeedId) -> Result<Option<Anchor>, ServiceError> {
        Ok(self.store.latest(seed)?)
    }

    /// Cosign an accepted anchor with the witness key.
    fn cosign(
        &self,
        anchor: &Anchor,
        now: DateTime<Utc>,
    ) -> Result<WitnessCosignature, ServiceError> {
        let message = anchor.cosign_bytes()?;
        Ok(WitnessCosignature {
            witness_name: self.signer.witness_name().to_string(),
            witness_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                self.signer.public_key(),
            ),
            signature: auths_verifier::Ed25519Signature::from_bytes(self.signer.sign(&message)),
            timestamp: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor_store::InMemoryAnchorStore;
    use crate::signer::FileSigner;
    use auths_anchor::{CurrentKey, CurveType, Head, PartySignature, SeedId, WitnessSetRef};
    use ed25519_dalek::{Signer as _, SigningKey};

    fn now() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_800_000_000, 0).unwrap()
    }

    fn party_sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn signed_anchor(index: u64, head: [u8; 32]) -> Anchor {
        let sk = party_sk();
        let mut anchor = Anchor {
            seed_id: SeedId::derive("root", "agent", "seal"),
            index,
            head: Head::from_bytes(head),
            cumulative: index as u128 * 100,
            timestamp: now(),
            witness_set: WitnessSetRef {
                said: "EWit".into(),
                threshold: 1,
            },
            sig_party: PartySignature {
                curve: CurveType::Ed25519,
                public_key: sk.verifying_key().as_bytes().to_vec(),
                signature: Vec::new(),
            },
        };
        let msg = anchor.party_signing_bytes().unwrap();
        anchor.sig_party.signature = sk.sign(&msg).to_bytes().to_vec();
        anchor
    }

    fn keys() -> ControllerKeys {
        ControllerKeys {
            current: vec![CurrentKey {
                curve: CurveType::Ed25519,
                public_key: party_sk().verifying_key().as_bytes().to_vec(),
            }],
        }
    }

    fn service() -> AnchorService<FileSigner, InMemoryAnchorStore> {
        AnchorService::new(
            FileSigner::from_seed("us-west", [1u8; 32]),
            InMemoryAnchorStore::new(),
        )
    }

    #[test]
    fn cosigns_then_refuses_a_fork() {
        let svc = service();
        let first = signed_anchor(1, [1u8; 32]);
        assert!(matches!(
            svc.submit(&first, &keys(), now()).unwrap(),
            SubmitOutcome::CoSigned { .. }
        ));

        // A second anchor at the same index with a different head is equivocation.
        let fork = signed_anchor(1, [2u8; 32]);
        assert!(matches!(
            svc.submit(&fork, &keys(), now()).unwrap(),
            SubmitOutcome::Duplicity(_)
        ));
    }

    #[test]
    fn cosignature_verifies_against_the_anchor() {
        let svc = service();
        let anchor = signed_anchor(1, [7u8; 32]);
        let SubmitOutcome::CoSigned {
            cosignature,
            anchor,
        } = svc.submit(&anchor, &keys(), now()).unwrap()
        else {
            panic!("expected cosign");
        };
        let message = anchor.cosign_bytes().unwrap();
        assert!(
            auths_anchor::verify_signature(
                CurveType::Ed25519,
                cosignature.witness_public_key.as_bytes(),
                &message,
                cosignature.signature.as_bytes(),
            )
            .unwrap()
        );
    }
}
