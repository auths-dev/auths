//! The anchor role — a witness's spend-anchor service.
//!
//! This is the I/O-orchestration half above the pure protocol core: it resolves
//! prior state through the [`AnchorStore`], runs the pure `accept_anchor` rule,
//! and — on acceptance — CAS-stores, cosigns, appends the anchor to the
//! witness's own append-only log, and returns the cosignature together with the
//! member-signed logged inclusion. A cosignature without a logged inclusion is
//! not finalization-grade, so the two are minted together or not at all. The
//! store is the serialization point: a concurrent fork is caught as a lost CAS
//! and re-run against the winner, which yields a duplicity proof if the heads
//! differ. The node never forks the rule; it composes it.

use auths_anchor::{
    Acceptance, Anchor, AnchorError, AnchorStore, CasOutcome, ControllerKeys, DuplicityProof,
    LoggedInclusion, StoreError, WitnessCosignature, accept_anchor,
};
use auths_transparency::{LogWriter, TileStore, hash_leaf};
use chrono::{DateTime, Utc};

use crate::signer::Signer;

/// What the service decided for one submission.
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// The anchor was accepted, stored, cosigned, and logged.
    CoSigned {
        /// The stored anchor.
        anchor: Box<Anchor>,
        /// This witness's cosignature over the anchor's cosign message.
        cosignature: Box<WitnessCosignature>,
        /// The member-signed checkpoint + inclusion proof for the anchor leaf —
        /// what makes the cosignature finalization-grade.
        inclusion: Box<LoggedInclusion>,
    },
    /// The anchor equivocated against the co-signed prior — refused, with the
    /// publishable proof.
    Duplicity(Box<DuplicityProof>),
}

/// A failure serving one submission.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The pure acceptance rule rejected the request (non-monotone, bad sig, …).
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// The anchor store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The witness log faulted while appending or proving.
    #[error("witness log error: {0}")]
    Log(String),
    /// A concurrent writer won the CAS with a non-conflicting anchor; the caller
    /// should retry against fresh prior state.
    #[error("lost a compare-and-set race without a fork — retry")]
    Contended,
}

/// A witness's anchor-acceptance service over a signer, a store, and its own
/// append-only log.
pub struct AnchorService<S, T, L: TileStore> {
    signer: S,
    store: T,
    log: LogWriter<L>,
}

impl<S: Signer, T: AnchorStore, L: TileStore> AnchorService<S, T, L> {
    /// Build a service from a signer, a store, and the witness's log writer.
    ///
    /// The log writer must sign with the SAME Ed25519 identity as `signer` —
    /// verifiers pin one member key for both the cosignature and the logged
    /// inclusion's checkpoint.
    ///
    /// Args:
    /// * `signer`: the witness cosigning identity.
    /// * `store`: the per-seed latest-anchor store.
    /// * `log`: the witness's append-only log, signing as the same identity.
    pub fn new(signer: S, store: T, log: LogWriter<L>) -> Self {
        Self { signer, store, log }
    }

    /// Decide, store, cosign, and log one anchor request.
    ///
    /// Args:
    /// * `req`: the incoming anchor request.
    /// * `keys`: the controller's current keys (resolved from the KEL upstream).
    /// * `now`: injected clock.
    ///
    /// Usage:
    /// ```ignore
    /// match service.submit(&req, &keys, clock.now()).await? {
    ///     SubmitOutcome::CoSigned { cosignature, inclusion, .. } => respond(cosignature, inclusion),
    ///     SubmitOutcome::Duplicity(proof) => refuse_and_publish(proof),
    /// }
    /// ```
    pub async fn submit(
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
                        let (cosignature, inclusion) = self.cosign_and_log(&anchor, now).await?;
                        Ok(SubmitOutcome::CoSigned {
                            anchor,
                            cosignature: Box::new(cosignature),
                            inclusion: Box::new(inclusion),
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

    /// The latest co-signed anchor for a seed (the public withholding-detection
    /// read).
    ///
    /// Args:
    /// * `seed`: the spend chain to read.
    pub fn latest(&self, seed: &auths_anchor::SeedId) -> Result<Option<Anchor>, ServiceError> {
        Ok(self.store.latest(seed)?)
    }

    /// Cosign an accepted anchor and append it to the witness's own log,
    /// returning the cosignature plus the member-signed logged inclusion.
    async fn cosign_and_log(
        &self,
        anchor: &Anchor,
        now: DateTime<Utc>,
    ) -> Result<(WitnessCosignature, LoggedInclusion), ServiceError> {
        let message = anchor.cosign_bytes().map_err(ServiceError::Anchor)?;
        let cosignature = WitnessCosignature {
            witness_name: self.signer.witness_name().to_string(),
            witness_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                self.signer.public_key(),
            ),
            signature: auths_verifier::Ed25519Signature::from_bytes(self.signer.sign(&message)),
            timestamp: now,
        };

        let leaf = hash_leaf(&message);
        self.log
            .append(leaf, now)
            .await
            .map_err(|e| ServiceError::Log(e.to_string()))?;
        // Proof and checkpoint come from ONE read of the grown log, so the
        // proof is always rooted in exactly the checkpoint beside it.
        let proven = self
            .log
            .prove(&leaf)
            .await
            .map_err(|e| ServiceError::Log(e.to_string()))?;
        let inclusion = LoggedInclusion {
            witness_name: self.signer.witness_name().to_string(),
            checkpoint: proven.signed_checkpoint,
            proof: proven.inclusion_proof,
        };
        Ok((cosignature, inclusion))
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Deterministic fixtures shared by the node's unit tests.

    use auths_anchor::{
        Anchor, ControllerKeys, CurrentKey, CurveType, Head, PartySignature, SeedId, WitnessSetRef,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::{Signer as _, SigningKey};

    pub(crate) fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap()
    }

    pub(crate) fn party_sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    pub(crate) fn signed_anchor(index: u64, head: [u8; 32]) -> Anchor {
        signed_anchor_committing(index, head, "EWit", 1)
    }

    pub(crate) fn signed_anchor_committing(
        index: u64,
        head: [u8; 32],
        said: &str,
        threshold: u32,
    ) -> Anchor {
        let sk = party_sk();
        let mut anchor = Anchor {
            seed_id: SeedId::derive("root", "agent", "seal"),
            index,
            head: Head::from_bytes(head),
            cumulative: index as u128 * 100,
            timestamp: now(),
            witness_set: WitnessSetRef {
                said: said.to_string(),
                threshold,
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

    pub(crate) fn keys() -> ControllerKeys {
        ControllerKeys {
            current: vec![CurrentKey {
                curve: CurveType::Ed25519,
                public_key: party_sk().verifying_key().as_bytes().to_vec(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{keys, now, signed_anchor};
    use super::*;
    use crate::anchor_store::InMemoryAnchorStore;
    use crate::signer::FileSigner;
    use auths_transparency::{FsTileStore, LogOrigin, LogSigningKey};

    fn service(
        dir: &std::path::Path,
    ) -> AnchorService<FileSigner, InMemoryAnchorStore, FsTileStore> {
        let seed = [1u8; 32];
        let log = LogWriter::new(
            FsTileStore::new(dir.to_path_buf()),
            LogSigningKey::from_seed(seed).unwrap(),
            LogOrigin::new("awn/us-west").unwrap(),
        );
        AnchorService::new(
            FileSigner::from_seed("us-west", seed),
            InMemoryAnchorStore::new(),
            log,
        )
    }

    #[tokio::test]
    async fn cosigns_logs_then_refuses_a_fork() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let first = signed_anchor(1, [1u8; 32]);
        let SubmitOutcome::CoSigned {
            anchor,
            cosignature,
            inclusion,
        } = svc.submit(&first, &keys(), now()).await.unwrap()
        else {
            panic!("expected cosign");
        };

        // The logged inclusion is finalization-grade: checkpoint signed by this
        // witness, proof rooted in it, leaf = this anchor's cosign message.
        let message = anchor.cosign_bytes().unwrap();
        let leaf = hash_leaf(&message);
        inclusion
            .checkpoint
            .verify_log_signature(&cosignature.witness_public_key)
            .unwrap();
        assert_eq!(inclusion.proof.root, inclusion.checkpoint.checkpoint.root);
        inclusion.proof.verify(&leaf).unwrap();

        let fork = signed_anchor(1, [2u8; 32]);
        assert!(matches!(
            svc.submit(&fork, &keys(), now()).await.unwrap(),
            SubmitOutcome::Duplicity(_)
        ));
    }

    #[tokio::test]
    async fn service_output_finalizes_under_the_strict_verifier() {
        use super::tests_support::signed_anchor_committing;
        let dir = tempfile::tempdir().unwrap();
        let seed = [1u8; 32];
        let wsk = ed25519_dalek::SigningKey::from_bytes(&seed);

        let mut set = auths_anchor::WitnessSet {
            said: String::new(),
            threshold: 1,
            members: vec![auths_anchor::WitnessRef {
                name: "us-west".into(),
                curve: auths_anchor::CurveType::Ed25519,
                public_key: wsk.verifying_key().as_bytes().to_vec(),
                operator: None,
            }],
        };
        set.said = set.computed_said().unwrap();

        let req = signed_anchor_committing(1, [7u8; 32], &set.said, 1);
        let svc = service(dir.path());
        let SubmitOutcome::CoSigned {
            anchor,
            cosignature,
            inclusion,
        } = svc.submit(&req, &keys(), now()).await.unwrap()
        else {
            panic!("expected cosign");
        };

        // The whole loop closes: what the node emitted is exactly what the
        // strict offline verifier accepts.
        let finalized = auths_anchor::FinalizedAnchor {
            anchor: *anchor,
            witness_set: set,
            cosignatures: vec![*cosignature],
            inclusion: vec![*inclusion],
        };
        auths_anchor::verify_finalized(&finalized, Some(&finalized.anchor.witness_set.said))
            .unwrap();
    }
}
