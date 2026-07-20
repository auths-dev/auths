//! # auths-anchor — the Auths Witness Network protocol core
//!
//! The base construction proves tamper-evidence and authorization offline, but
//! a dishonest party defeats accountability for free by **withholding** recent
//! records or **equivocating**. This crate is the missing pure protocol core
//! that closes both gaps: a threshold quorum co-signs monotone growth anchors
//! `⟨seed_id, b_k, k, cum_k, τ_k⟩` into append-only logs, making rollback a
//! signed contradiction and equivocation a publishable duplicity proof — while
//! authorization verification stays offline and free (I-VERIFY-1).
//!
//! It is modeled on `auths-rp` (D3): pure, I/O-free, Layer 1.5. KEL resolution,
//! storage, and HTTP live above it in the node/SDK. The verification half
//! (freshness, finalized-anchor verification, duplicity-proof verification) is
//! WASM-safe.
//!
//! ## The pieces
//!
//! - [`accept_anchor`] — the §9.2 acceptance rule (pure, clock-injected).
//! - [`DuplicityProof`] — equivocation as a self-contained, offline artifact.
//! - [`verify_finalized`] / [`honesty_ceiling_of`] — `t`-of-`N` finalization.
//! - [`freshness`] — the `fresh | stale | unanchored` labeled result.
//! - [`AnchorStore`] — the per-seed latest-anchor port (CAS is the contract).

mod accept;
mod duplicity;
mod error;
mod finalize;
mod freshness;
mod keystate;
mod store;
mod types;
mod verify;

pub use accept::{Acceptance, MAX_FUTURE_SKEW_SECS, accept_anchor};
pub use duplicity::DuplicityProof;
pub use error::{AnchorError, StoreError};
pub use finalize::{honesty_ceiling_of, quorum_independence, verify_finalized};
pub use freshness::{Freshness, freshness};
pub use store::{AnchorStore, CasOutcome};
pub use types::{
    Anchor, AnchorReq, ControllerKeys, CurrentKey, FinalizedAnchor, Head, LoggedInclusion,
    OperatorInfo, PartySignature, SeedId, WitnessRef, WitnessSet, WitnessSetRef,
};
pub use verify::verify_signature;

/// The curve tag every anchor signature carries, re-exported so consumers
/// dispatch on the same allowlisted type the wire format names.
pub use auths_crypto::CurveType;

/// The shipped transparency types this crate composes over, re-exported so a
/// consumer building a [`FinalizedAnchor`] needs only one dependency.
pub use auths_transparency::{Checkpoint, InclusionProof, SignedCheckpoint, WitnessCosignature};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    //! Deterministic, fixed-seed fixtures for the in-crate unit tests and, under
    //! the `test-support` feature, for downstream test crates (`auths-evidence`).
    // Fixtures are test-only material built from fixed seeds, so these unwraps are
    // infallible; the `#[cfg(test)]` clippy exemption does not reach the
    // feature-gated build, so allow them explicitly here. Never in production.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use crate::types::{
        Anchor, ControllerKeys, CurrentKey, FinalizedAnchor, Head, OperatorInfo, PartySignature,
        SeedId, WitnessRef, WitnessSet, WitnessSetRef,
    };
    use auths_crypto::CurveType;
    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};

    fn party_sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn witness_sk(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[100u8.wrapping_add(i); 32])
    }

    fn ts(index: u64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + index as i64, 0).unwrap()
    }

    /// An Ed25519-signed anchor at `index` with a deterministic head.
    pub fn sample_anchor(index: u64) -> Anchor {
        sample_anchor_with_head(index, [index as u8; 32])
    }

    /// An Ed25519-signed anchor at `index` with an explicit head.
    pub fn sample_anchor_with_head(index: u64, head: [u8; 32]) -> Anchor {
        let sk = party_sk();
        let vk = sk.verifying_key();
        let mut anchor = Anchor {
            seed_id: SeedId::derive("did:keri:root", "did:keri:agent", "ESeal"),
            index,
            head: Head::from_bytes(head),
            cumulative: index as u128 * 100,
            timestamp: ts(index),
            witness_set: WitnessSetRef {
                said: "EWitSet".into(),
                threshold: 2,
            },
            sig_party: PartySignature {
                curve: CurveType::Ed25519,
                public_key: vk.as_bytes().to_vec(),
                signature: Vec::new(),
            },
        };
        let message = anchor.party_signing_bytes().unwrap();
        anchor.sig_party.signature = sk.sign(&message).to_bytes().to_vec();
        anchor
    }

    /// The controller-keys view that authorizes `anchor`'s party signature.
    pub fn controller_keys_for(anchor: &Anchor) -> ControllerKeys {
        ControllerKeys {
            current: vec![CurrentKey {
                curve: anchor.sig_party.curve,
                public_key: anchor.sig_party.public_key.clone(),
            }],
        }
    }

    /// The raw Ed25519 seed the sample / `finalized_*` anchors are party-signed
    /// with. Hand it to a document signer so the embedded-anchor party-key check
    /// (party key ∈ the agent's current keys) passes.
    pub fn party_seed_bytes() -> [u8; 32] {
        [9u8; 32]
    }

    /// The Ed25519 verifying-key bytes of [`party_seed_bytes`] — the party key
    /// every sample anchor is signed under.
    pub fn party_verifying_key_bytes() -> [u8; 32] {
        party_sk().verifying_key().to_bytes()
    }

    /// A finalized anchor over `n` witnesses at `threshold` whose tuple restates
    /// a CALLER-chosen `(seed_id, index, head, cumulative)`. Everything the
    /// embedded-anchor check restates against a document is caller-controlled, so
    /// an `activity/v1` verifier test can build a document this anchor
    /// legitimately restates. Party-signed by [`party_seed_bytes`].
    ///
    /// The declared set is genuinely self-addressing (its SAID is computed from
    /// content and committed into the party-signed anchor), and every cosigner
    /// carries a member-signed checkpoint rooting its inclusion proof — the same
    /// material a real node must produce.
    pub fn finalized_matching(
        seed_id: SeedId,
        index: u64,
        head: [u8; 32],
        cumulative: u128,
        n: u8,
        threshold: u32,
    ) -> FinalizedAnchor {
        let members: Vec<WitnessRef> = (0..n)
            .map(|i| WitnessRef {
                name: format!("witness-{i}"),
                curve: auths_crypto::CurveType::Ed25519,
                public_key: witness_sk(i).verifying_key().as_bytes().to_vec(),
                operator: Some(OperatorInfo {
                    operator: format!("op-{i}"),
                    organization: format!("org-{i}"),
                    jurisdiction: "US".into(),
                    infrastructure: format!("aws/zone-{i}"),
                }),
            })
            .collect();
        let mut witness_set = WitnessSet {
            said: String::new(),
            threshold,
            members,
        };
        witness_set.said = witness_set.computed_said().unwrap();

        let sk = party_sk();
        let mut anchor = Anchor {
            seed_id,
            index,
            head: Head::from_bytes(head),
            cumulative,
            timestamp: ts(index),
            witness_set: WitnessSetRef {
                said: witness_set.said.clone(),
                threshold,
            },
            sig_party: PartySignature {
                curve: CurveType::Ed25519,
                public_key: sk.verifying_key().as_bytes().to_vec(),
                signature: Vec::new(),
            },
        };
        let message = anchor.party_signing_bytes().unwrap();
        anchor.sig_party.signature = sk.sign(&message).to_bytes().to_vec();

        let cosign_message = anchor.cosign_bytes().unwrap();
        let leaf = auths_transparency::hash_leaf(&cosign_message);
        let mut cosignatures = Vec::new();
        let mut inclusion = Vec::new();
        for i in 0..n {
            let wsk = witness_sk(i);
            let sig = wsk.sign(&cosign_message);
            cosignatures.push(auths_transparency::WitnessCosignature {
                witness_name: format!("witness-{i}"),
                witness_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                    wsk.verifying_key().to_bytes(),
                ),
                signature: auths_verifier::Ed25519Signature::from_bytes(sig.to_bytes()),
                timestamp: ts(1),
            });
            inclusion.push(logged_inclusion_for(&format!("witness-{i}"), &wsk, leaf));
        }

        FinalizedAnchor {
            anchor,
            witness_set,
            cosignatures,
            inclusion,
        }
    }

    /// A finalized anchor over `n` witnesses with the given `threshold`, on the
    /// default sample spend chain (`sample_anchor(1)`'s tuple).
    pub fn finalized_sample(n: u8, threshold: u32) -> FinalizedAnchor {
        finalized_matching(
            SeedId::derive("did:keri:root", "did:keri:agent", "ESeal"),
            1,
            [1u8; 32],
            100,
            n,
            threshold,
        )
    }

    /// A member-signed checkpoint over a one-leaf log containing `leaf`, with
    /// the inclusion proof rooted in it.
    pub fn logged_inclusion_for(
        name: &str,
        witness_key: &SigningKey,
        leaf: auths_transparency::MerkleHash,
    ) -> crate::types::LoggedInclusion {
        let hashes = auths_transparency::prove_inclusion(&[leaf], 0).unwrap();
        let root = auths_transparency::compute_root(&[leaf]);
        let checkpoint = auths_transparency::Checkpoint {
            origin: auths_transparency::LogOrigin::new(&format!("awn/{name}")).unwrap(),
            size: 1,
            root,
            timestamp: ts(1),
        };
        let log_signature = witness_key.sign(checkpoint.to_note_body().as_bytes());
        crate::types::LoggedInclusion {
            witness_name: name.to_string(),
            checkpoint: auths_transparency::SignedCheckpoint {
                checkpoint,
                log_signature: auths_verifier::Ed25519Signature::from_bytes(
                    log_signature.to_bytes(),
                ),
                log_public_key: auths_verifier::Ed25519PublicKey::from_bytes(
                    witness_key.verifying_key().to_bytes(),
                ),
                witnesses: vec![],
                ecdsa_checkpoint_signature: None,
                ecdsa_checkpoint_key: None,
            },
            proof: auths_transparency::InclusionProof {
                index: 0,
                size: 1,
                root,
                hashes,
            },
        }
    }

    /// Keep only the first `k` cosignatures (to fall below a threshold).
    pub fn with_cosigners(mut finalized: FinalizedAnchor, k: usize) -> FinalizedAnchor {
        finalized.cosignatures.truncate(k);
        finalized
    }
}
