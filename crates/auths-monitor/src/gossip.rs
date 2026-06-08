//! Operator-to-operator checkpoint gossip.
//!
//! Gossip cross-distributes signed checkpoints between pinned operators so that
//! equivocation becomes **non-repudiable** to any operator who saw both views —
//! not merely sampled. A gossiped checkpoint is authenticated by the gossiper's
//! pinned cosignature; an unpinned peer is rejected. Accepted checkpoints
//! accumulate in **append-only** state (a rolled-back "last seen size" would
//! defeat the non-monotonicity proofs, so a regression is refused). When two
//! validly-cosigned checkpoints share a size but differ in root, the
//! [`EquivocationEvidence`](super::evidence::EquivocationEvidence) artifact is
//! emitted — never auto-resolved.
//!
//! Scope is operator-to-operator. Client-echo / partition-resistant gossip is a
//! documented limitation tracked in W.0.

// CT cosignatures are Ed25519-only per C2SP; `ring` is the verification primitive
// (as in `auths-transparency::verify`), not curve drift.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;

use auths_transparency::{EquivocationDetection, SignedCheckpoint};
use auths_verifier::Ed25519PublicKey;

use super::evidence::{
    EquivocationEvidence, OperatorCheckpoint, checkpoint_cosigned_by,
    detect_cross_operator_equivocation, keys_equal,
};

/// A gossiped, operator-authenticated checkpoint observation.
pub struct GossipMessage {
    /// The pinned operator that gossiped this; its cosignature on `signed`
    /// authenticates the message.
    pub gossiper_key: Ed25519PublicKey,
    /// The signed checkpoint the gossiper observed.
    pub signed: SignedCheckpoint,
}

/// Why a gossip message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipReject {
    /// The gossiper is not a pinned operator.
    UnpinnedGossiper,
    /// The gossiper has no valid cosignature on the checkpoint it gossiped.
    Unauthenticated,
    /// The gossiper's view rolled back — a smaller tree size than already seen.
    Rollback {
        /// The largest size previously accepted from this operator.
        last_size: u64,
        /// The smaller size the rollback attempted.
        new_size: u64,
    },
    /// The gossiper rewrote the root it previously cosigned at a size it had
    /// already gossiped (self-equivocation / state rewrite).
    StateRewrite {
        /// The size whose root was rewritten.
        size: u64,
    },
}

#[derive(Default)]
struct OperatorView {
    max_size: u64,
    roots: BTreeMap<u64, [u8; 32]>,
}

/// Append-only gossip state across pinned operators.
#[derive(Default)]
pub struct GossipState {
    views: BTreeMap<Vec<u8>, OperatorView>,
    observations: Vec<OperatorCheckpoint>,
}

impl GossipState {
    /// A fresh, empty gossip state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a gossiped checkpoint.
    ///
    /// Authenticates the gossiper (pinned + cosigned), enforces append-only
    /// monotonicity, records the observation, and returns any cross-operator
    /// equivocation evidence the new observation reveals.
    ///
    /// Args:
    /// * `msg`: The gossip message.
    /// * `pinned_operators`: The operator verkeys this node trusts.
    ///
    /// Returns `Ok(Some(evidence))` when ingestion exposes a same-size/
    /// different-root conflict (NOT auto-resolved), `Ok(None)` otherwise, or a
    /// [`GossipReject`].
    ///
    /// Usage:
    /// ```ignore
    /// match state.ingest(msg, &pinned)? { Some(ev) => emit(ev), None => {} }
    /// ```
    pub fn ingest(
        &mut self,
        msg: GossipMessage,
        pinned_operators: &[Ed25519PublicKey],
    ) -> Result<Option<EquivocationEvidence>, GossipReject> {
        // 1. Only pinned operators may gossip.
        if !pinned_operators
            .iter()
            .any(|k| keys_equal(k, &msg.gossiper_key))
        {
            return Err(GossipReject::UnpinnedGossiper);
        }
        // 2. The gossiper must have actually cosigned the checkpoint.
        if !checkpoint_cosigned_by(&msg.signed, &msg.gossiper_key) {
            return Err(GossipReject::Unauthenticated);
        }

        let size = msg.signed.checkpoint.size;
        let root = *msg.signed.checkpoint.root.as_bytes();
        let view = self
            .views
            .entry(msg.gossiper_key.as_bytes().to_vec())
            .or_default();

        // 3. Append-only: never accept a regressed size or a rewritten root.
        if size < view.max_size {
            return Err(GossipReject::Rollback {
                last_size: view.max_size,
                new_size: size,
            });
        }
        if let Some(prev) = view.roots.get(&size)
            && *prev != root
        {
            return Err(GossipReject::StateRewrite { size });
        }

        view.max_size = view.max_size.max(size);
        view.roots.insert(size, root);

        // 4. Record and scan for cross-operator equivocation (do not auto-resolve).
        self.observations.push(OperatorCheckpoint {
            operator_key: msg.gossiper_key,
            signed: msg.signed,
        });
        Ok(detect_cross_operator_equivocation(&self.observations))
    }

    /// Number of accepted observations (for liveness/telemetry).
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

/// The equivocation-detection strength a surface may honestly claim.
///
/// Only when gossip is **active** (operators cross-distributing and this node
/// cross-verifying) may a surface claim `NonRepudiable`; otherwise detection is
/// the W.3.1 `Sampled` tripwire. This gate is what lets the W.2.3 honesty ceiling
/// upgrade past "sampled".
///
/// Args:
/// * `gossip_active`: Whether the gossip layer is live for this node.
///
/// Usage:
/// ```ignore
/// let strength = gossip_detection_strength(gossip_is_live);
/// ```
pub fn gossip_detection_strength(gossip_active: bool) -> EquivocationDetection {
    if gossip_active {
        EquivocationDetection::NonRepudiable
    } else {
        EquivocationDetection::Sampled
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_transparency::types::{LogOrigin, MerkleHash};
    use auths_transparency::{Checkpoint, WitnessCosignature};
    use auths_verifier::Ed25519Signature;
    use chrono::{DateTime, Utc};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn cosigned(
        size: u64,
        root: [u8; 32],
        kp: &Ed25519KeyPair,
    ) -> (SignedCheckpoint, Ed25519PublicKey) {
        let cp = Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size,
            root: MerkleHash::from_bytes(root),
            timestamp: ts(1_700_000_000),
        };
        let sig = kp.sign(cp.to_note_body().as_bytes());
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig.as_ref());
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(kp.public_key().as_ref());
        let pubkey = Ed25519PublicKey::from_bytes(pk_arr);
        let signed = SignedCheckpoint {
            checkpoint: cp,
            log_signature: Ed25519Signature::from_bytes(sig_arr),
            log_public_key: pubkey,
            witnesses: vec![WitnessCosignature {
                witness_name: "op".into(),
                witness_public_key: pubkey,
                signature: Ed25519Signature::from_bytes(sig_arr),
                timestamp: ts(1_700_000_000),
            }],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        };
        (signed, pubkey)
    }

    #[test]
    fn unpinned_gossiper_is_rejected() {
        let kp = keypair();
        let (signed, key) = cosigned(10, [1u8; 32], &kp);
        let mut state = GossipState::new();
        // `key` is NOT in the pinned set.
        let result = state.ingest(
            GossipMessage {
                gossiper_key: key,
                signed,
            },
            &[],
        );
        assert!(matches!(result, Err(GossipReject::UnpinnedGossiper)));
    }

    #[test]
    fn pinned_gossiper_is_accepted() {
        let kp = keypair();
        let (signed, key) = cosigned(10, [1u8; 32], &kp);
        let mut state = GossipState::new();
        let result = state.ingest(
            GossipMessage {
                gossiper_key: key,
                signed,
            },
            &[key],
        );
        assert!(matches!(result, Ok(None)));
        assert_eq!(state.observation_count(), 1);
    }

    #[test]
    fn conflicting_gossip_emits_non_repudiable_evidence() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xBB; 32], &kp_b);
        let mut state = GossipState::new();
        let pinned = [key_a, key_b];

        assert!(matches!(
            state.ingest(
                GossipMessage {
                    gossiper_key: key_a,
                    signed: sc_a
                },
                &pinned
            ),
            Ok(None)
        ));
        let evidence = state
            .ingest(
                GossipMessage {
                    gossiper_key: key_b,
                    signed: sc_b,
                },
                &pinned,
            )
            .unwrap()
            .expect("conflict yields evidence, not auto-resolution");
        // The emitted artifact is independently verifiable (W.3.2).
        assert!(super::super::evidence::verify_equivocation_evidence(
            &evidence, &pinned
        ));
    }

    #[test]
    fn size_rollback_is_refused() {
        let kp = keypair();
        let (big, key) = cosigned(100, [1u8; 32], &kp);
        let (small, _) = cosigned(50, [2u8; 32], &kp);
        let mut state = GossipState::new();
        let pinned = [key];

        state
            .ingest(
                GossipMessage {
                    gossiper_key: key,
                    signed: big,
                },
                &pinned,
            )
            .unwrap();
        let rolled_back = state.ingest(
            GossipMessage {
                gossiper_key: key,
                signed: small,
            },
            &pinned,
        );
        assert!(matches!(
            rolled_back,
            Err(GossipReject::Rollback {
                last_size: 100,
                new_size: 50
            })
        ));
    }

    #[test]
    fn state_rewrite_at_seen_size_is_refused() {
        let kp = keypair();
        let (first, key) = cosigned(100, [1u8; 32], &kp);
        let (rewrite, _) = cosigned(100, [9u8; 32], &kp);
        let mut state = GossipState::new();
        let pinned = [key];

        state
            .ingest(
                GossipMessage {
                    gossiper_key: key,
                    signed: first,
                },
                &pinned,
            )
            .unwrap();
        let result = state.ingest(
            GossipMessage {
                gossiper_key: key,
                signed: rewrite,
            },
            &pinned,
        );
        assert!(matches!(
            result,
            Err(GossipReject::StateRewrite { size: 100 })
        ));
    }

    #[test]
    fn detection_strength_flips_only_when_gossip_active() {
        assert_eq!(
            gossip_detection_strength(false),
            EquivocationDetection::Sampled
        );
        assert_eq!(
            gossip_detection_strength(true),
            EquivocationDetection::NonRepudiable
        );
    }
}
