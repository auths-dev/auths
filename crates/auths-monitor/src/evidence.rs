//! Cross-operator checkpoint divergence + portable, third-party-verifiable
//! equivocation evidence.
//!
//! Two pinned operators presenting checkpoints of the SAME tree size but
//! DIFFERENT roots is equivocation no single witness sees alone. The evidence
//! artifact carries both operators' signed checkpoints; the verdict stands on
//! THOSE cosignatures alone. [`verify_equivocation_evidence`] trusts only the
//! pinned operator keys, never the monitor — so a second monitor or an auditor
//! who never saw (and does not trust) this monitor reaches the same verdict, and
//! the monitor's provenance note cannot change it. That is what makes the monitor
//! non-authoritative and independently runnable.
//!
//! All comparison is **positional** (by tree size), never by wall-clock timestamp.

// CT cosignatures are Ed25519-only per the C2SP tlog-witness spec; `ring` is the
// verification primitive here (as in `auths-transparency::verify`), not curve drift.
#![allow(clippy::disallowed_methods)]

use auths_transparency::{Checkpoint, SignedCheckpoint};
use auths_verifier::Ed25519PublicKey;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Constant-time equality of two verkeys (keys are public, but the workspace
/// bans `==` on `.as_bytes()`; use the same `ct_eq` path as the verifier).
pub(crate) fn keys_equal(a: &Ed25519PublicKey, b: &Ed25519PublicKey) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Schema version of the evidence artifact (forward-compatible parsing).
pub const EVIDENCE_VERSION: u32 = 1;

/// The positional relationship between two checkpoints of one log view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointTransition {
    /// The new checkpoint may extend the old (size grew or held with same root);
    /// a consistency proof still gates acceptance.
    Continue,
    /// Tree size regressed (`new < old`) — never legitimate for an append-only log.
    SizeRegression {
        /// The previous (larger) size.
        old_size: u64,
        /// The regressed (smaller) size.
        new_size: u64,
    },
    /// Same size, different root — equivocation within a single operator's view.
    Equivocation {
        /// The size at which the roots diverged.
        size: u64,
    },
}

/// Classify a checkpoint transition POSITIONALLY — by tree size and root, never
/// by wall-clock timestamp (a malicious operator controls its own clock).
///
/// Args:
/// * `old`: The last-seen checkpoint.
/// * `new`: The newly-observed checkpoint.
///
/// Usage:
/// ```ignore
/// match checkpoint_transition(&last, &latest) {
///     CheckpointTransition::SizeRegression { .. } => reject(),
///     CheckpointTransition::Equivocation { .. } => alert(),
///     CheckpointTransition::Continue => verify_consistency_proof(),
/// }
/// ```
pub fn checkpoint_transition(old: &Checkpoint, new: &Checkpoint) -> CheckpointTransition {
    if new.size < old.size {
        return CheckpointTransition::SizeRegression {
            old_size: old.size,
            new_size: new.size,
        };
    }
    if new.size == old.size && new.root != old.root {
        return CheckpointTransition::Equivocation { size: new.size };
    }
    CheckpointTransition::Continue
}

/// Non-repudiable cross-operator equivocation evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// Artifact schema version.
    pub version: u32,
    /// The tree size at which the operators diverged.
    pub size: u64,
    /// One operator's signed checkpoint at `size`.
    pub checkpoint_a: SignedCheckpoint,
    /// The other operator's signed checkpoint at `size` (different root).
    pub checkpoint_b: SignedCheckpoint,
    /// Pinned key of the operator that cosigned `checkpoint_a`.
    pub operator_a_key: Ed25519PublicKey,
    /// Pinned key of the operator that cosigned `checkpoint_b`.
    pub operator_b_key: Ed25519PublicKey,
    /// Optional monitor provenance note — NOT authority. Ignored by verification.
    #[serde(default)]
    pub monitor_note: Option<String>,
}

/// Whether `key` has a verifying cosignature over `signed`'s note body.
///
/// The basis for both equivocation verification and gossip authentication: a
/// checkpoint genuinely from an operator carries that operator's cosignature.
///
/// Args:
/// * `signed`: The signed checkpoint.
/// * `key`: The operator verkey to check for a cosignature.
///
/// Usage:
/// ```ignore
/// if !checkpoint_cosigned_by(&signed, &gossiper_key) { reject(); }
/// ```
pub fn checkpoint_cosigned_by(signed: &SignedCheckpoint, key: &Ed25519PublicKey) -> bool {
    cosigned_by(signed, key)
}

/// Whether `key` has a verifying cosignature over `signed`'s note body.
fn cosigned_by(signed: &SignedCheckpoint, key: &Ed25519PublicKey) -> bool {
    let note_body = signed.checkpoint.to_note_body();
    signed.witnesses.iter().any(|cosig| {
        keys_equal(&cosig.witness_public_key, key)
            && UnparsedPublicKey::new(&ED25519, key.as_bytes())
                .verify(note_body.as_bytes(), cosig.signature.as_bytes())
                .is_ok()
    })
}

/// Verify equivocation evidence using ONLY the pinned operator keys — zero trust
/// in the monitor.
///
/// Returns `true` only when two **distinct, pinned** operators each cosigned a
/// checkpoint of the same tree size with **different** roots. The monitor's note
/// is never consulted, so substituting or tampering it cannot change the verdict.
///
/// Args:
/// * `evidence`: The artifact to check.
/// * `pinned_operators`: The operator verkeys the verifier already trusts.
///
/// Usage:
/// ```ignore
/// assert!(verify_equivocation_evidence(&artifact, &[op_a_key, op_b_key]));
/// ```
pub fn verify_equivocation_evidence(
    evidence: &EquivocationEvidence,
    pinned_operators: &[Ed25519PublicKey],
) -> bool {
    let pinned = |k: &Ed25519PublicKey| pinned_operators.iter().any(|p| keys_equal(p, k));

    if !pinned(&evidence.operator_a_key) || !pinned(&evidence.operator_b_key) {
        return false;
    }
    if keys_equal(&evidence.operator_a_key, &evidence.operator_b_key) {
        return false;
    }

    // Positional: same claimed size on both, different root — the equivocation.
    if evidence.checkpoint_a.checkpoint.size != evidence.size
        || evidence.checkpoint_b.checkpoint.size != evidence.size
    {
        return false;
    }
    if evidence.checkpoint_a.checkpoint.root == evidence.checkpoint_b.checkpoint.root {
        return false;
    }

    // Each operator actually cosigned its conflicting checkpoint.
    cosigned_by(&evidence.checkpoint_a, &evidence.operator_a_key)
        && cosigned_by(&evidence.checkpoint_b, &evidence.operator_b_key)
}

/// An operator's observed checkpoint in a cross-read round.
pub struct OperatorCheckpoint {
    /// The operator's pinned cosigning key.
    pub operator_key: Ed25519PublicKey,
    /// The checkpoint that operator cosigned.
    pub signed: SignedCheckpoint,
}

/// Scan operators' observed checkpoints for two at the same size with different
/// roots — cross-operator equivocation. Positional (by tree size), never by clock.
///
/// Args:
/// * `observations`: Each operator's observed, cosigned checkpoint.
///
/// Usage:
/// ```ignore
/// if let Some(ev) = detect_cross_operator_equivocation(&observations) { emit(ev); }
/// ```
pub fn detect_cross_operator_equivocation(
    observations: &[OperatorCheckpoint],
) -> Option<EquivocationEvidence> {
    for (i, a) in observations.iter().enumerate() {
        for b in observations.iter().skip(i + 1) {
            if a.signed.checkpoint.size == b.signed.checkpoint.size
                && a.signed.checkpoint.root != b.signed.checkpoint.root
            {
                return Some(EquivocationEvidence {
                    version: EVIDENCE_VERSION,
                    size: a.signed.checkpoint.size,
                    checkpoint_a: a.signed.clone(),
                    checkpoint_b: b.signed.clone(),
                    operator_a_key: a.operator_key,
                    operator_b_key: b.operator_key,
                    monitor_note: None,
                });
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_transparency::types::{LogOrigin, MerkleHash};
    use auths_verifier::Ed25519Signature;
    use chrono::{DateTime, Utc};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn checkpoint(size: u64, root: [u8; 32], timestamp: DateTime<Utc>) -> Checkpoint {
        Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size,
            root: MerkleHash::from_bytes(root),
            timestamp,
        }
    }

    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    /// A checkpoint cosigned at `size`/`root` by `kp`; returns it + the pubkey.
    fn cosigned(
        size: u64,
        root: [u8; 32],
        kp: &Ed25519KeyPair,
    ) -> (SignedCheckpoint, Ed25519PublicKey) {
        let cp = checkpoint(size, root, ts(1_700_000_000));
        let note_body = cp.to_note_body();
        let sig = kp.sign(note_body.as_bytes());
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig.as_ref());
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(kp.public_key().as_ref());
        let pubkey = Ed25519PublicKey::from_bytes(pk_arr);

        let signed = SignedCheckpoint {
            checkpoint: cp,
            log_signature: Ed25519Signature::from_bytes(sig_arr),
            log_public_key: pubkey,
            witnesses: vec![auths_transparency::WitnessCosignature {
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
    fn transition_continue_when_size_grows() {
        let old = checkpoint(100, [1u8; 32], ts(2));
        // Newer tree, OLDER timestamp — positional logic ignores the clock.
        let new = checkpoint(150, [2u8; 32], ts(1));
        assert_eq!(
            checkpoint_transition(&old, &new),
            CheckpointTransition::Continue
        );
    }

    #[test]
    fn transition_size_regression_even_with_newer_clock() {
        let old = checkpoint(100, [1u8; 32], ts(1));
        // Smaller tree but NEWER timestamp — still a regression (positional).
        let new = checkpoint(50, [2u8; 32], ts(999));
        assert_eq!(
            checkpoint_transition(&old, &new),
            CheckpointTransition::SizeRegression {
                old_size: 100,
                new_size: 50
            }
        );
    }

    #[test]
    fn transition_equivocation_same_size_different_root() {
        let old = checkpoint(100, [1u8; 32], ts(1));
        let new = checkpoint(100, [2u8; 32], ts(2));
        assert_eq!(
            checkpoint_transition(&old, &new),
            CheckpointTransition::Equivocation { size: 100 }
        );
    }

    #[test]
    fn cross_operator_same_size_different_root_emits_evidence() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xBB; 32], &kp_b);

        let observations = vec![
            OperatorCheckpoint {
                operator_key: key_a,
                signed: sc_a,
            },
            OperatorCheckpoint {
                operator_key: key_b,
                signed: sc_b,
            },
        ];
        let evidence = detect_cross_operator_equivocation(&observations).expect("evidence");
        assert_eq!(evidence.size, 100);
        // Third-party verifiable with only the pinned operator keys.
        assert!(verify_equivocation_evidence(&evidence, &[key_a, key_b]));
    }

    #[test]
    fn same_root_is_not_equivocation() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xAA; 32], &kp_b);
        let observations = vec![
            OperatorCheckpoint {
                operator_key: key_a,
                signed: sc_a,
            },
            OperatorCheckpoint {
                operator_key: key_b,
                signed: sc_b,
            },
        ];
        assert!(detect_cross_operator_equivocation(&observations).is_none());
    }

    #[test]
    fn monitor_note_tampering_does_not_change_verdict() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xBB; 32], &kp_b);
        let mut evidence = detect_cross_operator_equivocation(&[
            OperatorCheckpoint {
                operator_key: key_a,
                signed: sc_a,
            },
            OperatorCheckpoint {
                operator_key: key_b,
                signed: sc_b,
            },
        ])
        .unwrap();
        // The verdict stands on the operators' cosignatures, not the monitor's note.
        evidence.monitor_note = Some("a lying monitor said it's fine".into());
        assert!(verify_equivocation_evidence(&evidence, &[key_a, key_b]));
    }

    #[test]
    fn tampered_root_breaks_the_cosignature() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xBB; 32], &kp_b);
        let mut evidence = detect_cross_operator_equivocation(&[
            OperatorCheckpoint {
                operator_key: key_a,
                signed: sc_a,
            },
            OperatorCheckpoint {
                operator_key: key_b,
                signed: sc_b,
            },
        ])
        .unwrap();
        // Rewriting a checkpoint root invalidates the cosignature over its note body.
        evidence.checkpoint_a.checkpoint.root = MerkleHash::from_bytes([0xCC; 32]);
        assert!(!verify_equivocation_evidence(&evidence, &[key_a, key_b]));
    }

    #[test]
    fn unpinned_operator_does_not_verify() {
        let kp_a = keypair();
        let kp_b = keypair();
        let (sc_a, key_a) = cosigned(100, [0xAA; 32], &kp_a);
        let (sc_b, key_b) = cosigned(100, [0xBB; 32], &kp_b);
        let evidence = detect_cross_operator_equivocation(&[
            OperatorCheckpoint {
                operator_key: key_a,
                signed: sc_a,
            },
            OperatorCheckpoint {
                operator_key: key_b,
                signed: sc_b,
            },
        ])
        .unwrap();
        // Only operator A is pinned → the evidence does not verify.
        assert!(!verify_equivocation_evidence(&evidence, &[key_a]));
    }
}
