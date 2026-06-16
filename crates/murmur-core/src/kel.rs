//! The witnessed key-log replay — the correctness root the whole continuity story
//! rests on (PRD §2 binding mechanism, §3.1 launch-centralization asterisk).
//!
//! The verified-continuation badge (PRD §2) means something *only* because the
//! key-state it replays is the **one true witnessed log**. Two things can corrupt
//! that log under the app's feet, both via the relay the launch path centralizes
//! on (PRD §3.1) — and a replay that does not catch them turns the badge into a
//! lie:
//!
//!  1. **A forked KEL.** A malicious or buggy relay serves *two different rotation
//!     events at the same sequence number* (two contradictory "next keys" at the
//!     same point in history). Last-writer-wins here is the dangerous bug: it lets
//!     a relay pick which key-state the app continues onto, faking or suppressing a
//!     rotation. The replay must **reject the fork outright** — refuse to derive a
//!     current key-state from a log that contradicts itself — never silently take
//!     the later (or the attacker's) branch.
//!  2. **A relay-suppressed / stale key-state.** The relay serves a key-state that
//!     *no witness threshold corroborates* — it withheld the receipts, or served a
//!     snapshot that predates the witnessed truth. A key-state under the AID's
//!     **witness receipt threshold** is not the witnessed current state; accepting
//!     it as current lets the relay suppress a rotation by simply not showing the
//!     receipts. The replay must **fail the witness-threshold check** rather than
//!     accept an uncorroborated state.
//!
//! ## What this models vs. the full KERI replay
//!
//! The full engine drives this over auths-keri's `replay_with_receipts` →
//! `KeyState`, which replays a witnessed KEL (the `r`/`n` fields of each event, the
//! witness receipts) and derives the current key-state. Here the same two
//! **correctness properties** are modelled directly: a [`Kel`] is an ordered run of
//! signed [`KelEvent`]s each carrying its sequence number, the prior key it is
//! signed by, the new current key, and the next-key pre-rotation commitment; each
//! event carries the [`WitnessReceipt`]s a witness pool returned for it. Replaying
//! the log [`Kel::replay`] derives a [`crate::rotation::KeyState`] **only** when the
//! log is fork-free and the tip event clears the witness threshold — otherwise it
//! fails closed, the same fail-closed the full replay would. So the seam is a real
//! correctness check the app runs over the served log, never a stub that trusts the
//! relay's say-so.
//!
//! The pre-rotation continuity check itself ([`crate::rotation::verify_continuation`])
//! is unchanged and still load-bearing — this module guarantees the *log it runs
//! over* is the one true witnessed log, which is the precondition that check assumes
//! but cannot enforce by itself.

use serde::{Deserialize, Serialize};

use crate::address::Aid;
use crate::identity::{Identity, verify_sender};
use crate::rotation::{KeyState, compute_next_commitment};
use crate::{CoreError, CoreResult};

/// Domain-separating context a KEL event is signed under, so a signature over a
/// key-log event can never be replayed as a signature for another purpose.
const KEL_EVENT_CONTEXT: &[u8] = b"murmur/kel/event/v1\n";

/// Domain-separating context a witness receipt is signed under — a witness
/// signature over *this event's* identity is what corroborates it.
const WITNESS_RECEIPT_CONTEXT: &[u8] = b"murmur/kel/witness-receipt/v1\n";

/// The canonical bytes a KEL event is signed over: the AID it is for, its sequence
/// number, the prior key it rotates *from* (empty at inception), the current key it
/// installs, and the pre-rotation commitment to the next key. Binding all of these
/// means a relay cannot move an event to a different sequence, swap its key, or
/// detach its commitment without invalidating the controller signature.
fn event_signing_bytes(
    aid: &Aid,
    sequence: u64,
    prior_key: &[u8],
    current_key: &[u8],
    next_commitment: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(KEL_EVENT_CONTEXT);
    bytes.extend_from_slice(aid.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(prior_key);
    bytes.push(b'\n');
    bytes.extend_from_slice(current_key);
    bytes.push(b'\n');
    bytes.extend_from_slice(next_commitment);
    bytes
}

/// The bytes a witness receipts: the AID, the sequence number, and the current key
/// the event installed. A receipt corroborates *which* key-state a witness saw at a
/// given point in the log, so a relay cannot lift a receipt onto a different event.
fn receipt_signing_bytes(aid: &Aid, sequence: u64, current_key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WITNESS_RECEIPT_CONTEXT);
    bytes.extend_from_slice(aid.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(current_key);
    bytes
}

/// A witness's signed receipt for one KEL event — the corroboration a relay cannot
/// fabricate and the launch-centralization asterisk (PRD §3.1) leans on. A
/// key-state is *witnessed* only when a **threshold** of distinct witnesses have
/// receipted the event that installed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// The witness that signed this receipt (its AID).
    pub witness: Aid,
    /// The witness's public key, so the receipt's signature can be checked.
    pub witness_key: Vec<u8>,
    /// The witness's signature over `(aid ‖ sequence ‖ current_key)`.
    pub signature: Vec<u8>,
}

impl WitnessReceipt {
    /// Issue a receipt: `witness` signs that it saw `current_key` installed at
    /// `sequence` for `aid`. Returned so a hermetic replay can assemble a witnessed
    /// log; in the full engine the witness pool returns these over the wire.
    pub fn issue(
        witness: &Identity,
        aid: &Aid,
        sequence: u64,
        current_key: &[u8],
    ) -> CoreResult<Self> {
        let signing_bytes = receipt_signing_bytes(aid, sequence, current_key);
        let signature = witness.sign(&signing_bytes)?;
        Ok(WitnessReceipt {
            witness: witness.aid().clone(),
            witness_key: witness.public_key().to_vec(),
            signature,
        })
    }

    /// Verify this receipt against the event it claims to corroborate. The witness's
    /// key must derive its AID (a relay cannot present a key for a different witness)
    /// and the signature must verify over the event's `(aid ‖ sequence ‖ current_key)`.
    fn verify(&self, aid: &Aid, sequence: u64, current_key: &[u8]) -> CoreResult<()> {
        let signing_bytes = receipt_signing_bytes(aid, sequence, current_key);
        verify_sender(
            &self.witness,
            &self.witness_key,
            &signing_bytes,
            &self.signature,
        )
        .map_err(|_| CoreError::Rejected("a witness receipt did not verify under its witness AID"))
    }
}

/// One signed event in a witnessed key-event-log: the inception (sequence 0) or a
/// rotation (sequence ≥ 1). Each event installs a `current_key` and pre-commits to
/// the next one, is signed by the **prior** key (the key that controlled the AID
/// before this event — the current key itself at inception), and carries the
/// witness receipts the witness pool returned for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KelEvent {
    /// The position of this event in the log: 0 is the inception, each rotation
    /// increments it by one. The fork the replay must reject is *two distinct events
    /// at the same `sequence`*.
    pub sequence: u64,
    /// The key the AID was controlled by *before* this event — and therefore the key
    /// that must have signed it. Empty at inception (the current key signs itself).
    pub prior_key: Vec<u8>,
    /// The key this event installs as the current controller.
    pub current_key: Vec<u8>,
    /// The pre-rotation commitment to the *next* key — the digest a later rotation is
    /// verified against ([`compute_next_commitment`]).
    pub next_commitment: [u8; 32],
    /// The controller signature over this event, by the `prior_key` (the current key
    /// at inception). Authenticates that the holder of the controlling key authored
    /// this transition.
    pub signature: Vec<u8>,
    /// The witness receipts the pool returned for this event. A relay that suppresses
    /// a rotation serves an event whose receipts fall under the threshold.
    pub receipts: Vec<WitnessReceipt>,
}

impl KelEvent {
    /// Assemble and sign an inception event (sequence 0): `controller` installs its
    /// own key and pre-commits to `next_public_key`, signing with itself.
    pub fn incept(
        controller: &Identity,
        next_public_key: &[u8],
        receipts: Vec<WitnessReceipt>,
    ) -> CoreResult<Self> {
        let next_commitment = compute_next_commitment(next_public_key);
        let signing_bytes = event_signing_bytes(
            controller.aid(),
            0,
            &[], // inception is signed by the current key itself
            controller.public_key(),
            &next_commitment,
        );
        let signature = controller.sign(&signing_bytes)?;
        Ok(KelEvent {
            sequence: 0,
            prior_key: Vec::new(),
            current_key: controller.public_key().to_vec(),
            next_commitment,
            signature,
            receipts,
        })
    }

    /// Assemble and sign a rotation event at `sequence`: the `prior` key (which
    /// controlled the AID before) rotates to the `rotated` key — which must be the
    /// key the prior event pre-committed to — and pre-commits to `next_public_key`.
    /// The event is signed by the **prior** key, the key that was authorized to
    /// rotate. The AID is stable across the rotation, so the signing AID is the
    /// prior identity's AID (the inception SAID stand-in).
    pub fn rotate(
        aid: &Aid,
        prior: &Identity,
        rotated: &Identity,
        sequence: u64,
        next_public_key: &[u8],
        receipts: Vec<WitnessReceipt>,
    ) -> CoreResult<Self> {
        if sequence == 0 {
            return Err(CoreError::Malformed(
                "a rotation event cannot be at sequence 0 (that is the inception)".into(),
            ));
        }
        let next_commitment = compute_next_commitment(next_public_key);
        let signing_bytes = event_signing_bytes(
            aid,
            sequence,
            prior.public_key(),
            rotated.public_key(),
            &next_commitment,
        );
        // The PRIOR key signs the rotation — it is the key authorized to rotate.
        let signature = prior.sign(&signing_bytes)?;
        Ok(KelEvent {
            sequence,
            prior_key: prior.public_key().to_vec(),
            current_key: rotated.public_key().to_vec(),
            next_commitment,
            signature,
            receipts,
        })
    }

    /// How many *distinct* witnesses returned a verifying receipt for this event.
    /// Duplicate receipts from the same witness count once — a relay cannot inflate
    /// the corroboration count by repeating one witness's receipt.
    fn corroborating_witnesses(&self, aid: &Aid) -> usize {
        let mut seen: Vec<&Aid> = Vec::new();
        for receipt in &self.receipts {
            if receipt
                .verify(aid, self.sequence, &self.current_key)
                .is_ok()
                && !seen.contains(&&receipt.witness)
            {
                seen.push(&receipt.witness);
            }
        }
        seen.len()
    }
}

/// The witness policy an AID's key-state must clear to be accepted as *current*: at
/// least `threshold` distinct witnesses must have receipted the tip event. A
/// key-state under this threshold is not the witnessed current state — it is a
/// relay-suppressed or stale snapshot, and the replay refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPolicy {
    /// The minimum number of distinct corroborating witnesses for a key-state to be
    /// accepted as the witnessed current state.
    pub threshold: u8,
}

impl WitnessPolicy {
    /// A policy requiring `threshold` distinct corroborating witnesses.
    pub fn of(threshold: u8) -> Self {
        WitnessPolicy { threshold }
    }
}

/// A served key-event-log for one stable AID, exactly as a relay would hand it to
/// the app: the AID, the witness policy its key-state must clear, and the ordered
/// run of signed events with their receipts. Replaying it [`Kel::replay`] derives
/// the witnessed current [`KeyState`] **only** when the log is fork-free and the tip
/// clears the witness threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kel {
    /// The stable AID this log is for (the inception SAID stand-in). It is preserved
    /// across every rotation — a rotation changes the key, never the identity.
    pub aid: Aid,
    /// The witness threshold the tip key-state must clear to be accepted as current.
    pub policy: WitnessPolicy,
    /// The events of the log. A well-formed log is the inception at sequence 0
    /// followed by rotations at consecutive sequences, each fork-free.
    pub events: Vec<KelEvent>,
}

impl Kel {
    /// Build a log for `aid` under `policy` from `events`.
    pub fn new(aid: Aid, policy: WitnessPolicy, events: Vec<KelEvent>) -> Self {
        Kel {
            aid,
            policy,
            events,
        }
    }

    /// Replay the served log to the witnessed current [`KeyState`], or fail closed.
    ///
    /// This is the correctness root the continuity story turns on. The replay derives a current
    /// key-state **only** when every one of these holds, and otherwise refuses to
    /// produce a key-state at all (the fail-closed the badge depends on):
    ///
    ///  * the log is non-empty and begins with an inception at sequence 0;
    ///  * **no fork** — there are never two *distinct* events at the same sequence
    ///    number (two different rotations claiming the same point in history). A
    ///    forked log is [`CoreError::Rejected`] (`forked-kel`), never resolved by
    ///    taking the later or larger branch;
    ///  * each rotation's controller signature verifies under the **prior** key, that
    ///    prior key is the one the preceding event installed, and the rotated key was
    ///    **pre-committed** by the preceding event (its commitment matches) — a relay
    ///    cannot splice in an event the log did not authorize;
    ///  * the **tip** event clears the AID's **witness threshold** — at least
    ///    `policy.threshold` distinct witnesses receipted it. A key-state under the
    ///    threshold is a relay-suppressed / stale snapshot and is
    ///    [`CoreError::Rejected`] (`stale-keystate`), never accepted as current.
    ///
    /// On success the returned [`KeyState`] carries the stable AID, the witnessed
    /// current key, and the tip's next-key commitment — exactly the shape
    /// [`crate::rotation::verify_continuation`] consumes, but now provably over the
    /// one true witnessed log.
    pub fn replay(&self) -> CoreResult<KeyState> {
        // Reject a forked log up front: two distinct events at the same sequence.
        self.reject_forks()?;

        let mut iter = self.events.iter();
        let inception = iter.next().ok_or(CoreError::Rejected(
            "forked-kel: empty key-log has no inception",
        ))?;
        if inception.sequence != 0 {
            return Err(CoreError::Rejected(
                "forked-kel: the key-log does not begin with an inception at sequence 0",
            ));
        }
        // The inception is signed by its own current key.
        self.verify_event_signature(inception, &inception.current_key)?;

        // Walk the rotations: each must follow the previous sequence exactly, be
        // signed by the prior key the previous event installed, and reveal a key the
        // previous event pre-committed to.
        let mut prior = inception;
        for event in iter {
            if event.sequence != prior.sequence + 1 {
                return Err(CoreError::Rejected(
                    "forked-kel: a key-log event skipped or repeated a sequence number",
                ));
            }
            if event.prior_key != prior.current_key {
                return Err(CoreError::Rejected(
                    "forked-kel: a rotation was not signed by the key the prior event installed",
                ));
            }
            // The rotated key must have been pre-committed by the prior event.
            if compute_next_commitment(&event.current_key) != prior.next_commitment {
                return Err(CoreError::Rejected(
                    "stale-keystate: a rotation revealed a key the prior event never pre-committed to",
                ));
            }
            // The rotation is signed by the prior key (the one authorized to rotate).
            self.verify_event_signature(event, &event.prior_key)?;
            prior = event;
        }

        // The tip is the witnessed current state — only if it clears the threshold.
        let tip = prior;
        let corroborating = tip.corroborating_witnesses(&self.aid);
        if self.policy.threshold == 0 || corroborating < self.policy.threshold as usize {
            return Err(CoreError::Rejected(
                "stale-keystate: the served key-state is below the witness threshold — a \
                 relay-suppressed or stale snapshot, not the witnessed current state",
            ));
        }

        Ok(KeyState {
            aid: self.aid.clone(),
            current_key: tip.current_key.clone(),
            next_commitment: tip.next_commitment,
        })
    }

    /// How many distinct witnesses corroborate the tip key-state — exposed so a
    /// caller (the relay self-test) can report the corroboration the replay relied
    /// on without re-walking the log.
    pub fn tip_corroborating_witnesses(&self) -> CoreResult<usize> {
        let tip = self
            .events
            .last()
            .ok_or(CoreError::Rejected("forked-kel: empty key-log has no tip"))?;
        Ok(tip.corroborating_witnesses(&self.aid))
    }

    /// Reject a forked log: two *distinct* events claiming the same sequence number.
    /// Two byte-identical events at the same sequence are a harmless duplicate (a
    /// relay re-sending the same event); two *different* events are a fork — the
    /// relay (or an attacker) is trying to make the app continue onto a branch it
    /// chose. Forks fail closed; the replay never picks a branch.
    fn reject_forks(&self) -> CoreResult<()> {
        for (i, a) in self.events.iter().enumerate() {
            for b in &self.events[i + 1..] {
                if a.sequence == b.sequence && a != b {
                    return Err(CoreError::Rejected(
                        "forked-kel: two different events claim the same sequence number — the \
                         log contradicts itself and is refused, never resolved last-writer-wins",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify one event's controller signature under `signer_key`, the key the prior
    /// event installed (or the event's own current key at inception). The signer key
    /// must derive an AID — a relay cannot present a key for a different controller —
    /// and the signature must verify over the event's canonical bytes.
    fn verify_event_signature(&self, event: &KelEvent, signer_key: &[u8]) -> CoreResult<()> {
        let prior_key: &[u8] = if event.sequence == 0 {
            &[]
        } else {
            &event.prior_key
        };
        let signing_bytes = event_signing_bytes(
            &self.aid,
            event.sequence,
            prior_key,
            &event.current_key,
            &event.next_commitment,
        );
        let signer_aid = Aid::from_public_key(signer_key);
        verify_sender(&signer_aid, signer_key, &signing_bytes, &event.signature).map_err(|_| {
            CoreError::Rejected(
                "stale-keystate: a key-log event's controller signature did not verify",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Identity {
        Identity::from_seed([byte; 32]).unwrap()
    }

    /// A witness pool of `n` distinct witnesses, seeded high to avoid colliding with
    /// controller seeds in the tests.
    fn witnesses(n: u8) -> Vec<Identity> {
        (0..n).map(|i| id(0xA0u8.wrapping_add(i))).collect()
    }

    /// Receipts for `(aid, seq, key)` from the first `count` witnesses of `pool`.
    fn receipts_for(
        pool: &[Identity],
        count: usize,
        aid: &Aid,
        seq: u64,
        key: &[u8],
    ) -> Vec<WitnessReceipt> {
        pool.iter()
            .take(count)
            .map(|w| WitnessReceipt::issue(w, aid, seq, key).unwrap())
            .collect()
    }

    /// Build a simple two-event witnessed log (incept → rotate) for the stable AID of
    /// `gen0`, with `tip_receipts` distinct witnesses receipting the rotation.
    fn witnessed_log(
        gen0: &Identity,
        gen1: &Identity,
        gen2_key: &[u8],
        pool: &[Identity],
        tip_receipts: usize,
        threshold: u8,
    ) -> Kel {
        let aid = gen0.aid().clone();
        let icp_receipts = receipts_for(pool, pool.len(), &aid, 0, gen0.public_key());
        let inception = KelEvent::incept(gen0, gen1.public_key(), icp_receipts).unwrap();
        let rot_receipts = receipts_for(pool, tip_receipts, &aid, 1, gen1.public_key());
        let rotation = KelEvent::rotate(&aid, gen0, gen1, 1, gen2_key, rot_receipts).unwrap();
        Kel::new(aid, WitnessPolicy::of(threshold), vec![inception, rotation])
    }

    #[test]
    fn a_witnessed_fork_free_log_replays_to_the_tip_key_state() {
        let gen0 = id(1);
        let gen1 = id(2);
        let gen2 = id(3);
        let pool = witnesses(3);
        let kel = witnessed_log(&gen0, &gen1, gen2.public_key(), &pool, 3, 2);
        let state = kel.replay().unwrap();
        assert_eq!(state.aid, *gen0.aid());
        // The witnessed current key is the rotated (gen1) key.
        assert_eq!(state.current_key, gen1.public_key());
        // …and it pre-commits to gen2 (the tip's next commitment).
        assert_eq!(
            state.next_commitment,
            compute_next_commitment(gen2.public_key())
        );
    }

    #[test]
    fn a_forked_kel_two_rotations_at_the_same_sequence_is_rejected() {
        let gen0 = id(1);
        let gen1 = id(2); // the legitimately pre-committed key
        let gen2 = id(3);
        let pool = witnesses(3);
        let aid = gen0.aid().clone();

        let inception = KelEvent::incept(
            &gen0,
            gen1.public_key(),
            receipts_for(&pool, 3, &aid, 0, gen0.public_key()),
        )
        .unwrap();
        // The honest rotation to gen1 at sequence 1.
        let honest = KelEvent::rotate(
            &aid,
            &gen0,
            &gen1,
            1,
            gen2.public_key(),
            receipts_for(&pool, 3, &aid, 1, gen1.public_key()),
        )
        .unwrap();
        // A SECOND, different rotation also at sequence 1 — the fork. (It is even
        // signed by the legitimate prior key, so signature alone would not catch it;
        // only fork detection does.)
        let attacker = id(9);
        let forked = KelEvent::rotate(
            &aid,
            &gen0,
            &attacker,
            1,
            attacker.public_key(),
            receipts_for(&pool, 3, &aid, 1, attacker.public_key()),
        )
        .unwrap();

        let kel = Kel::new(aid, WitnessPolicy::of(2), vec![inception, honest, forked]);
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(m) if m.contains("forked-kel")));
    }

    #[test]
    fn a_byte_identical_duplicate_event_is_not_a_fork() {
        // A relay re-sending the SAME event at the same sequence is a harmless
        // duplicate, not a fork — the log does not contradict itself.
        let gen0 = id(1);
        let gen1 = id(2);
        let gen2 = id(3);
        let pool = witnesses(3);
        let aid = gen0.aid().clone();
        let inception = KelEvent::incept(
            &gen0,
            gen1.public_key(),
            receipts_for(&pool, 3, &aid, 0, gen0.public_key()),
        )
        .unwrap();
        let rotation = KelEvent::rotate(
            &aid,
            &gen0,
            &gen1,
            1,
            gen2.public_key(),
            receipts_for(&pool, 3, &aid, 1, gen1.public_key()),
        )
        .unwrap();
        let kel = Kel::new(
            aid,
            WitnessPolicy::of(2),
            // the rotation appears twice, byte-identical
            vec![inception, rotation.clone(), rotation],
        );
        // Not a fork — but the duplicate is at a repeated sequence, caught as a
        // skipped/repeated sequence on the walk (still fails closed, never silently
        // accepted twice).
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_relay_suppressed_key_state_under_the_threshold_is_rejected() {
        let gen0 = id(1);
        let gen1 = id(2);
        let gen2 = id(3);
        let pool = witnesses(3);
        // The tip carries only ONE receipt but the policy demands two — a
        // relay-suppressed / stale snapshot.
        let kel = witnessed_log(&gen0, &gen1, gen2.public_key(), &pool, 1, 2);
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(m) if m.contains("stale-keystate")));
    }

    #[test]
    fn duplicate_receipts_from_one_witness_do_not_inflate_the_count() {
        let gen0 = id(1);
        let gen1 = id(2);
        let gen2 = id(3);
        let pool = witnesses(1); // only ONE distinct witness
        let aid = gen0.aid().clone();
        let inception = KelEvent::incept(
            &gen0,
            gen1.public_key(),
            receipts_for(&pool, 1, &aid, 0, gen0.public_key()),
        )
        .unwrap();
        // Repeat the single witness's receipt three times on the tip.
        let one = WitnessReceipt::issue(&pool[0], &aid, 1, gen1.public_key()).unwrap();
        let rotation = KelEvent::rotate(
            &aid,
            &gen0,
            &gen1,
            1,
            gen2.public_key(),
            vec![one.clone(), one.clone(), one],
        )
        .unwrap();
        let kel = Kel::new(aid, WitnessPolicy::of(2), vec![inception, rotation]);
        // One distinct witness < threshold 2 — rejected despite three receipts.
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(m) if m.contains("stale-keystate")));
    }

    #[test]
    fn a_rotation_to_a_key_the_prior_event_never_pre_committed_is_rejected() {
        let gen0 = id(1);
        let gen1 = id(2); // pre-committed
        let substitute = id(7); // never pre-committed
        let gen2 = id(3);
        let pool = witnesses(3);
        let aid = gen0.aid().clone();
        let inception = KelEvent::incept(
            &gen0,
            gen1.public_key(),
            receipts_for(&pool, 3, &aid, 0, gen0.public_key()),
        )
        .unwrap();
        // The rotation installs `substitute`, which gen0's inception never committed.
        let rotation = KelEvent::rotate(
            &aid,
            &gen0,
            &substitute,
            1,
            gen2.public_key(),
            receipts_for(&pool, 3, &aid, 1, substitute.public_key()),
        )
        .unwrap();
        let kel = Kel::new(aid, WitnessPolicy::of(2), vec![inception, rotation]);
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_zero_threshold_policy_never_accepts_a_key_state() {
        // A threshold of zero would accept any uncorroborated state — refused.
        let gen0 = id(1);
        let gen1 = id(2);
        let gen2 = id(3);
        let pool = witnesses(3);
        let kel = witnessed_log(&gen0, &gen1, gen2.public_key(), &pool, 3, 0);
        let err = kel.replay().unwrap_err();
        assert!(matches!(err, CoreError::Rejected(m) if m.contains("stale-keystate")));
    }
}
