//! The transport seam — untrusted store-and-forward.
//!
//! A relay is dumb and untrusted by design: it sees an opaque mailbox id and
//! ciphertext, queues it for an offline recipient, and lets that recipient pull
//! or subscribe to drain the mailbox. It never sees plaintext, a sender AID, or
//! a phone number — it never had a number to begin with.
//!
//! [`MailboxStore`] is the real queue the relay binary drives: a deposit appends
//! an [`OuterEnvelope`] under its mailbox; a drain hands back everything queued
//! there and empties it. Everything the store touches is an outer envelope — a
//! pairwise mailbox id and opaque bytes — so a relay built on it is structurally
//! incapable of reading a message or learning who sent it. (The HTTPS / WebSocket
//! wire that exposes the store over a network is the binary's surface; the queue
//! semantics live here so they can be tested without a socket.)

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::envelope::OuterEnvelope;

/// A pairwise / rotating mailbox identifier. Keeping it per-contact stops the
/// relay from learning that all of a person's traffic is one person. It carries
/// no AID and no phone number — only a routing handle the recipient authorized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MailboxId(String);

impl MailboxId {
    pub fn new(text: impl Into<String>) -> Self {
        MailboxId(text.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn placeholder() -> Self {
        MailboxId("mbx:placeholder".into())
    }
}

/// A store-and-forward request the relay binary speaks: queue ciphertext under a
/// mailbox, or drain everything queued under one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayRequest {
    /// Queue ciphertext under a mailbox for an offline recipient.
    Deposit(OuterEnvelope),
    /// Drain everything queued under a mailbox.
    Drain(MailboxId),
}

/// What the relay did with a deposit: it either queued fresh ciphertext, or
/// recognized byte-identical bytes it had already accepted under this mailbox and
/// dropped them. The relay never reads inside the ciphertext to decide — it
/// fingerprints the opaque bytes and refuses to forward the same capture twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositOutcome {
    /// Fresh ciphertext the relay had not seen under this mailbox — queued for the
    /// recipient.
    Queued,
    /// A byte-identical replay of ciphertext already accepted under this mailbox —
    /// dropped, so a captured envelope re-presented by the network or a hostile
    /// relay is never delivered twice.
    DedupedReplay,
}

/// The relay's in-memory store-and-forward queue: a map from mailbox id to the
/// FIFO of outer envelopes waiting there, plus the set of ciphertext fingerprints
/// it has already accepted under each mailbox. This is the whole of what an
/// untrusted relay holds — opaque bytes keyed by an opaque mailbox id, never
/// plaintext and never a sender AID. The fingerprints are a SHA-256 over the
/// ciphertext bytes alone, so the relay can recognize a re-presented capture
/// without ever reading what is inside it.
#[derive(Debug, Default)]
pub struct MailboxStore {
    queues: HashMap<MailboxId, Vec<OuterEnvelope>>,
    /// Per-mailbox set of ciphertext digests already accepted, so a byte-identical
    /// replay is dropped instead of forwarded a second time. Keyed by mailbox so a
    /// fingerprint never links traffic across mailboxes (a pairwise mailbox id
    /// stays the only thing the relay correlates on).
    seen: HashMap<MailboxId, HashSet<[u8; 32]>>,
}

/// The SHA-256 fingerprint of an outer envelope's opaque ciphertext — what the
/// relay dedups on. Computed over the ciphertext bytes only (never the mailbox id
/// or anything inside the ciphertext), so two byte-identical captures fingerprint
/// alike and a single bit flip fingerprints differently.
fn ciphertext_fingerprint(env: &OuterEnvelope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&env.ciphertext);
    hasher.finalize().into()
}

impl MailboxStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        MailboxStore::default()
    }

    /// Accept ciphertext into a mailbox, deduplicating a byte-identical replay.
    /// The first time a fingerprint is seen under a mailbox the envelope is queued
    /// ([`DepositOutcome::Queued`]); a later deposit of the same opaque bytes under
    /// the same mailbox is dropped ([`DepositOutcome::DedupedReplay`]) — so a
    /// captured envelope re-presented by the network, or replayed by a hostile
    /// relay, is never delivered to the recipient twice. The relay decides purely
    /// from the ciphertext fingerprint; it never reads inside the bytes.
    pub fn deposit(&mut self, env: &OuterEnvelope) -> DepositOutcome {
        let fingerprint = ciphertext_fingerprint(env);
        let first_time = self
            .seen
            .entry(env.to_mailbox.clone())
            .or_default()
            .insert(fingerprint);
        if first_time {
            self.queues
                .entry(env.to_mailbox.clone())
                .or_default()
                .push(env.clone());
            DepositOutcome::Queued
        } else {
            DepositOutcome::DedupedReplay
        }
    }

    /// Apply a [`RelayRequest`]. A deposit accepts ciphertext through the dedup
    /// guard (a byte-identical replay is dropped, never queued) and yields nothing;
    /// a drain removes and returns everything queued under the mailbox (empty if
    /// none). Drains do not forget fingerprints, so a capture replayed *after* the
    /// recipient has already drained it is still recognized and dropped.
    pub fn handle(&mut self, req: &RelayRequest) -> Vec<OuterEnvelope> {
        match req {
            RelayRequest::Deposit(env) => {
                self.deposit(env);
                Vec::new()
            }
            RelayRequest::Drain(mbx) => self.queues.remove(mbx).unwrap_or_default(),
        }
    }

    /// How many envelopes are currently queued under a mailbox (a diagnostic the
    /// relay binary can report; never reveals contents).
    pub fn depth(&self, mbx: &MailboxId) -> usize {
        self.queues.get(mbx).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::MailboxId;

    fn env(mbx: &str, byte: u8) -> OuterEnvelope {
        OuterEnvelope {
            to_mailbox: MailboxId::new(mbx),
            ciphertext: vec![byte; 8],
        }
    }

    #[test]
    fn deposit_then_drain_returns_in_order_and_empties() {
        let mut store = MailboxStore::new();
        store.handle(&RelayRequest::Deposit(env("mbx:bob", 1)));
        store.handle(&RelayRequest::Deposit(env("mbx:bob", 2)));
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 2);

        let drained = store.handle(&RelayRequest::Drain(MailboxId::new("mbx:bob")));
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].ciphertext, vec![1u8; 8]);
        assert_eq!(drained[1].ciphertext, vec![2u8; 8]);
        // A second drain is empty — the mailbox was emptied.
        assert!(
            store
                .handle(&RelayRequest::Drain(MailboxId::new("mbx:bob")))
                .is_empty()
        );
    }

    #[test]
    fn mailboxes_do_not_leak_into_each_other() {
        let mut store = MailboxStore::new();
        store.handle(&RelayRequest::Deposit(env("mbx:bob", 1)));
        store.handle(&RelayRequest::Deposit(env("mbx:carol", 2)));
        let bob = store.handle(&RelayRequest::Drain(MailboxId::new("mbx:bob")));
        assert_eq!(bob.len(), 1);
        assert_eq!(store.depth(&MailboxId::new("mbx:carol")), 1);
    }

    #[test]
    fn draining_an_unknown_mailbox_is_empty_not_an_error() {
        let mut store = MailboxStore::new();
        assert!(
            store
                .handle(&RelayRequest::Drain(MailboxId::new("mbx:nobody")))
                .is_empty()
        );
    }

    #[test]
    fn a_byte_identical_replay_is_deduped_not_queued_twice() {
        // The attacker (or a hostile relay) re-presents the exact bytes it captured.
        // The relay fingerprints the ciphertext and drops the second copy, so the
        // recipient drains the message once, not twice.
        let mut store = MailboxStore::new();
        let original = env("mbx:bob", 7);
        assert_eq!(store.deposit(&original), DepositOutcome::Queued);
        assert_eq!(store.deposit(&original), DepositOutcome::DedupedReplay);
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 1);
        let drained = store.handle(&RelayRequest::Drain(MailboxId::new("mbx:bob")));
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn a_replay_after_a_drain_is_still_dropped() {
        // The recipient has already drained the message; replaying the same capture
        // afterward must not re-deliver it — the fingerprint outlives the queue.
        let mut store = MailboxStore::new();
        let original = env("mbx:bob", 9);
        assert_eq!(store.deposit(&original), DepositOutcome::Queued);
        let drained = store.handle(&RelayRequest::Drain(MailboxId::new("mbx:bob")));
        assert_eq!(drained.len(), 1);
        // Re-present the exact capture after the drain.
        assert_eq!(store.deposit(&original), DepositOutcome::DedupedReplay);
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 0);
    }

    #[test]
    fn a_single_bit_flip_is_not_seen_as_a_replay() {
        // Dedup is by exact ciphertext bytes: a tampered copy fingerprints
        // differently, so the relay does not silently swallow it as a duplicate —
        // it is queued, and the recipient's AEAD is what rejects it.
        let mut store = MailboxStore::new();
        let original = env("mbx:bob", 1);
        let mut tampered = original.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert_eq!(store.deposit(&original), DepositOutcome::Queued);
        assert_eq!(store.deposit(&tampered), DepositOutcome::Queued);
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 2);
    }

    #[test]
    fn the_same_bytes_under_two_mailboxes_are_not_cross_deduped() {
        // The fingerprint is scoped per mailbox, so identical ciphertext addressed
        // to two different pairwise mailboxes is each queued — the relay never
        // correlates the two mailboxes through a shared fingerprint.
        let mut store = MailboxStore::new();
        assert_eq!(store.deposit(&env("mbx:bob", 3)), DepositOutcome::Queued);
        assert_eq!(store.deposit(&env("mbx:carol", 3)), DepositOutcome::Queued);
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 1);
        assert_eq!(store.depth(&MailboxId::new("mbx:carol")), 1);
    }
}
