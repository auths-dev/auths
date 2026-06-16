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

use std::collections::{HashMap, HashSet, VecDeque};

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

/// What the relay did with a deposit: it queued fresh ciphertext, recognized a
/// byte-identical replay it had already accepted and dropped it, or refused the
/// deposit because a quota was exceeded. The relay never reads inside the
/// ciphertext to decide — it fingerprints the opaque bytes and refuses to forward
/// the same capture twice, and it accounts only the byte/message counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositOutcome {
    /// Fresh ciphertext the relay had not seen under this mailbox — queued for the
    /// recipient.
    Queued,
    /// A byte-identical replay of ciphertext already accepted under this mailbox —
    /// dropped, so a captured envelope re-presented by the network or a hostile
    /// relay is never delivered twice.
    DedupedReplay,
    /// The deposit would exceed a relay quota — a per-mailbox message/byte cap or
    /// the global byte cap — so it is refused (fail-closed, H2). An attacker
    /// flooding one mailbox cannot grow the relay's memory without bound; legitimate
    /// traffic under quota still queues.
    QuotaExceeded,
}

/// Default per-mailbox cap on the number of undrained envelopes. Past this a
/// deposit is refused ([`DepositOutcome::QuotaExceeded`]).
pub const DEFAULT_MAX_MESSAGES_PER_MAILBOX: usize = 1024;
/// Default per-mailbox cap on the total bytes of undrained ciphertext.
pub const DEFAULT_MAX_BYTES_PER_MAILBOX: usize = 16 * 1024 * 1024;
/// Default global cap on the total bytes of undrained ciphertext across every
/// mailbox — the relay's whole queue footprint.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
/// How many recent ciphertext fingerprints the dedup window keeps per mailbox. The
/// replay window need only cover the delivery horizon, not all history; bounding it
/// stops the dedup set from growing without limit (M8). Oldest fingerprints are
/// evicted once the window is full.
pub const DEFAULT_DEDUP_WINDOW: usize = 4096;

/// Tunable relay quotas (H2): per-mailbox message/byte caps, a global byte cap, and
/// the dedup sliding-window size (M8). [`MailboxStore::new`] uses the defaults; a
/// test or a deployment can dial them down.
#[derive(Debug, Clone, Copy)]
pub struct RelayLimits {
    pub max_messages_per_mailbox: usize,
    pub max_bytes_per_mailbox: usize,
    pub max_total_bytes: usize,
    pub dedup_window: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        RelayLimits {
            max_messages_per_mailbox: DEFAULT_MAX_MESSAGES_PER_MAILBOX,
            max_bytes_per_mailbox: DEFAULT_MAX_BYTES_PER_MAILBOX,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            dedup_window: DEFAULT_DEDUP_WINDOW,
        }
    }
}

/// A bounded, per-mailbox replay-dedup window (M8). Keeps at most `window` of the
/// most-recent ciphertext fingerprints: a `HashSet` for O(1) membership and a
/// `VecDeque` recording insertion order so the oldest fingerprint is evicted when
/// the window is full. A byte-identical replay inside the window is still
/// recognized; an ancient capture older than the window is no longer in memory, so
/// the set cannot grow without bound. The window is NOT cleared on drain — a replay
/// re-presented just after the recipient drained must still be dropped (the
/// delivery horizon outlives the queue).
#[derive(Debug)]
struct DedupWindow {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl DedupWindow {
    fn new(capacity: usize) -> Self {
        DedupWindow {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record a fingerprint, evicting the oldest if the window is full. Returns
    /// `true` if it was fresh (not already in the window), `false` if it is a
    /// recognized in-window replay.
    fn record(&mut self, fingerprint: [u8; 32]) -> bool {
        if self.seen.contains(&fingerprint) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.order.push_back(fingerprint);
        self.seen.insert(fingerprint);
        true
    }

    fn len(&self) -> usize {
        self.seen.len()
    }
}

/// The relay's in-memory store-and-forward queue: a map from mailbox id to the
/// FIFO of outer envelopes waiting there, plus a bounded dedup window of ciphertext
/// fingerprints per mailbox. This is the whole of what an untrusted relay holds —
/// opaque bytes keyed by an opaque mailbox id, never plaintext and never a sender
/// AID. The fingerprints are a SHA-256 over the ciphertext bytes alone, so the
/// relay can recognize a re-presented capture without ever reading what is inside
/// it.
///
/// **Bounded by construction (H2/M8).** Per-mailbox message and byte caps and a
/// global byte cap refuse a deposit that would grow the queue past quota
/// ([`DepositOutcome::QuotaExceeded`]); the dedup set is a bounded sliding window
/// of the most-recent fingerprints. An attacker flooding one mailbox can neither
/// exhaust relay memory through the queue nor through an unbounded fingerprint set.
#[derive(Debug, Default)]
pub struct MailboxStore {
    queues: HashMap<MailboxId, Vec<OuterEnvelope>>,
    /// Per-mailbox bounded dedup window, so a byte-identical replay is dropped
    /// instead of forwarded a second time. Keyed by mailbox so a fingerprint never
    /// links traffic across mailboxes (a pairwise mailbox id stays the only thing
    /// the relay correlates on).
    seen: HashMap<MailboxId, DedupWindow>,
    /// Running total of undrained ciphertext bytes across every mailbox, kept in
    /// step with `queues` so the global cap is checked in O(1).
    total_bytes: usize,
    limits: RelayLimits,
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
    /// A fresh, empty store with the default quotas ([`RelayLimits::default`]).
    pub fn new() -> Self {
        MailboxStore::default()
    }

    /// A fresh, empty store with explicit quotas — for a deployment that dials the
    /// caps, or a test that drives the quota boundary without depositing megabytes.
    pub fn with_limits(limits: RelayLimits) -> Self {
        MailboxStore {
            queues: HashMap::new(),
            seen: HashMap::new(),
            total_bytes: 0,
            limits,
        }
    }

    /// Accept ciphertext into a mailbox, enforcing the quotas and deduplicating a
    /// byte-identical replay.
    ///
    /// Order of checks (all fail-closed):
    ///  1. **Dedup (M8):** a fingerprint already in this mailbox's bounded window is
    ///     a [`DepositOutcome::DedupedReplay`] — dropped, so a captured envelope
    ///     re-presented by the network or a hostile relay is never delivered twice.
    ///  2. **Quota (H2):** a fresh deposit that would push the mailbox past its
    ///     message or byte cap, or the relay past its global byte cap, is refused
    ///     ([`DepositOutcome::QuotaExceeded`]) — an attacker flooding a mailbox
    ///     cannot grow relay memory without bound.
    ///  3. Otherwise the envelope is queued ([`DepositOutcome::Queued`]) and its
    ///     fingerprint recorded in the window.
    ///
    /// The relay decides purely from the ciphertext fingerprint and byte length; it
    /// never reads inside the bytes.
    pub fn deposit(&mut self, env: &OuterEnvelope) -> DepositOutcome {
        let fingerprint = ciphertext_fingerprint(env);
        let size = env.ciphertext.len();

        // (1) Dedup against the bounded window WITHOUT mutating it yet — a replay is
        // dropped before any quota accounting.
        if self
            .seen
            .get(&env.to_mailbox)
            .is_some_and(|w| w.seen.contains(&fingerprint))
        {
            return DepositOutcome::DedupedReplay;
        }

        // (2) Quota: a fresh deposit must fit the per-mailbox caps and the global
        // byte cap. Checked before anything is recorded, so a refused deposit
        // changes no state.
        let queue_len = self.queues.get(&env.to_mailbox).map_or(0, Vec::len);
        let mailbox_bytes: usize = self
            .queues
            .get(&env.to_mailbox)
            .map(|q| q.iter().map(|e| e.ciphertext.len()).sum())
            .unwrap_or(0);
        if queue_len >= self.limits.max_messages_per_mailbox
            || mailbox_bytes.saturating_add(size) > self.limits.max_bytes_per_mailbox
            || self.total_bytes.saturating_add(size) > self.limits.max_total_bytes
        {
            return DepositOutcome::QuotaExceeded;
        }

        // (3) Queue it and record the fingerprint in the bounded window.
        self.queues
            .entry(env.to_mailbox.clone())
            .or_default()
            .push(env.clone());
        self.total_bytes = self.total_bytes.saturating_add(size);
        let window = self.limits.dedup_window;
        self.seen
            .entry(env.to_mailbox.clone())
            .or_insert_with(|| DedupWindow::new(window))
            .record(fingerprint);
        DepositOutcome::Queued
    }

    /// Apply a [`RelayRequest`]. A deposit accepts ciphertext through the quota +
    /// dedup guard and yields nothing; a drain removes and returns everything queued
    /// under the mailbox (empty if none) and frees its bytes from the global total.
    /// Drains do not clear the dedup window, so a capture replayed *after* the
    /// recipient has already drained it is still recognized and dropped (the
    /// delivery horizon outlives the queue); the window stays bounded regardless.
    pub fn handle(&mut self, req: &RelayRequest) -> Vec<OuterEnvelope> {
        match req {
            RelayRequest::Deposit(env) => {
                self.deposit(env);
                Vec::new()
            }
            RelayRequest::Drain(mbx) => {
                let drained = self.queues.remove(mbx).unwrap_or_default();
                let freed: usize = drained.iter().map(|e| e.ciphertext.len()).sum();
                self.total_bytes = self.total_bytes.saturating_sub(freed);
                drained
            }
        }
    }

    /// How many envelopes are currently queued under a mailbox (a diagnostic the
    /// relay binary can report; never reveals contents).
    pub fn depth(&self, mbx: &MailboxId) -> usize {
        self.queues.get(mbx).map_or(0, Vec::len)
    }

    /// How many fingerprints the dedup window for a mailbox currently holds — a
    /// diagnostic proving the set stays bounded by the window size (M8).
    pub fn dedup_len(&self, mbx: &MailboxId) -> usize {
        self.seen.get(mbx).map_or(0, DedupWindow::len)
    }

    /// The running total of undrained ciphertext bytes across every mailbox — what
    /// the global cap bounds.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
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

    // A distinct envelope under one mailbox: distinct payload byte → distinct
    // fingerprint, so it is not deduped against an earlier one.
    fn distinct_env(mbx: &str, n: usize) -> OuterEnvelope {
        OuterEnvelope {
            to_mailbox: MailboxId::new(mbx),
            ciphertext: (n as u64).to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn deposit_past_the_per_mailbox_message_quota_is_refused() {
        // H2 regression: under quota an envelope queues; the one that would exceed
        // the per-mailbox message cap is refused (QuotaExceeded), and the queue does
        // not grow past the cap. An attacker cannot flood one mailbox without bound.
        let limits = RelayLimits {
            max_messages_per_mailbox: 3,
            ..RelayLimits::default()
        };
        let mut store = MailboxStore::with_limits(limits);
        for n in 0..3 {
            assert_eq!(
                store.deposit(&distinct_env("mbx:bob", n)),
                DepositOutcome::Queued
            );
        }
        // The 4th distinct deposit exceeds the cap.
        assert_eq!(
            store.deposit(&distinct_env("mbx:bob", 99)),
            DepositOutcome::QuotaExceeded
        );
        assert_eq!(store.depth(&MailboxId::new("mbx:bob")), 3);
    }

    #[test]
    fn deposit_past_the_global_byte_cap_is_refused() {
        // H2 regression: the global byte cap bounds the relay's whole footprint, not
        // just one mailbox. Spread across mailboxes, a deposit that would push the
        // global total past the cap is refused.
        let limits = RelayLimits {
            max_messages_per_mailbox: 1000,
            max_bytes_per_mailbox: 1000,
            max_total_bytes: 16, // two 8-byte envelopes fit; a third does not
            dedup_window: 64,
        };
        let mut store = MailboxStore::with_limits(limits);
        assert_eq!(
            store.deposit(&distinct_env("mbx:a", 1)),
            DepositOutcome::Queued
        );
        assert_eq!(
            store.deposit(&distinct_env("mbx:b", 2)),
            DepositOutcome::Queued
        );
        assert_eq!(store.total_bytes(), 16);
        // A third 8-byte envelope would push the global total to 24 > 16.
        assert_eq!(
            store.deposit(&distinct_env("mbx:c", 3)),
            DepositOutcome::QuotaExceeded
        );
        assert_eq!(store.total_bytes(), 16);
    }

    #[test]
    fn a_drain_frees_global_bytes_so_fresh_deposits_fit_again() {
        // Draining a mailbox returns its bytes to the global budget, so the relay
        // recovers capacity for the next recipient — the cap bounds *live* queue
        // memory, not lifetime throughput.
        let limits = RelayLimits {
            max_total_bytes: 16,
            ..RelayLimits::default()
        };
        let mut store = MailboxStore::with_limits(limits);
        assert_eq!(
            store.deposit(&distinct_env("mbx:a", 1)),
            DepositOutcome::Queued
        );
        assert_eq!(
            store.deposit(&distinct_env("mbx:a", 2)),
            DepositOutcome::Queued
        );
        assert_eq!(
            store.deposit(&distinct_env("mbx:a", 3)),
            DepositOutcome::QuotaExceeded
        );
        // Drain frees the 16 bytes; a fresh deposit fits again.
        let drained = store.handle(&RelayRequest::Drain(MailboxId::new("mbx:a")));
        assert_eq!(drained.len(), 2);
        assert_eq!(store.total_bytes(), 0);
        assert_eq!(
            store.deposit(&distinct_env("mbx:a", 4)),
            DepositOutcome::Queued
        );
    }

    #[test]
    fn the_dedup_window_stays_bounded_but_still_catches_an_in_window_replay() {
        // M8 regression: depositing many distinct envelopes keeps the dedup set
        // bounded by the window size (it does not grow without limit), AND a
        // byte-identical replay of a RECENT capture is still dropped. The existing
        // "replay after a drain is still dropped" test pins the same in-window
        // guarantee across a drain.
        let window = 8;
        let limits = RelayLimits {
            max_messages_per_mailbox: 10_000,
            dedup_window: window,
            ..RelayLimits::default()
        };
        let mut store = MailboxStore::with_limits(limits);
        // Deposit far more distinct envelopes than the window holds.
        for n in 0..100 {
            assert_eq!(
                store.deposit(&distinct_env("mbx:bob", n)),
                DepositOutcome::Queued
            );
        }
        // The dedup set is capped at the window size — not 100.
        assert!(store.dedup_len(&MailboxId::new("mbx:bob")) <= window);
        // A replay of the MOST RECENT capture (still inside the window) is dropped.
        assert_eq!(
            store.deposit(&distinct_env("mbx:bob", 99)),
            DepositOutcome::DedupedReplay
        );
        // A replay of an ANCIENT capture (evicted from the window) is no longer
        // recognized — it is treated as fresh. This is the bounded-memory tradeoff:
        // the window covers the delivery horizon, not all history.
        assert_eq!(
            store.deposit(&distinct_env("mbx:bob", 0)),
            DepositOutcome::Queued
        );
    }
}
