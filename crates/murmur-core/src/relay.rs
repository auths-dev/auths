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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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

/// The relay's in-memory store-and-forward queue: a map from mailbox id to the
/// FIFO of outer envelopes waiting there. This is the whole of what an untrusted
/// relay holds — opaque bytes keyed by an opaque mailbox id, never plaintext and
/// never a sender AID.
#[derive(Debug, Default)]
pub struct MailboxStore {
    queues: HashMap<MailboxId, Vec<OuterEnvelope>>,
}

impl MailboxStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        MailboxStore::default()
    }

    /// Apply a [`RelayRequest`]. A deposit appends and yields nothing; a drain
    /// removes and returns everything queued under the mailbox (empty if none).
    pub fn handle(&mut self, req: &RelayRequest) -> Vec<OuterEnvelope> {
        match req {
            RelayRequest::Deposit(env) => {
                self.queues
                    .entry(env.to_mailbox.clone())
                    .or_default()
                    .push(env.clone());
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
}
