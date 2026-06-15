//! The transport seam — untrusted store-and-forward.
//!
//! A relay is dumb and untrusted by design: it sees an opaque mailbox id and
//! ciphertext, queues it for an offline recipient, and lets that recipient pull
//! or subscribe to drain the mailbox. It never sees plaintext, a sender AID, or
//! a phone number — it never had a number to begin with.

use serde::{Deserialize, Serialize};

/// A pairwise / rotating mailbox identifier. Keeping it per-contact stops the
/// relay from learning that all of a person's traffic is one person. SKELETON:
/// the derivation (from a pairwise AID) is not wired yet.
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

/// A store-and-forward request the relay binary speaks. SKELETON: the wire
/// format and the queue are not built; this only names the two verbs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayRequest {
    /// Queue ciphertext under a mailbox for an offline recipient.
    Deposit(crate::envelope::OuterEnvelope),
    /// Drain everything queued under a mailbox.
    Drain(MailboxId),
}

/// Accept a relay request against an in-memory queue. SKELETON: unbuilt — the
/// relay binary stands up the HTTP/WebSocket surface but the store is not here
/// yet, so this fails closed.
pub fn handle(_req: &RelayRequest) -> crate::CoreResult<Vec<crate::envelope::OuterEnvelope>> {
    Err(crate::CoreError::NotBuilt(
        "relay: store-and-forward queue + pull/subscribe wire",
    ))
}
