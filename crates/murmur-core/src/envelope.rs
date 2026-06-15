//! The two-layer envelope — routing on the outside, a verified session inside.
//!
//! The phone number smushed routing and identity together; splitting them is
//! strictly better for metadata privacy. The relay only ever touches the
//! [`OuterEnvelope`]; only the recipient device ever reconstructs the
//! [`InnerEnvelope`].

use serde::{Deserialize, Serialize};

use crate::relay::MailboxId;

/// What the untrusted relay sees: a pairwise mailbox id and opaque ciphertext.
/// No sender AID, no plaintext, no phone number — routing only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OuterEnvelope {
    /// The pairwise/rotating mailbox the bytes are queued under.
    pub to_mailbox: MailboxId,
    /// Opaque, end-to-end-encrypted bytes. The relay cannot read these.
    pub ciphertext: Vec<u8>,
}

impl OuterEnvelope {
    /// A stand-in envelope for tests and skeleton call sites.
    pub fn placeholder() -> Self {
        OuterEnvelope {
            to_mailbox: MailboxId::placeholder(),
            ciphertext: Vec::new(),
        }
    }
}

/// What the recipient verifies and decrypts after pulling the outer envelope:
/// the authenticated sender AID and the forward-secret ciphertext the Signal
/// session produced. SKELETON: reconstructed by [`crate::open`], which is
/// unbuilt — this type only documents the shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerEnvelope {
    /// The real sender AID — authenticated by replaying *their* key log, never
    /// trusted because it was asserted.
    pub sender: crate::address::Aid,
    /// The Signal-Protocol ciphertext that wraps the user's message body.
    pub ratchet_ciphertext: Vec<u8>,
}
