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

/// What the recipient reconstructs after AEAD-opening the outer envelope: the
/// claimed sender AID, the message body, and the sender's signature over both.
/// [`crate::open`] verifies the signature against the key the sender's AID
/// resolves to *before* surfacing the body, so the `sender` here is never
/// trusted because it was asserted — it is trusted only once the signature
/// checks out. The whole struct is sealed inside the [`OuterEnvelope`]'s
/// ciphertext, so the relay never sees any of these fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerEnvelope {
    /// The claimed sender AID — authenticated by verifying [`signature`] against
    /// the key this AID resolves to, never trusted because it was asserted.
    ///
    /// [`signature`]: InnerEnvelope::signature
    pub sender: crate::address::Aid,
    /// The recipient AID the body was authored for, bound into the signed bytes
    /// so a captured inner envelope cannot be re-attributed to another
    /// conversation.
    pub recipient: crate::address::Aid,
    /// The user's message body. Confidential against the relay (it only ever
    /// holds the sealed outer ciphertext) and authenticated by `signature`.
    pub body: String,
    /// The sender's signature over the authenticated bytes (sender ‖ recipient ‖
    /// body). Verifying it under the sender AID's key is what authenticates the
    /// message; an envelope whose signature does not verify is rejected by
    /// [`crate::open`].
    pub signature: Vec<u8>,
}

impl InnerEnvelope {
    /// The canonical byte string a sender signs and a recipient verifies. Binds
    /// the sender AID, the recipient AID, and the body together so none can be
    /// swapped after signing.
    pub fn signing_bytes(
        sender: &crate::address::Aid,
        recipient: &crate::address::Aid,
        body: &str,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"murmur/inner/v1\n");
        bytes.extend_from_slice(sender.as_str().as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(recipient.as_str().as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    /// The signing bytes for *this* envelope — what [`crate::open`] re-derives to
    /// verify the signature against.
    pub fn signing_bytes_for(&self) -> Vec<u8> {
        Self::signing_bytes(&self.sender, &self.recipient, &self.body)
    }
}
