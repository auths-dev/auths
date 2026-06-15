//! Murmur core — the shared engine behind the native iOS + macOS messenger.
//!
//! Murmur splits the two jobs a phone number used to do at once: it is an
//! *identity* (a self-certifying AID you control) and a *routing key* (a signed
//! endpoint record naming a mailbox/relay). This crate models that split as a
//! two-layer envelope:
//!
//!   * the **outer** envelope is what an untrusted relay sees — a pairwise
//!     mailbox id and opaque bytes. Routing only.
//!   * the **inner** envelope is what the recipient verifies and decrypts — the
//!     real sender AID, authenticated by replaying *their* key log, wrapping a
//!     forward-secret ciphertext.
//!
//! This is a SKELETON. The types and the seams are here and they compile, but
//! the identity bind, the ratchet, and the relay wire are not built yet — every
//! operation that would need them returns [`CoreError::NotBuilt`] so callers
//! (the SwiftUI shells, the relay binary, the probe harness) get an honest,
//! testable "feature absent" instead of a fake success.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod address;
pub mod envelope;
pub mod relay;
pub mod trust;

pub use address::Aid;
pub use envelope::{InnerEnvelope, OuterEnvelope};
pub use relay::{MailboxId, RelayRequest};
pub use trust::{TrustState, TrustVerdict};

/// The crate's error type. `NotBuilt` is the load-bearing one for the skeleton:
/// it names the seam that is specified but not yet wired, so a caller — and a
/// probe — can tell "absent" apart from "broke".
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A specified seam that has not been built yet. The string names the seam.
    #[error("not built yet: {0}")]
    NotBuilt(&'static str),

    /// A message claimed an AID the sender does not control, a substituted key,
    /// a tampered ciphertext, or a revoked device — anything that must fail
    /// closed. The string names which.
    #[error("rejected: {0}")]
    Rejected(&'static str),

    /// Malformed input the core could not even parse.
    #[error("malformed: {0}")]
    Malformed(String),
}

/// The result of building/verifying one message through the core.
pub type CoreResult<T> = Result<T, CoreError>;

/// The crate version, surfaced to the FFI and the relay's `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single conversation message at the API boundary the SwiftUI shell sees:
/// plaintext in, an addressed [`OuterEnvelope`] out (once built). No phone
/// number or email appears anywhere in this type — the address is the AID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    /// The recipient's self-certifying address.
    pub to: Aid,
    /// The sender's self-certifying address (authenticated, never asserted).
    pub from: Aid,
    /// The cleartext the user typed. Never leaves the device in the clear.
    pub body: String,
}

/// Seal a [`Message`] into the two-layer envelope: KERI-bind the sender,
/// ratchet-encrypt the body, address the result to the recipient's pairwise
/// mailbox. SKELETON: the bind+ratchet are unbuilt, so this fails closed.
pub fn seal(_msg: &Message) -> CoreResult<OuterEnvelope> {
    Err(CoreError::NotBuilt(
        "seal: KERI prekey bind + Signal ratchet + relay envelope",
    ))
}

/// Open an [`OuterEnvelope`] pulled from a mailbox: verify the sender AID by
/// replaying their key log, then ratchet-decrypt. SKELETON: unbuilt, fails
/// closed (an unverified message is never surfaced as plaintext).
pub fn open(_outer: &OuterEnvelope) -> CoreResult<Message> {
    Err(CoreError::NotBuilt(
        "open: sender-AID KEL replay + ratchet-decrypt",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn seal_is_honestly_unbuilt() {
        let m = Message {
            to: Aid::placeholder(),
            from: Aid::placeholder(),
            body: "hi".into(),
        };
        assert!(matches!(seal(&m), Err(CoreError::NotBuilt(_))));
    }

    #[test]
    fn open_is_honestly_unbuilt() {
        let outer = OuterEnvelope::placeholder();
        assert!(matches!(open(&outer), Err(CoreError::NotBuilt(_))));
    }
}
