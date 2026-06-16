//! The message-encryption seam.
//!
//! A [`SecureChannel`] is an established pairwise leg that seals and opens
//! individual messages. Everything *above* the ratchet — the inner signature that
//! authenticates the sender as an AID, the two-layer envelope, the KERI-rooted
//! prekey bundle, the relay — is independent of which ratchet implementation sits
//! underneath. This trait is the line between the two: the rest of the engine
//! depends on `encrypt`/`decrypt`, not on a concrete chain.
//!
//! Two backends implement it:
//! - the in-tree forward-secret symmetric ratchet ([`crate::ratchet::Ratchet`]),
//!   the default; and
//! - the audited Olm library ratchet ([`crate::olm_backend`]), behind the `olm`
//!   feature.
//!
//! The seam is deliberately small. Establishment differs per backend (each roots
//! a session from the KERI-authenticated bundle in its own key types), so it stays
//! an inherent constructor on each type; only the per-message seal/open — the part
//! the relay path and the property proofs actually call — is unified here.

use crate::CoreResult;

/// An established pairwise secure channel: seal and open one message at a time.
///
/// `encrypt` returns the opaque wire bytes that become an
/// [`OuterEnvelope`](crate::OuterEnvelope) ciphertext; `decrypt` takes those bytes
/// back. Implementations own their own nonce, counter, ratchet advance, and key
/// zeroization — the caller never supplies a nonce or sees a key.
pub trait SecureChannel: Sized {
    /// Seal one plaintext into opaque wire bytes. Advances the sending ratchet.
    fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>>;

    /// Open one message from its wire bytes. Advances the receiving ratchet;
    /// rejects a replay of an already-opened message and a message it cannot
    /// authenticate, with a uniform error (no decryption oracle).
    fn decrypt(&mut self, wire: &[u8]) -> CoreResult<Vec<u8>>;
}

/// The in-tree symmetric ratchet as a [`SecureChannel`]. It binds a fixed
/// associated-data context (the pairwise mailbox id) into every seal, the same
/// context the receiving end opens against, so a ciphertext cannot be relocated to
/// a different mailbox and still open.
pub struct RatchetChannel {
    ratchet: crate::ratchet::Ratchet,
    aad: Vec<u8>,
}

impl RatchetChannel {
    /// Wrap a seeded ratchet with the associated-data context it seals under.
    pub fn new(ratchet: crate::ratchet::Ratchet, aad: Vec<u8>) -> Self {
        RatchetChannel { ratchet, aad }
    }
}

impl SecureChannel for RatchetChannel {
    fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        self.ratchet.seal(&self.aad, plaintext)
    }

    fn decrypt(&mut self, wire: &[u8]) -> CoreResult<Vec<u8>> {
        self.ratchet.open(&self.aad, wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::Ratchet;
    use crate::session::Session;

    fn channel(secret: [u8; 32], aad: &[u8]) -> RatchetChannel {
        let root = Session::from_secret(secret);
        RatchetChannel::new(Ratchet::from_session(&root).unwrap(), aad.to_vec())
    }

    #[test]
    fn round_trips_through_the_trait() {
        let mut send = channel([7u8; 32], b"mbx:demo");
        let mut recv = channel([7u8; 32], b"mbx:demo");
        let wire = send.encrypt(b"hello").unwrap();
        assert_eq!(recv.decrypt(&wire).unwrap(), b"hello");
    }

    #[test]
    fn a_consumed_message_does_not_open_again() {
        // Forward secrecy, behaviorally: once the receiving chain advances past a
        // message, re-presenting it is rejected — the key that opened it is gone.
        let mut send = channel([9u8; 32], b"mbx:demo");
        let mut recv = channel([9u8; 32], b"mbx:demo");
        let w0 = send.encrypt(b"m0").unwrap();
        let w1 = send.encrypt(b"m1").unwrap();
        assert_eq!(recv.decrypt(&w0).unwrap(), b"m0");
        assert_eq!(recv.decrypt(&w1).unwrap(), b"m1");
        assert!(recv.decrypt(&w0).is_err(), "a consumed message must not re-open");
    }
}
