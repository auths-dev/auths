//! The message-encryption seam.
//!
//! A [`SecureChannel`] is an established pairwise leg that seals and opens
//! individual messages. Everything *above* the ratchet — the inner signature that
//! authenticates the sender as an AID, the two-layer envelope, the KERI-rooted
//! prekey bundle, the relay — is independent of which ratchet implementation sits
//! underneath. This trait is the line between the two: a consumer depends on
//! `encrypt`/`decrypt`, not on a concrete chain.
//!
//! The audited Olm library ratchet ([`OlmChannel`](crate::olm_backend::OlmChannel),
//! behind the `olm` feature) implements it, and it is the seam the FFI message path
//! is planned to depend on. The seam is deliberately small: establishment differs
//! per backend (each roots a session from the KERI-authenticated bundle in its own
//! key types), so it stays an inherent constructor on each type; only the
//! per-message seal/open is unified here.

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
