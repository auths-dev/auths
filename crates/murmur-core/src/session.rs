//! The session — real AEAD confidentiality so the relay only ever sees opaque
//! bytes.
//!
//! A Murmur session holds a 32-byte secret shared by the two endpoints. From it,
//! each message derives a fresh per-message content key (HKDF-SHA256 over the
//! secret + a 96-bit message nonce), then seals the inner payload with
//! ChaCha20-Poly1305. The relay is handed only the resulting ciphertext and a
//! pairwise mailbox id — it can read neither the plaintext nor the sender AID
//! (those live *inside* the sealed inner envelope).
//!
//! **What this is and is not.** The AEAD and the KDF here are the real, audited
//! constructions (the same primitives the workspace's crypto provider uses).
//! What is deliberately *not* here is how the session secret is agreed: the full
//! X3DH key agreement and the forward-secret Double Ratchet are their own later
//! work. Until those land, the secret is established out-of-band (the pairing
//! channel, §6.2) and held fixed for the session — so this gives confidentiality
//! from the relay, not yet per-message forward secrecy. The two jobs are kept
//! separate on purpose: identity authenticates (a real signature,
//! [`crate::identity`]); the session encrypts.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{CoreError, CoreResult};

/// Domain-separating label for the content-key derivation, so a Murmur content
/// key can never collide with a key derived for another protocol off the same
/// secret.
const CONTENT_KEY_INFO: &[u8] = b"murmur/session/content-key/v1";

/// A fresh 96-bit AEAD nonce from OS entropy. Each sealed message must use a new
/// one: a distinct nonce derives a distinct content key (see
/// [`Session::content_key`]), so never reusing a nonce is how a content key is
/// never reused. Returns an error rather than panicking if the OS entropy source
/// is unavailable, so a caller fails the seal closed instead of crashing.
pub fn fresh_nonce() -> CoreResult<[u8; 12]> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| CoreError::Malformed("OS entropy source unavailable for nonce".into()))?;
    Ok(nonce)
}

/// A shared session secret between two endpoints. Wrapping it keeps the raw
/// bytes from being logged or serialized by accident.
#[derive(Clone)]
pub struct Session {
    secret: [u8; 32],
}

impl Session {
    /// Build a session from a 32-byte shared secret. In the full engine this is
    /// the X3DH output; for the hermetic round-trip both endpoints are
    /// constructed from the same out-of-band secret.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Session { secret }
    }

    /// Derive the per-message content key for a given 96-bit message nonce via
    /// HKDF-SHA256. A distinct nonce yields a distinct key, so reusing a content
    /// key requires reusing a nonce — which the caller must never do.
    fn content_key(&self, nonce: &[u8; 12]) -> CoreResult<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(nonce), &self.secret);
        let mut okm = [0u8; 32];
        hk.expand(CONTENT_KEY_INFO, &mut okm)
            .map_err(|_| CoreError::Malformed("content-key derivation failed".into()))?;
        Ok(okm)
    }

    /// Seal `plaintext` under a freshly-derived content key, binding `aad` (the
    /// routing context — the mailbox id) into the AEAD so a relay cannot move
    /// ciphertext between mailboxes without the tag failing. Returns the message
    /// nonce prepended to the ciphertext.
    pub fn seal(&self, nonce: [u8; 12], aad: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let key_bytes = self.content_key(&nonce)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CoreError::Malformed("AEAD seal failed".into()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a sealed blob (message nonce ‖ ciphertext) under the same `aad`. A
    /// tampered ciphertext, a wrong session secret, or a mismatched AAD all fail
    /// the AEAD tag and are rejected — the relay gets no decryption oracle.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> CoreResult<Vec<u8>> {
        if sealed.len() < 12 {
            return Err(CoreError::Malformed(
                "sealed blob shorter than its nonce".into(),
            ));
        }
        let (nonce_bytes, ct) = sealed.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        let key_bytes = self.content_key(&nonce)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad })
            .map_err(|_| CoreError::Rejected("AEAD open failed — tampered, replayed, or wrong key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::from_secret([42u8; 32])
    }

    #[test]
    fn round_trips_under_matching_aad() {
        let s = session();
        let sealed = s.seal([1u8; 12], b"mbx:bob", b"hi bob").unwrap();
        assert_eq!(s.open(&sealed, b"mbx:bob").unwrap(), b"hi bob");
    }

    #[test]
    fn the_relay_sees_no_plaintext() {
        let s = session();
        let sealed = s.seal([2u8; 12], b"mbx:bob", b"secret words").unwrap();
        assert!(
            !sealed
                .windows(b"secret words".len())
                .any(|w| w == b"secret words")
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let s = session();
        let mut sealed = s.seal([3u8; 12], b"mbx:bob", b"hi bob").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(matches!(
            s.open(&sealed, b"mbx:bob"),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn moving_ciphertext_to_another_mailbox_is_rejected() {
        let s = session();
        let sealed = s.seal([4u8; 12], b"mbx:bob", b"hi bob").unwrap();
        // A relay that re-files the bytes under a different mailbox breaks AAD.
        assert!(matches!(
            s.open(&sealed, b"mbx:eve"),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_wrong_session_secret_cannot_open() {
        let sealed = session().seal([5u8; 12], b"mbx:bob", b"hi bob").unwrap();
        let other = Session::from_secret([7u8; 32]);
        assert!(matches!(
            other.open(&sealed, b"mbx:bob"),
            Err(CoreError::Rejected(_))
        ));
    }
}
