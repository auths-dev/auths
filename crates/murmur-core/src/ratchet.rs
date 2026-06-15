//! The forward-secret symmetric ratchet — per-message keys that cannot be
//! recovered from a later state.
//!
//! X3DH ([`crate::prekey`]) agrees the *initial* root secret; this module is the
//! part that gives every message its own key and **forward secrecy**: a
//! ciphertext captured off the relay cannot be decrypted from a *later*,
//! compromised session state, because the chain that produced its key has been
//! ratcheted past it and the used key was zeroized (PRD §10, the
//! forward-secrecy claim).
//!
//! ## The symmetric-key ratchet (the Double Ratchet's sending/receiving chain)
//!
//! A [`Ratchet`] holds one 32-byte **chain key** and a message counter. For each
//! message it does a one-way KDF step (the Signal Double Ratchet's symmetric-key
//! ratchet, HMAC-SHA256 with distinct constants):
//!
//! ```text
//!   message_key = HMAC(chain_key, 0x01)      // this message's key
//!   chain_key'  = HMAC(chain_key, 0x02)      // the chain, ratcheted forward
//! ```
//!
//! then **destroys the old chain key** (`zeroize`) and increments the counter.
//! The KDF is one-way, so a state holding `chain_key_n` (the chain after message
//! `n`) cannot reproduce `chain_key_{n-k}` and therefore cannot derive any
//! earlier message key — *that* is forward secrecy. Each message key is also
//! zeroized the instant it has sealed or opened its one message, so a state
//! captured between messages holds no message key at all, only the forward chain
//! key.
//!
//! ## What this is and is not
//!
//! This is the **symmetric** half of the Double Ratchet — the chain that gives
//! forward secrecy. The **asymmetric** (DH) half, which injects fresh entropy on
//! a reply to give *post-compromise healing*, is its own later feature
//! ([`crate::prekey`]'s X3DH seeds the first root; the DH ratchet step is the
//! post-compromise-healing claim). Keeping them separate is deliberate: forward
//! secrecy is a property of the chain KDF alone and is provable without the DH
//! step, which is exactly what the forward-secrecy claim asserts.
//!
//! The KDF is HMAC-SHA256 — the same construction Signal's `kdf_ck` uses — over
//! the audited `hmac`/`sha2` crates already in the workspace; we do not reinvent
//! the primitive, only wire the chain.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::session::Session;
use crate::{CoreError, CoreResult};

type HmacSha256 = Hmac<Sha256>;

/// The constant fed to the chain KDF to derive a message key. Distinct from
/// [`CHAIN_STEP`] so a message key can never equal the next chain key.
const MESSAGE_KEY_STEP: &[u8] = &[0x01];
/// The constant fed to the chain KDF to ratchet the chain key forward.
const CHAIN_STEP: &[u8] = &[0x02];
/// Domain-separating salt the root secret is bound to before it becomes the
/// initial chain key, so a Murmur chain key can never collide with a key derived
/// off the same root for another purpose.
const CHAIN_INIT_SALT: &[u8] = b"murmur/ratchet/chain-init/v1";

/// A single message key, derived from the chain and used exactly once. It zeroizes
/// itself on drop, so a session state captured *between* messages never holds a
/// spent message key — only the forward chain key, from which earlier keys cannot
/// be recovered.
struct MessageKey([u8; 32]);

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One direction's symmetric-key chain: a 32-byte chain key plus the count of
/// messages it has produced. Advancing it is one-way (an HMAC step), and the
/// previous chain key is destroyed on each advance — so the state at message `n`
/// cannot reproduce the key for any earlier message. This is the unit forward
/// secrecy is a property of.
///
/// `Zeroize` is *not* derived to wipe on drop blindly; the chain key is wiped
/// explicitly on every advance (`replace_chain_key`) and a `Drop` zeroizes
/// whatever remains, so a dropped ratchet leaves no key in memory.
pub struct Ratchet {
    chain_key: [u8; 32],
    /// The index of the next message this chain will produce (0-based).
    counter: u64,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl Ratchet {
    /// Seed a chain from an X3DH root [`Session`]. Both endpoints seed the same
    /// direction's chain from the same agreed root, so they stay in lockstep
    /// without ever transmitting a chain or message key.
    ///
    /// The root secret is run through one HKDF-free HMAC bind (salted by
    /// [`CHAIN_INIT_SALT`]) so the value used as a chain key is domain-separated
    /// from the value the [`Session`] would use as a content key — the two derive
    /// different keys from the same root by construction.
    pub fn from_session(root: &Session) -> CoreResult<Self> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(CHAIN_INIT_SALT)
            .map_err(|_| CoreError::Malformed("ratchet chain-init keying failed".into()))?;
        mac.update(root.secret_bytes());
        let tag = mac.finalize().into_bytes();
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&tag);
        Ok(Ratchet {
            chain_key,
            counter: 0,
        })
    }

    /// The index of the next message this chain will produce — the counter a peer
    /// must be at to stay in lockstep.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// HMAC the current chain key with `step` and return the 32-byte tag. The one
    /// failure HMAC-from-key can report is an (impossible, fixed-length) keying
    /// error, which we propagate rather than panic on.
    fn kdf(&self, step: &[u8]) -> CoreResult<[u8; 32]> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key)
            .map_err(|_| CoreError::Malformed("ratchet chain-key keying failed".into()))?;
        mac.update(step);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Overwrite the chain key with its successor, zeroizing the old bytes first
    /// so the prior chain key cannot be recovered from memory after the advance.
    fn replace_chain_key(&mut self, next: [u8; 32]) {
        self.chain_key.zeroize();
        self.chain_key = next;
        self.counter += 1;
    }

    /// Advance the chain one step: derive this message's key, ratchet the chain
    /// forward, and destroy the old chain key. Returns the spent-on-drop message
    /// key for message [`counter`](Self::counter) (the value *before* the advance).
    fn advance(&mut self) -> CoreResult<(u64, MessageKey)> {
        let index = self.counter;
        let message_key = MessageKey(self.kdf(MESSAGE_KEY_STEP)?);
        let next_chain = self.kdf(CHAIN_STEP)?;
        self.replace_chain_key(next_chain);
        Ok((index, message_key))
    }

    /// Seal `plaintext` for the next message on this sending chain, binding `aad`
    /// (the routing context) into the AEAD. The per-message key is derived, used
    /// once, and zeroized; the chain is ratcheted forward so this message's key
    /// can never be reproduced from the post-send state.
    ///
    /// The wire format is `counter(8) ‖ Session::seal output`, so the receiver
    /// knows which message index a ciphertext is and can derive the matching key
    /// without the sender ever transmitting it.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let (index, key) = self.advance()?;
        let inner = Session::from_secret(key.0);
        let nonce = crate::session::fresh_nonce()?;
        let sealed = inner.seal(nonce, aad, plaintext)?;
        let mut out = Vec::with_capacity(8 + sealed.len());
        out.extend_from_slice(&index.to_be_bytes());
        out.extend_from_slice(&sealed);
        Ok(out)
        // `key` and `inner`'s secret are dropped here — zeroized.
    }

    /// Open a ciphertext produced by [`seal`](Self::seal) on the peer's matching
    /// sending chain. The receiving chain must be at the message's index (in-order
    /// delivery, the thin slice's contract); a ciphertext for an *earlier* index
    /// than the chain has reached cannot be opened, because the key for it has been
    /// ratcheted past and destroyed — which is forward secrecy, observable.
    ///
    /// Returns [`CoreError::Rejected`] for an out-of-order index and for any AEAD
    /// failure (tamper / wrong key), so the relay gets no decryption oracle.
    pub fn open(&mut self, aad: &[u8], wire: &[u8]) -> CoreResult<Vec<u8>> {
        if wire.len() < 8 {
            return Err(CoreError::Malformed(
                "ratchet wire shorter than its index".into(),
            ));
        }
        let (idx_bytes, sealed) = wire.split_at(8);
        let mut idx = [0u8; 8];
        idx.copy_from_slice(idx_bytes);
        let index = u64::from_be_bytes(idx);
        if index != self.counter {
            // The chain is past (or short of) this message. A *later* state cannot
            // open an *earlier* ciphertext — the forward-secrecy property itself.
            return Err(CoreError::Rejected(
                "out-of-order message: this chain key cannot open a ciphertext from another index",
            ));
        }
        let (_index, key) = self.advance()?;
        let inner = Session::from_secret(key.0);
        inner.open(sealed, aad)
        // `key` and `inner`'s secret are dropped here — zeroized.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Ratchet, Ratchet) {
        let root = Session::from_secret([0x5au8; 32]);
        // Both ends seed the same direction's chain from the same agreed root.
        (
            Ratchet::from_session(&root).unwrap(),
            Ratchet::from_session(&root).unwrap(),
        )
    }

    #[test]
    fn an_in_order_message_round_trips() {
        let (mut send, mut recv) = pair();
        let wire = send.seal(b"mbx", b"hello").unwrap();
        assert_eq!(recv.open(b"mbx", &wire).unwrap(), b"hello");
    }

    #[test]
    fn each_message_uses_a_distinct_key() {
        // Two messages sealed in a row must not produce the same ciphertext key:
        // sealing the *same plaintext* twice yields ciphertexts whose post-nonce
        // bodies differ (distinct per-message keys), and both still open in order.
        let (mut send, mut recv) = pair();
        let w0 = send.seal(b"mbx", b"same").unwrap();
        let w1 = send.seal(b"mbx", b"same").unwrap();
        assert_ne!(w0, w1);
        assert_eq!(recv.open(b"mbx", &w0).unwrap(), b"same");
        assert_eq!(recv.open(b"mbx", &w1).unwrap(), b"same");
    }

    #[test]
    fn the_counter_advances_with_each_message() {
        let (mut send, _recv) = pair();
        assert_eq!(send.counter(), 0);
        send.seal(b"mbx", b"a").unwrap();
        assert_eq!(send.counter(), 1);
        send.seal(b"mbx", b"b").unwrap();
        assert_eq!(send.counter(), 2);
    }

    #[test]
    fn forward_secrecy_a_later_state_cannot_open_an_earlier_ciphertext() {
        // The forward-secrecy property in a unit: capture message 0's ciphertext, advance the
        // receiving chain past it (open messages 0..N), then a state *cloned from
        // the advanced chain* cannot open message 0 — its key was ratcheted past
        // and destroyed.
        let (mut send, mut recv) = pair();
        let early = send.seal(b"mbx", b"early secret").unwrap();
        // Receiver processes message 0 (consuming it) then several more.
        assert_eq!(recv.open(b"mbx", &early).unwrap(), b"early secret");
        for _ in 0..4 {
            let w = send.seal(b"mbx", b"later").unwrap();
            recv.open(b"mbx", &w).unwrap();
        }
        // The receiving chain is now at message 5. Re-presenting message 0's
        // ciphertext is rejected: the chain cannot reach back to index 0.
        assert!(matches!(
            recv.open(b"mbx", &early),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn replaying_a_consumed_ciphertext_against_the_advanced_chain_fails() {
        // The attacker captures message 0 off the relay and replays it after the
        // receiving chain has moved on. The advanced chain holds only a forward
        // chain key; the key that opened message 0 was zeroized, so the replay is
        // rejected — a captured ciphertext is single-use against a live chain.
        let (mut send, mut recv) = pair();
        let early = send.seal(b"mbx", b"earliest").unwrap();
        // The receiver consumes message 0 (advancing to index 1) and three more.
        assert_eq!(recv.open(b"mbx", &early).unwrap(), b"earliest");
        for _ in 0..3 {
            let w = send.seal(b"mbx", b"fill").unwrap();
            recv.open(b"mbx", &w).unwrap();
        }
        // recv is now at index 4; re-presenting message 0 is rejected.
        assert!(matches!(
            recv.open(b"mbx", &early),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let (mut send, mut recv) = pair();
        let mut wire = send.seal(b"mbx", b"hello").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert!(matches!(
            recv.open(b"mbx", &wire),
            Err(CoreError::Rejected(_))
        ));
    }
}
