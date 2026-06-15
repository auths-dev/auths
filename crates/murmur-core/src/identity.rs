//! The sender identity — a signing keypair whose public key *is* the address.
//!
//! A Murmur address is self-certifying: the [`Aid`](crate::address::Aid) is
//! derived from the identity's public key, so anyone who can resolve the AID to
//! its key can verify a signature the holder produced — and no one else can
//! forge one. This is the authentication root the whole envelope hangs from:
//! `open` accepts a message only when its signature verifies under the public
//! key the sender's AID resolves to.
//!
//! What lives here is the *static* key binding (AID ↔ signing key). The full
//! KERI key-log replay (`replay_with_receipts` → key-state, pre-rotation
//! continuity) that turns a resolved key into a *witnessed* one is the engine's
//! later work; a relay-served directory is the stand-in a hermetic round-trip
//! resolves against here. Confidentiality and key agreement (X3DH, the Double
//! Ratchet) are likewise their own later work; this module owns identity, not
//! the session.

use auths_crypto::{CurveType, TypedSeed, typed_public_key, typed_sign};

use crate::address::Aid;
use crate::{CoreError, CoreResult};

/// A locally-held identity: the secret signing seed plus the public key the AID
/// is derived from. The seed never leaves the device — in the apps it lives in
/// the Secure Enclave and only signatures cross the FFI; here it is held in
/// memory for the engine's hermetic round-trip.
#[derive(Clone)]
pub struct Identity {
    seed: TypedSeed,
    public_key: Vec<u8>,
    aid: Aid,
}

impl Identity {
    /// Build an identity from a 32-byte Ed25519 seed. The public key is derived
    /// from the seed and the AID is derived from the public key, so the address
    /// is bound to the key by construction — you cannot mint an AID for a key
    /// you do not hold.
    pub fn from_seed(seed_bytes: [u8; 32]) -> CoreResult<Self> {
        let seed = TypedSeed::Ed25519(seed_bytes);
        let public_key = typed_public_key(&seed)
            .map_err(|e| CoreError::Malformed(format!("derive public key: {e}")))?;
        let aid = Aid::from_public_key(&public_key);
        Ok(Identity {
            seed,
            public_key,
            aid,
        })
    }

    /// This identity's self-certifying address.
    pub fn aid(&self) -> &Aid {
        &self.aid
    }

    /// The raw Ed25519 public key the AID is derived from.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `message` with the identity's signing key. The signature is what a
    /// recipient verifies against this identity's AID to authenticate it.
    pub fn sign(&self, message: &[u8]) -> CoreResult<Vec<u8>> {
        typed_sign(&self.seed, message).map_err(|e| CoreError::Malformed(format!("sign: {e}")))
    }
}

/// Verify that `signature` over `message` was produced by the holder of `aid`.
///
/// This is the authentication gate: `open` calls it before surfacing any
/// plaintext, so a message that claims an AID the sender does not control is
/// rejected (it cannot produce a signature that verifies under that AID's key).
/// `public_key` is the key the AID resolved to — in the full engine, the output
/// of a witnessed KEL replay; here, a directory lookup.
pub fn verify_sender(
    aid: &Aid,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    // The resolved key must actually be the one the AID is derived from — a
    // directory cannot hand us a key for a *different* AID and have it pass.
    if Aid::from_public_key(public_key) != *aid {
        return Err(CoreError::Rejected(
            "sender AID does not match the resolved public key",
        ));
    }
    auths_crypto::RingCryptoProvider::ed25519_verify(public_key, message, signature).map_err(
        |_| CoreError::Rejected("sender signature did not verify under the claimed AID"),
    )?;
    Ok(())
}

/// The curve every Murmur identity signs with today. P-256 is the Secure-Enclave
/// curve the apps will mint with; the engine's hermetic round-trip uses Ed25519
/// seeds, and the AID encodes the curve so a future P-256 identity resolves the
/// same way.
pub const IDENTITY_CURVE: CurveType = CurveType::Ed25519;

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn aid_is_derived_from_the_key_and_is_stable() {
        let id = Identity::from_seed(seed(7)).unwrap();
        let again = Identity::from_seed(seed(7)).unwrap();
        assert_eq!(id.aid(), again.aid());
        assert!(id.aid().as_str().starts_with("did:keri:"));
    }

    #[test]
    fn a_signature_verifies_under_its_own_aid() {
        let id = Identity::from_seed(seed(1)).unwrap();
        let msg = b"hello murmur";
        let sig = id.sign(msg).unwrap();
        assert!(verify_sender(id.aid(), id.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_aid() {
        let alice = Identity::from_seed(seed(1)).unwrap();
        let mallory = Identity::from_seed(seed(2)).unwrap();
        let msg = b"hello murmur";
        let sig = alice.sign(msg).unwrap();
        // Mallory presents Alice's signature under *his own* AID+key: rejected.
        assert!(matches!(
            verify_sender(mallory.aid(), mallory.public_key(), msg, &sig),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_key_for_a_mismatched_aid_is_rejected() {
        let alice = Identity::from_seed(seed(1)).unwrap();
        let mallory = Identity::from_seed(seed(2)).unwrap();
        let msg = b"hello murmur";
        let sig = alice.sign(msg).unwrap();
        // A directory hands us Mallory's key but claims it is Alice's AID.
        assert!(matches!(
            verify_sender(alice.aid(), mallory.public_key(), msg, &sig),
            Err(CoreError::Rejected(_))
        ));
    }
}
