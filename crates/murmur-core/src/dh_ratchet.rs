//! The Diffie-Hellman ratchet — the *asymmetric* half of the Double Ratchet that
//! gives **post-compromise security** (the attacker is locked back out after the
//! next step).
//!
//! [`crate::ratchet`] is the symmetric-key chain: it gives **forward secrecy**
//! (a captured ciphertext can't be reopened from a *later* state). What it cannot
//! do is *heal*: if an attacker captures the whole session state — the root key
//! and the live chain key — at some instant, they can derive every subsequent
//! symmetric step from there, because the symmetric chain injects no new secret
//! entropy. The chain only ever HMACs what it already holds.
//!
//! The DH ratchet closes that. Each party holds a current X25519 ratchet key
//! pair. A **DH ratchet step** happens when a party turns the conversation
//! around: it generates a *fresh* ephemeral key pair, mixes a fresh
//! Diffie-Hellman output — `DH(my new private, their current public)` — into the
//! root key, and derives a new root and a new sending-chain seed from it (the
//! Signal `KDF_RK`):
//!
//! ```text
//!   (root', chain_seed) = HKDF( root, DH(my_new_eph_priv, their_pub) )
//! ```
//!
//! ## Why this *heals*
//!
//! Say an attacker compromises the full state at some instant: they hold the
//! current root key `R`. While the conversation only ratchets *symmetrically*
//! they keep up — every step is a function of `R` alone, which they have. The
//! instant either party takes a **DH ratchet step**, the new root is
//! `HKDF(R, DH(fresh_priv, peer_pub))`. The attacker has `R`, and the public
//! keys are on the wire — but `DH(fresh_priv, peer_pub)` requires *one of the two
//! private keys*, and `fresh_priv` was generated **after** the compromise and
//! never left the device. The attacker cannot compute the DH output, so cannot
//! derive `R'`, so is **locked out** of everything sealed on the post-step chain.
//! The legitimate peer holds the matching private key and derives the same `R'`,
//! so for the honest pair the conversation continues seamlessly. That asymmetry —
//! peer can heal, attacker can't follow — *is* post-compromise security.
//!
//! ## What this is and is not
//!
//! This is the DH (asymmetric) ratchet only: it advances the **root** and seeds a
//! fresh symmetric chain on each turn. The per-message keys on that chain are the
//! existing forward-secret [`crate::ratchet::Ratchet`]; the two compose into the
//! full Double Ratchet. The DH primitive is X25519 over the audited
//! `x25519-dalek` already in the workspace (the same curve [`crate::prekey`]'s
//! X3DH uses); the root KDF is HKDF-SHA256. We do not reinvent either primitive,
//! only wire the asymmetric step.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::ratchet::Ratchet;
use crate::session::Session;
use crate::{CoreError, CoreResult};

/// Domain-separating label for the DH-ratchet root-KDF, so a root advanced by a DH
/// step can never collide with a key derived for another purpose off the same DH
/// output.
const ROOT_KDF_INFO: &[u8] = b"murmur/dh-ratchet/root/v1";
/// Domain-separating label for the chain-seed the root-KDF emits alongside the new
/// root, so the seed handed to the symmetric chain is distinct from the new root.
const CHAIN_SEED_INFO: &[u8] = b"murmur/dh-ratchet/chain-seed/v1";

/// One party's view of the Diffie-Hellman ratchet: the current root key and the
/// party's current X25519 ratchet key pair. Each **DH ratchet step** generates a
/// fresh ratchet key pair, advances the root with a fresh DH output, and seeds a
/// new symmetric sending chain — injecting entropy an attacker who snapshotted an
/// earlier root cannot reproduce.
///
/// The root key is zeroized on every advance and on drop, so a dropped or advanced
/// ratchet leaves no prior root in memory.
pub struct DhRatchet {
    /// The current root key — the secret the next DH step mixes a fresh DH output
    /// into. Compromising *this* is exactly the state the healing step recovers
    /// from.
    root: [u8; 32],
    /// This party's current X25519 ratchet secret. Replaced (and the old one
    /// zeroized) on every step this party initiates.
    ratchet_secret: X25519Secret,
    /// How many DH ratchet steps this party has taken — the turn count, surfaced so
    /// a proof can assert the root actually advanced.
    steps: u64,
}

impl Drop for DhRatchet {
    fn drop(&mut self) {
        self.root.zeroize();
    }
}

/// The public output of a DH ratchet step: the fresh ratchet public key the peer
/// needs to perform the matching step, and the [`Session`]-rooted symmetric chain
/// seed the stepping party will seal on. The public key travels on the wire (the
/// relay may see it — it is public); the seed never does.
pub struct DhStep {
    /// The fresh X25519 ratchet public key the stepping party generated. The peer
    /// mixes `DH(their_secret, this)` into their own root to land on the same new
    /// root. Public by construction — safe for the relay to carry.
    pub public_key: [u8; 32],
}

/// Run HKDF-SHA256 over `(root ‖ dh_output)` to derive the next root key and a
/// fresh symmetric chain seed (the Signal `KDF_RK`). The old root salts the KDF so
/// the new root depends on *both* the prior root and the fresh DH output: an
/// attacker missing either cannot derive it.
fn kdf_root(root: &[u8; 32], dh_output: &[u8; 32]) -> CoreResult<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_output);
    let mut next_root = [0u8; 32];
    hk.expand(ROOT_KDF_INFO, &mut next_root)
        .map_err(|_| CoreError::Malformed("DH-ratchet root derivation failed".into()))?;
    let mut chain_seed = [0u8; 32];
    hk.expand(CHAIN_SEED_INFO, &mut chain_seed)
        .map_err(|_| CoreError::Malformed("DH-ratchet chain-seed derivation failed".into()))?;
    Ok((next_root, chain_seed))
}

impl DhRatchet {
    /// Seed both parties' DH ratchets from the same agreed root secret (the X3DH
    /// output) and their initial X25519 ratchet secrets. Both ends start from the
    /// same `root`; each holds its own `ratchet_secret`. No step has been taken yet
    /// (`steps == 0`).
    pub fn from_root(root: [u8; 32], ratchet_secret: X25519Secret) -> Self {
        DhRatchet {
            root,
            ratchet_secret,
            steps: 0,
        }
    }

    /// This party's current ratchet public key — what the peer needs to perform the
    /// matching DH step.
    pub fn public_key(&self) -> [u8; 32] {
        X25519Public::from(&self.ratchet_secret).to_bytes()
    }

    /// How many DH ratchet steps this party has taken.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// The current root key, for the metadata-hygiene self-test ([`crate::leakcheck`])
    /// to confirm the live root never appears in the relay-visible bytes, and for a
    /// proof to snapshot the *compromised* root. Crate-internal on purpose: the root
    /// is never exposed across the public API or the FFI. Proof/test-only
    /// introspection, gated with the harness rather than carried as dead code in the
    /// default engine build.
    #[cfg(any(feature = "proofs", test))]
    pub(crate) fn root_state(&self) -> &[u8; 32] {
        &self.root
    }

    /// **Take a DH ratchet step**: generate a fresh ratchet key pair, mix a fresh
    /// `DH(new_secret, peer_public)` into the root, advance the root, and return the
    /// fresh public key plus a [`Ratchet`] seeded on the new chain. This is the step
    /// that *heals* — its new root depends on a private key generated here and now,
    /// which an attacker holding only the prior root cannot reproduce.
    ///
    /// The old ratchet secret and the old root are zeroized as they are replaced, so
    /// the healed-from state cannot be recovered from memory after the step.
    pub fn ratchet_send(
        &mut self,
        peer_public: &[u8; 32],
        new_ratchet_secret: X25519Secret,
    ) -> CoreResult<(DhStep, Ratchet)> {
        let peer = X25519Public::from(*peer_public);
        let dh = new_ratchet_secret.diffie_hellman(&peer);
        let (next_root, chain_seed) = kdf_root(&self.root, dh.as_bytes())?;

        // Replace the ratchet secret with the fresh one, zeroizing the old root.
        self.ratchet_secret = new_ratchet_secret;
        self.root.zeroize();
        self.root = next_root;
        self.steps += 1;

        let public_key = self.public_key();
        let chain = Ratchet::from_session(&Session::from_secret(chain_seed))?;
        Ok((DhStep { public_key }, chain))
    }

    /// **Follow the peer's DH ratchet step**: on receiving the peer's fresh ratchet
    /// public key, mix `DH(my_current_secret, peer_new_public)` into the root and
    /// derive the *same* new root and chain seed the peer derived in
    /// [`ratchet_send`]. Returns a [`Ratchet`] seeded on the new receiving chain.
    ///
    /// Both sides land on the same root because DH is symmetric:
    /// `DH(peer_new_priv, my_pub) == DH(my_priv, peer_new_pub)`. An attacker holding
    /// the prior root but neither private key cannot compute that shared output, so
    /// cannot follow — the healing asymmetry.
    pub fn ratchet_receive(&mut self, peer_new_public: &[u8; 32]) -> CoreResult<Ratchet> {
        let peer = X25519Public::from(*peer_new_public);
        let dh = self.ratchet_secret.diffie_hellman(&peer);
        let (next_root, chain_seed) = kdf_root(&self.root, dh.as_bytes())?;

        self.root.zeroize();
        self.root = next_root;
        self.steps += 1;

        Ratchet::from_session(&Session::from_secret(chain_seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> X25519Secret {
        X25519Secret::from([byte; 32])
    }

    #[test]
    fn a_dh_step_lets_both_sides_land_on_the_same_chain() {
        // Both ends seed from the same agreed root and their own ratchet keys. Alice
        // takes a DH step; Bob follows it. They must land on the same new chain — a
        // message Alice seals on it opens on Bob's.
        let root = [0x5au8; 32];
        let mut alice = DhRatchet::from_root(root, secret(0x10));
        let mut bob = DhRatchet::from_root(root, secret(0x20));

        let bob_pub = bob.public_key();
        let (step, mut alice_send) = alice.ratchet_send(&bob_pub, secret(0x11)).unwrap();
        let mut bob_recv = bob.ratchet_receive(&step.public_key).unwrap();

        let wire = alice_send.seal(b"mbx", b"healed hello").unwrap();
        assert_eq!(bob_recv.open(b"mbx", &wire).unwrap(), b"healed hello");
    }

    #[test]
    fn a_dh_step_advances_the_root_away_from_the_compromised_value() {
        // The healing property in a unit: snapshot the root an attacker would seize,
        // take a DH step, and prove the root changed to a value the snapshot does not
        // determine. The post-step chain is seeded from the *new* root; an attacker
        // with only the old root cannot derive the new chain seed.
        let compromised_root = [0x42u8; 32];
        let mut alice = DhRatchet::from_root(compromised_root, secret(0x10));
        let bob = DhRatchet::from_root(compromised_root, secret(0x20));

        let (_step, _chain) = alice.ratchet_send(&bob.public_key(), secret(0x11)).unwrap();
        assert_eq!(alice.steps(), 1);
        // The live root is no longer the compromised value.
        assert_ne!(alice.root_state(), &compromised_root);
    }

    #[test]
    fn an_attacker_with_only_the_old_root_cannot_derive_the_healed_chain() {
        // Model the attacker explicitly: they captured `compromised_root` but hold
        // neither party's private ratchet key. After Alice's DH step, the legitimate
        // Bob (who holds his private key) derives the healed chain and opens the
        // message; the attacker — who can only run the symmetric chain off the old
        // root — derives a *different* seed and cannot open it.
        let compromised_root = [0x42u8; 32];
        let mut alice = DhRatchet::from_root(compromised_root, secret(0x10));
        let mut bob = DhRatchet::from_root(compromised_root, secret(0x20));

        let bob_pub = bob.public_key();
        let (step, mut alice_send) = alice.ratchet_send(&bob_pub, secret(0x11)).unwrap();
        let healed = alice_send.seal(b"mbx", b"after the compromise").unwrap();

        // Legitimate Bob heals and opens.
        let mut bob_recv = bob.ratchet_receive(&step.public_key).unwrap();
        assert_eq!(
            bob_recv.open(b"mbx", &healed).unwrap(),
            b"after the compromise"
        );

        // The attacker can only continue the *symmetric* chain off the compromised
        // root (no fresh DH output to mix). That chain is seeded from the old root,
        // not the healed one, so it cannot open the post-step ciphertext.
        let mut attacker_chain =
            Ratchet::from_session(&Session::from_secret(compromised_root)).unwrap();
        assert!(matches!(
            attacker_chain.open(b"mbx", &healed),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn the_new_root_depends_on_the_fresh_dh_output_not_the_old_root_alone() {
        // Two runs from the *same* old root but *different* fresh ratchet secrets
        // must reach different new roots — proof the fresh DH entropy (not the old
        // root alone) determines the healed root.
        let old_root = [0x42u8; 32];
        let bob = DhRatchet::from_root(old_root, secret(0x20));
        let bob_pub = bob.public_key();

        let mut a1 = DhRatchet::from_root(old_root, secret(0x10));
        a1.ratchet_send(&bob_pub, secret(0x11)).unwrap();

        let mut a2 = DhRatchet::from_root(old_root, secret(0x10));
        a2.ratchet_send(&bob_pub, secret(0x99)).unwrap();

        assert_ne!(a1.root_state(), a2.root_state());
    }
}
