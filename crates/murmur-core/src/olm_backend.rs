//! The audited Olm library ratchet as a message-encryption backend, joined to the
//! KERI identity root (behind the `olm` feature).
//!
//! This module replaces the in-tree Double Ratchet with **Olm** (Matrix's audited,
//! pure-Rust `vodozemac`): the 1:1 protocol in the same family as Signal's Double
//! Ratchet — forward secrecy + post-compromise security. The ratchet itself is
//! library code (Least-Authority-audited); the only custom crypto here is the
//! **join**: how a KERI-authenticated prekey bundle becomes an Olm session. That
//! join is the single seam an external audit still has to bless.
//!
//! ## The two layers, kept separate
//! - **Olm authenticates the *channel*** — a session is bound to both ends' Olm
//!   Curve25519 identity keys; a ciphertext from one pairwise session cannot be
//!   opened by any other.
//! - **KERI authenticates the *identity*** — the prekey bundle is signed by the
//!   AID's current key (the inner signature, kept above this layer, authenticates
//!   each message *as an AID*). Olm does not, and need not, know about AIDs.
//!
//! ## Curves
//! The AID signing key is Ed25519/P-256 (P-256 in the Secure Enclave on iOS); Olm
//! keys are Curve25519, software-held. The KERI key *signs* the Curve25519 bundle
//! — a signature over bytes that happen to contain a Curve25519 key, which is
//! standard. The "messaging key ≠ AID signing key" hygiene rule is then trivially
//! true: they are different curves.
//!
//! ## MAC strength
//! Sessions use Olm **version 2** ([`SessionConfig::version_2`]) — the full,
//! untruncated MAC. The default version 1 truncates the MAC to 8 bytes, too short
//! for a greenfield messenger. The inbound handshake passes v2 as the *expected*
//! config, so a v1 (downgraded) peer is rejected, not silently accepted.

use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;

use crate::address::Aid;
use crate::channel::SecureChannel;
use crate::identity::{verify_sender, Identity};
use crate::{CoreError, CoreResult};

/// Domain-separating context the AID key signs over an Olm prekey bundle. Distinct
/// from the in-tree bundle context so a signature over one can never be replayed as
/// the other.
const OLM_BUNDLE_CONTEXT: &[u8] = b"murmur/olm-prekey-bundle/v1\n";

/// Full-MAC Olm. The whole engine pins one version; the inbound side requires it.
fn session_config() -> SessionConfig {
    SessionConfig::version_2()
}

/// The bytes the AID's current KERI key signs over an Olm prekey bundle: the
/// context, the AID, the Olm Curve25519 identity key, and the one-time key. Binding
/// all of them means none can be swapped after signing.
fn olm_bundle_signing_bytes(aid: &Aid, identity_key: &[u8; 32], one_time_key: &[u8; 32]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(OLM_BUNDLE_CONTEXT.len() + aid.as_str().len() + 64 + 1);
    bytes.extend_from_slice(OLM_BUNDLE_CONTEXT);
    bytes.extend_from_slice(aid.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(identity_key);
    bytes.extend_from_slice(one_time_key);
    bytes
}

/// A recipient's Olm prekey bundle, published for first contact: the recipient's
/// Olm Curve25519 identity key + a one-time key, signed by the recipient's AID
/// current KERI key. The signature is what roots the Olm session in the KERI
/// identity — [`verify_rooted`] checks it before any session is created.
///
/// [`verify_rooted`]: OlmPrekeyBundle::verify_rooted
#[derive(Debug, Clone)]
pub struct OlmPrekeyBundle {
    /// The AID this bundle claims to publish Olm keys for.
    pub aid: Aid,
    /// The recipient's Olm Curve25519 identity key (DISTINCT curve from the AID
    /// signing key).
    pub olm_identity_key: [u8; 32],
    /// A one-time key, consumed once on the recipient's first inbound session.
    pub olm_one_time_key: [u8; 32],
    /// The AID current-key signature over (context ‖ AID ‖ identity key ‖ OTK).
    pub signature: Vec<u8>,
}

impl OlmPrekeyBundle {
    /// Verify this bundle is rooted in the key the recipient AID resolves to, then
    /// hand back the verified material an outbound session can run against. Three
    /// fail-closed checks, mirroring the in-tree bundle:
    ///  1. key hygiene — the Olm identity key must not equal the AID signing-key
    ///     bytes (it never can across curves, but we assert it anyway);
    ///  2. + 3. the AID's current key signed *this* bundle, and that key derives the
    ///     claimed AID (both via [`verify_sender`]).
    ///
    /// There is no other constructor for [`OlmRootedBundle`], so an outbound session
    /// can never be created against an unverified bundle.
    pub fn verify_rooted(&self, aid_current_key: &[u8]) -> CoreResult<OlmRootedBundle> {
        if self.olm_identity_key.as_slice() == aid_current_key {
            return Err(CoreError::Rejected(
                "key hygiene: the Olm identity key reuses the AID signing key (signing↔DH reuse)",
            ));
        }
        let signing_bytes =
            olm_bundle_signing_bytes(&self.aid, &self.olm_identity_key, &self.olm_one_time_key);
        verify_sender(&self.aid, aid_current_key, &signing_bytes, &self.signature).map_err(
            |_| {
                CoreError::Rejected(
                    "Olm prekey bundle is not signed by the AID's current key — bundle rejected",
                )
            },
        )?;
        let identity_key = Curve25519PublicKey::from_bytes(self.olm_identity_key);
        let one_time_key = Curve25519PublicKey::from_bytes(self.olm_one_time_key);
        Ok(OlmRootedBundle {
            aid: self.aid.clone(),
            identity_key,
            one_time_key,
        })
    }
}

/// An Olm prekey bundle that has been verified to belong to its AID — the
/// capability an outbound session requires. No public constructor: the only way to
/// hold one is [`OlmPrekeyBundle::verify_rooted`].
#[derive(Debug, Clone)]
pub struct OlmRootedBundle {
    aid: Aid,
    identity_key: Curve25519PublicKey,
    one_time_key: Curve25519PublicKey,
}

impl OlmRootedBundle {
    /// The AID this verified bundle belongs to.
    pub fn aid(&self) -> &Aid {
        &self.aid
    }
}

/// A local Olm endpoint: the long-term Olm account (identity + one-time keys) wired
/// to the KERI [`Identity`] that signs its bundles. The account holds the
/// Curve25519 secret material; the [`Identity`] holds the Ed25519/P-256 signing key
/// (in the apps, Secure-Enclave-held).
pub struct OlmIdentity {
    account: Account,
    identity: Identity,
}

impl OlmIdentity {
    /// Build an Olm endpoint over a KERI identity, minting a fresh Olm account.
    pub fn new(identity: Identity) -> Self {
        OlmIdentity {
            account: Account::new(),
            identity,
        }
    }

    /// The AID this endpoint sends as.
    pub fn aid(&self) -> &Aid {
        self.identity.aid()
    }

    /// This endpoint's Olm Curve25519 identity key — what a peer needs to open our
    /// first (prekey) message. In the full flow a peer learns this from our
    /// KERI-signed bundle.
    pub fn olm_identity_key(&self) -> Curve25519PublicKey {
        self.account.curve25519_key()
    }

    /// Mint and publish an Olm prekey bundle: generate a one-time key, then sign the
    /// (identity key ‖ OTK) with the AID's KERI key. Key hygiene is enforced here
    /// too — a bundle whose Olm identity key equalled the AID signing-key bytes is
    /// refused (it never can across curves, but we never emit one).
    pub fn publish_bundle(&mut self) -> CoreResult<OlmPrekeyBundle> {
        self.account.generate_one_time_keys(1);
        let one_time_key = *self
            .account
            .one_time_keys()
            .values()
            .next()
            .ok_or(CoreError::Rejected("no one-time key was generated"))?;
        self.account.mark_keys_as_published();

        let identity_key = self.account.curve25519_key();
        let id_bytes = identity_key.to_bytes();
        let otk_bytes = one_time_key.to_bytes();
        if id_bytes.as_slice() == self.identity.public_key() {
            return Err(CoreError::Rejected(
                "key hygiene: the Olm identity key must be distinct from the AID signing key",
            ));
        }
        let signing_bytes = olm_bundle_signing_bytes(self.identity.aid(), &id_bytes, &otk_bytes);
        let signature = self.identity.sign(&signing_bytes)?;
        Ok(OlmPrekeyBundle {
            aid: self.identity.aid().clone(),
            olm_identity_key: id_bytes,
            olm_one_time_key: otk_bytes,
            signature,
        })
    }

    /// Initiator side of the join: create an outbound Olm session against a verified
    /// bundle. The first message the returned channel seals is an Olm *prekey*
    /// message carrying the handshake; subsequent messages are normal.
    pub fn establish_outbound(&self, rooted: &OlmRootedBundle) -> CoreResult<OlmChannel> {
        let session = self
            .account
            .create_outbound_session(session_config(), rooted.identity_key, rooted.one_time_key)
            .map_err(|_| {
                CoreError::Rejected("outbound Olm session could not be created (non-contributory key)")
            })?;
        Ok(OlmChannel { session })
    }

    /// Responder side of the join: consume a one-time key to create the inbound Olm
    /// session from the sender's first (prekey) wire message, also yielding the
    /// first plaintext. `sender_olm_identity_key` is the sender's Olm identity key
    /// (learned from the sender's KERI bundle); the handshake binds to it.
    ///
    /// The session config is required to be v2 — a v1 (truncated-MAC, downgraded)
    /// first message is rejected here, not accepted.
    pub fn establish_inbound(
        &mut self,
        sender_olm_identity_key: Curve25519PublicKey,
        first_wire: &[u8],
    ) -> CoreResult<(OlmChannel, Vec<u8>)> {
        let prekey = match decode_wire(first_wire)? {
            OlmMessage::PreKey(p) => p,
            OlmMessage::Normal(_) => {
                return Err(CoreError::Rejected(
                    "first inbound message must be an Olm prekey message",
                ));
            }
        };
        let created = self
            .account
            .create_inbound_session(session_config(), sender_olm_identity_key, &prekey)
            .map_err(|_| {
                CoreError::Rejected(
                    "inbound Olm session rejected (config mismatch, identity mismatch, or missing one-time key)",
                )
            })?;
        Ok((
            OlmChannel {
                session: created.session,
            },
            created.plaintext,
        ))
    }
}

/// An established Olm session as a [`SecureChannel`]. Opaque: it owns the Double
/// Ratchet — nonce, counter, chain advance, skipped-key cache, and key zeroization
/// are all internal. The caller only ever seals and opens.
pub struct OlmChannel {
    session: Session,
}

impl OlmChannel {
    /// A stable id derived from both ends' identity keys — equal on the two legs of
    /// one session, distinct across peers. Binds a ciphertext to its pair.
    pub fn session_id(&self) -> String {
        self.session.session_id()
    }

    /// Snapshot the full session state — the in-memory equivalent of a device
    /// compromise. The post-compromise property is that a snapshot taken before a
    /// ratchet step cannot open traffic sealed after it.
    pub fn snapshot(&self) -> OlmChannel {
        OlmChannel {
            session: Session::from_pickle(self.session.pickle()),
        }
    }

    /// Serialize the session encrypted under a storage key (the pickle key, held in
    /// the Keychain wrapped by the Secure Enclave). This is how a session survives
    /// app restarts without ever writing key bytes in the clear.
    pub fn to_encrypted_pickle(&self, pickle_key: &[u8; 32]) -> String {
        self.session.pickle().encrypt(pickle_key)
    }

    /// Restore a session from its encrypted pickle.
    pub fn from_encrypted_pickle(blob: &str, pickle_key: &[u8; 32]) -> CoreResult<OlmChannel> {
        let pickle = SessionPickle::from_encrypted(blob, pickle_key)
            .map_err(|_| CoreError::Rejected("session pickle could not be decrypted"))?;
        Ok(OlmChannel {
            session: Session::from_pickle(pickle),
        })
    }
}

impl SecureChannel for OlmChannel {
    fn encrypt(&mut self, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let message = self
            .session
            .encrypt(plaintext)
            .map_err(|_| CoreError::Rejected("Olm encryption failed"))?;
        Ok(encode_wire(&message))
    }

    fn decrypt(&mut self, wire: &[u8]) -> CoreResult<Vec<u8>> {
        let message = decode_wire(wire)?;
        // Uniform error on any failure — tamper, wrong session, and replay all
        // surface the same rejection, so there is no decryption oracle.
        self.session
            .decrypt(&message)
            .map_err(|_| CoreError::Rejected("Olm decryption failed"))
    }
}

/// Wire form of an Olm message: a one-byte message-type tag followed by the
/// ciphertext, ready to ride in an `OuterEnvelope.ciphertext`.
fn encode_wire(message: &OlmMessage) -> Vec<u8> {
    let (message_type, ciphertext) = message.to_parts();
    let mut wire = Vec::with_capacity(1 + ciphertext.len());
    // message_type is 0 (prekey) or 1 (normal) — always one byte.
    wire.push(message_type as u8);
    wire.extend_from_slice(&ciphertext);
    wire
}

fn decode_wire(wire: &[u8]) -> CoreResult<OlmMessage> {
    let (tag, ciphertext) = wire
        .split_first()
        .ok_or(CoreError::Rejected("empty Olm wire message"))?;
    OlmMessage::from_parts(*tag as usize, ciphertext)
        .map_err(|_| CoreError::Rejected("malformed Olm wire message"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32]).unwrap()
    }

    /// Stand up a verified outbound session from Alice to Bob through the full join:
    /// Bob publishes a KERI-signed bundle, Alice resolves+verifies it, both ends
    /// hold a channel. Returns (alice endpoint, alice→bob channel, bob endpoint).
    fn joined() -> (OlmIdentity, OlmChannel, OlmIdentity, Vec<u8>) {
        let alice = OlmIdentity::new(identity(1));
        let mut bob = OlmIdentity::new(identity(2));
        let bundle = bob.publish_bundle().unwrap();
        // Alice resolves Bob's AID → current KERI key (here: Bob's own public key)
        // and verifies the bundle is rooted in it.
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut alice_to_bob = alice.establish_outbound(&rooted).unwrap();
        let first = alice_to_bob.encrypt(b"hello bob").unwrap();
        (alice, alice_to_bob, bob, first)
    }

    #[test]
    fn join_round_trips_both_directions() {
        let (alice, mut a2b, mut bob, first) = joined();
        let (mut b2a, first_plain) =
            bob.establish_inbound(alice.olm_identity_key(), &first).unwrap();
        assert_eq!(first_plain, b"hello bob");
        // Reply path.
        let reply = b2a.encrypt(b"hi alice").unwrap();
        assert_eq!(a2b.decrypt(&reply).unwrap(), b"hi alice");
        // Same session on both ends.
        assert_eq!(a2b.session_id(), b2a.session_id());
    }

    #[test]
    fn forward_secrecy_a_consumed_message_does_not_reopen() {
        // Behavioral forward secrecy: once the receiver has opened a message, its
        // key is destroyed; re-presenting that exact ciphertext is rejected. A later
        // (compromised) receiver state cannot recover an earlier message's key.
        let (alice, _a2b, mut bob, first) = joined();
        let (mut b2a, _p) = bob.establish_inbound(alice.olm_identity_key(), &first).unwrap();
        // Need an established normal-message chain Alice→Bob; redo with a fresh pair
        // and drive several messages.
        let alice2 = OlmIdentity::new(identity(3));
        let mut bob2 = OlmIdentity::new(identity(4));
        let bundle = bob2.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob2.identity.public_key()).unwrap();
        let mut a = alice2.establish_outbound(&rooted).unwrap();
        let w0 = a.encrypt(b"m0").unwrap();
        let (mut b, p0) = bob2.establish_inbound(alice2.olm_identity_key(), &w0).unwrap();
        assert_eq!(p0, b"m0");
        let w1 = a.encrypt(b"m1").unwrap();
        let w2 = a.encrypt(b"m2").unwrap();
        assert_eq!(b.decrypt(&w1).unwrap(), b"m1");
        assert_eq!(b.decrypt(&w2).unwrap(), b"m2");
        assert!(
            b.decrypt(&w1).is_err(),
            "a consumed message must not open again (forward secrecy)"
        );
        // touch b2a so the first pair is exercised too
        let _ = b2a.encrypt(b"x").unwrap();
    }

    #[test]
    fn post_compromise_a_pre_step_snapshot_cannot_read_post_step_traffic() {
        // Compromise Bob right after he reads Alice's first message, then let the
        // conversation take a DH ratchet step (Bob replies → Alice replies → Bob
        // replies again, minting fresh ratchet entropy the snapshot never held).
        // The snapshot must fail to open the post-step traffic — the conversation
        // healed.
        let alice = OlmIdentity::new(identity(10));
        let mut bob = OlmIdentity::new(identity(11));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut a2b = alice.establish_outbound(&rooted).unwrap();

        let w0 = a2b.encrypt(b"m0").unwrap();
        let (mut b2a, _p0) = bob.establish_inbound(alice.olm_identity_key(), &w0).unwrap();

        // Attacker seizes Bob's full session state here.
        let mut attacker = b2a.snapshot();

        // Healing exchange: Bob replies (mints a new ratchet key), Alice consumes it
        // and replies, Bob consumes that. Now Bob's send chain is post-step.
        let r0 = b2a.encrypt(b"r0").unwrap();
        assert_eq!(a2b.decrypt(&r0).unwrap(), b"r0");
        let m1 = a2b.encrypt(b"m1").unwrap();
        assert_eq!(b2a.decrypt(&m1).unwrap(), b"m1");
        let r1 = b2a.encrypt(b"r1").unwrap();
        assert_eq!(a2b.decrypt(&r1).unwrap(), b"r1");

        // The legitimate, healed Bob can still read the latest Alice message.
        let m2 = a2b.encrypt(b"m2").unwrap();
        assert_eq!(b2a.decrypt(&m2).unwrap(), b"m2");

        // The pre-step snapshot cannot read the post-step Alice→Bob traffic.
        assert!(
            attacker.decrypt(&m2).is_err(),
            "a pre-ratchet-step snapshot must not open post-step traffic (post-compromise security)"
        );
    }

    #[test]
    fn join_rejects_a_bundle_signed_by_the_wrong_key() {
        let mut bob = OlmIdentity::new(identity(20));
        let bundle = bob.publish_bundle().unwrap();
        // A different key (Mallory's) is what the AID resolves to — verification must
        // reject, so no session is ever created against it.
        let mallory = identity(21);
        assert!(bundle.verify_rooted(mallory.public_key()).is_err());
    }

    #[test]
    fn join_rejects_a_tampered_bundle() {
        let mut bob = OlmIdentity::new(identity(30));
        let mut bundle = bob.publish_bundle().unwrap();
        bundle.olm_one_time_key[0] ^= 0x01; // flip a bit in the signed material
        assert!(bundle.verify_rooted(bob.identity.public_key()).is_err());
    }

    #[test]
    fn inbound_rejects_a_downgraded_v1_first_message() {
        // A peer that tries to start a truncated-MAC (v1) session must be rejected by
        // the v2-expecting inbound handshake — no silent downgrade.
        use vodozemac::olm::Account as RawAccount;
        let mut bob = OlmIdentity::new(identity(40));
        let bundle = bob.publish_bundle().unwrap();

        // A raw v1 initiator targeting Bob's published bundle.
        let attacker = RawAccount::new();
        let mut v1_session = attacker
            .create_outbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_bytes(bundle.olm_identity_key),
                Curve25519PublicKey::from_bytes(bundle.olm_one_time_key),
            )
            .unwrap();
        let v1_wire = encode_wire(&v1_session.encrypt(b"downgrade me").unwrap());

        let result = bob.establish_inbound(attacker.curve25519_key(), &v1_wire);
        assert!(result.is_err(), "a v1 (truncated-MAC) first message must be rejected");
    }

    #[test]
    fn relocating_a_ciphertext_to_a_different_session_fails() {
        // §7 reframe of relay relocation: a ciphertext for one pairwise session does
        // not open under any other session.
        let (alice, _a2b, mut bob, first) = joined();
        let (mut b2a, _p) = bob.establish_inbound(alice.olm_identity_key(), &first).unwrap();
        let from_bob = b2a.encrypt(b"for alice only").unwrap();

        // An unrelated third party's session cannot open Bob's reply.
        let carol = OlmIdentity::new(identity(50));
        let mut dave = OlmIdentity::new(identity(51));
        let cb = dave.publish_bundle().unwrap();
        let cr = cb.verify_rooted(dave.identity.public_key()).unwrap();
        let mut c2d = carol.establish_outbound(&cr).unwrap();
        let cw = c2d.encrypt(b"unrelated").unwrap();
        let (mut d2c, _pp) = dave.establish_inbound(carol.olm_identity_key(), &cw).unwrap();
        assert!(d2c.decrypt(&from_bob).is_err(), "cross-session decrypt must fail");
    }

    #[test]
    fn encrypted_pickle_round_trips_a_live_session() {
        let (alice, mut a2b, mut bob, first) = joined();
        let (mut b2a, _p) = bob.establish_inbound(alice.olm_identity_key(), &first).unwrap();
        let key = [0x42u8; 32];
        let blob = b2a.to_encrypted_pickle(&key);
        let mut restored = OlmChannel::from_encrypted_pickle(&blob, &key).unwrap();
        // The restored session continues the conversation.
        let reply = restored.encrypt(b"after restart").unwrap();
        assert_eq!(a2b.decrypt(&reply).unwrap(), b"after restart");
        // A wrong pickle key cannot restore it.
        assert!(OlmChannel::from_encrypted_pickle(&blob, &[0x00u8; 32]).is_err());
    }
}
