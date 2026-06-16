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
//!   AID's current key. The per-message inner signature (kept *above* this module)
//!   is what authenticates each message *as an AID*. Olm does not, and need not,
//!   know about AIDs. **This module does not itself bind the sender's Olm key to
//!   the sender's AID** (see [`OlmIdentity::establish_inbound`]); that binding is
//!   the caller's inner-signature contract and an explicit external-audit item.
//!
//! ## Curves
//! The AID signing key is Ed25519/P-256 (P-256 in the Secure Enclave on iOS); Olm
//! keys are Curve25519, software-held. The KERI key *signs* the Curve25519 bundle
//! — a signature over bytes that happen to contain a Curve25519 key, which is
//! standard. The cryptographic "messaging key ≠ AID signing key" guarantee is the
//! **signature**, not the byte-inequality assertion in [`OlmPrekeyBundle::verify_rooted`]
//! (which, across two different curves, can only ever catch a literal coincidence —
//! it is defense-in-depth, not the binding).
//!
//! ## MAC strength
//! Sessions use Olm **version 2** ([`SessionConfig::version_2`]) — the full,
//! untruncated MAC. The default version 1 truncates the MAC to 8 bytes, too short
//! for a greenfield messenger. The inbound handshake passes v2 as the *expected*
//! config, so a v1 (downgraded) peer is rejected, not silently accepted. A unit
//! test pins `session_config().version() == 2` so a future library bump cannot
//! silently fall back to the 8-byte MAC.

use hkdf::Hkdf;
use sha2::Sha256;
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, OlmMessage, Session, SessionConfig, SessionCreationError, SessionPickle,
};

use crate::address::Aid;
use crate::channel::SecureChannel;
use crate::identity::{Identity, verify_sender};
use crate::{CoreError, CoreResult};

/// Domain label for deriving a generation-bound pickle key (anti-rollback, R10).
const PICKLE_GENERATION_INFO: &[u8] = b"murmur/olm-pickle-generation/v1";

/// Derive a pickle key bound to a monotonic generation. A blob encrypted under
/// generation *g* decrypts only with the key derived for *g*, so an attacker who
/// swaps in an older blob (a different generation) cannot have it decrypt under the
/// generation the storage layer currently expects — the binding that makes
/// rollback detectable rather than silent.
fn generation_pickle_key(base: &[u8; 32], generation: u64) -> CoreResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&generation.to_le_bytes()), base);
    let mut out = [0u8; 32];
    // 32 bytes is far below HKDF's 255*HashLen output ceiling, so this only ever
    // errors on a contract violation; surface it fail-closed rather than panic.
    hk.expand(PICKLE_GENERATION_INFO, &mut out)
        .map_err(|_| CoreError::Malformed("pickle-generation key derivation failed".into()))?;
    Ok(out)
}

/// Domain-separating context the AID key signs over an Olm prekey bundle. Distinct
/// from the in-tree bundle context so a signature over one can never be replayed as
/// the other.
const OLM_BUNDLE_CONTEXT: &[u8] = b"murmur/olm-prekey-bundle/v1\n";

/// Full-MAC Olm. The whole engine pins one version; the inbound side requires it.
/// `session_config_is_v2_full_mac` asserts this stays version 2.
fn session_config() -> SessionConfig {
    SessionConfig::version_2()
}

/// The bytes the AID's current KERI key signs over an Olm prekey bundle: the
/// context, the AID, the Olm Curve25519 identity key, the one-time key, and the
/// fallback key. Binding all of them means none can be swapped after signing. The
/// three key fields are each a fixed 32 bytes and the only delimiter (`'\n'`)
/// follows the variable-length AID, so the encoding is injective.
fn olm_bundle_signing_bytes(
    aid: &Aid,
    identity_key: &[u8; 32],
    one_time_key: &[u8; 32],
    fallback_key: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OLM_BUNDLE_CONTEXT.len() + aid.as_str().len() + 96 + 1);
    bytes.extend_from_slice(OLM_BUNDLE_CONTEXT);
    bytes.extend_from_slice(aid.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(identity_key);
    bytes.extend_from_slice(one_time_key);
    bytes.extend_from_slice(fallback_key);
    bytes
}

/// A recipient's Olm prekey bundle, published for first contact: the recipient's
/// Olm Curve25519 identity key, a single-use one-time key, and a reusable fallback
/// key, signed by the recipient's AID current KERI key. The signature is what roots
/// the Olm session in the KERI identity — [`verify_rooted`] checks it before any
/// session is created.
///
/// [`verify_rooted`]: OlmPrekeyBundle::verify_rooted
#[derive(Debug, Clone)]
pub struct OlmPrekeyBundle {
    /// The AID this bundle claims to publish Olm keys for.
    pub aid: Aid,
    /// The recipient's Olm Curve25519 identity key (DISTINCT curve from the AID
    /// signing key).
    pub olm_identity_key: [u8; 32],
    /// A one-time key, consumed exactly once on the recipient's first inbound
    /// session from a given initiator. Single-use: full first-message forward
    /// secrecy.
    pub olm_one_time_key: [u8; 32],
    /// A reusable fallback key, used when the one-time key is already consumed (e.g.
    /// a second concurrent initiator, or before the recipient republishes). Reused
    /// across initiators → **weaker first-message forward secrecy** than the OTK
    /// until it is rotated; the established ratchet's forward secrecy is unaffected.
    pub olm_fallback_key: [u8; 32],
    /// The AID current-key signature over (context ‖ AID ‖ identity ‖ OTK ‖ fallback).
    pub signature: Vec<u8>,
}

impl OlmPrekeyBundle {
    /// Verify this bundle is rooted in the key the recipient AID resolves to, then
    /// hand back the verified material a session can run against. Fail-closed,
    /// mirroring the in-tree bundle:
    /// 1. key hygiene — the Olm identity key must not equal the AID signing-key
    ///    bytes. Across the two curves this can only catch a literal coincidence,
    ///    so it is **defense-in-depth, not the binding** — the binding is the
    ///    signature checked next.
    /// 2. the AID's current key signed *this* bundle, and that key derives the
    ///    claimed AID (both via [`verify_sender`], which checks signature and AID).
    ///
    /// There is no other constructor for [`OlmRootedBundle`], so a session can never
    /// be created against an unverified bundle.
    pub fn verify_rooted(&self, aid_current_key: &[u8]) -> CoreResult<OlmRootedBundle> {
        if self.olm_identity_key.as_slice() == aid_current_key {
            return Err(CoreError::Rejected(
                "key hygiene: the Olm identity key reuses the AID signing key (signing↔DH reuse)",
            ));
        }
        let signing_bytes = olm_bundle_signing_bytes(
            &self.aid,
            &self.olm_identity_key,
            &self.olm_one_time_key,
            &self.olm_fallback_key,
        );
        verify_sender(&self.aid, aid_current_key, &signing_bytes, &self.signature).map_err(
            |_| {
                CoreError::Rejected(
                    "Olm prekey bundle is not signed by the AID's current key — bundle rejected",
                )
            },
        )?;
        Ok(OlmRootedBundle {
            aid: self.aid.clone(),
            identity_key: Curve25519PublicKey::from_bytes(self.olm_identity_key),
            one_time_key: Curve25519PublicKey::from_bytes(self.olm_one_time_key),
            fallback_key: Curve25519PublicKey::from_bytes(self.olm_fallback_key),
        })
    }
}

/// An Olm prekey bundle that has been verified to belong to its AID — the
/// capability a session requires. No public constructor: the only way to hold one
/// is [`OlmPrekeyBundle::verify_rooted`].
#[derive(Debug, Clone)]
pub struct OlmRootedBundle {
    aid: Aid,
    identity_key: Curve25519PublicKey,
    one_time_key: Curve25519PublicKey,
    fallback_key: Curve25519PublicKey,
}

impl OlmRootedBundle {
    /// The AID this verified bundle belongs to.
    pub fn aid(&self) -> &Aid {
        &self.aid
    }
}

/// A local Olm endpoint: the long-term Olm account (identity + one-time + fallback
/// keys) wired to the KERI [`Identity`] that signs its bundles. The account holds
/// the Curve25519 secret material; the [`Identity`] holds the Ed25519/P-256 signing
/// key (in the apps, Secure-Enclave-held).
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

    /// Mint and publish an Olm prekey bundle: generate a one-time key and a fallback
    /// key, then sign (identity ‖ OTK ‖ fallback) with the AID's KERI key. Each call
    /// yields a fresh single-use OTK, so a recipient publishes one bundle per
    /// expected first-contact; the fallback covers the case where the OTK is already
    /// spent.
    ///
    /// Key hygiene is enforced here too — a bundle whose Olm identity key equalled
    /// the AID signing-key bytes is refused (it never can across curves, but we never
    /// emit one).
    pub fn publish_bundle(&mut self) -> CoreResult<OlmPrekeyBundle> {
        self.account.generate_one_time_keys(1);
        let one_time_key = *self
            .account
            .one_time_keys()
            .values()
            .next()
            .ok_or(CoreError::Rejected("no one-time key was generated"))?;
        self.account.generate_fallback_key();
        let fallback_key = *self
            .account
            .fallback_key()
            .values()
            .next()
            .ok_or(CoreError::Rejected("no fallback key was generated"))?;
        self.account.mark_keys_as_published();

        let id_bytes = self.account.curve25519_key().to_bytes();
        let otk_bytes = one_time_key.to_bytes();
        let fallback_bytes = fallback_key.to_bytes();
        if id_bytes.as_slice() == self.identity.public_key() {
            return Err(CoreError::Rejected(
                "key hygiene: the Olm identity key must be distinct from the AID signing key",
            ));
        }
        let signing_bytes =
            olm_bundle_signing_bytes(self.identity.aid(), &id_bytes, &otk_bytes, &fallback_bytes);
        let signature = self.identity.sign(&signing_bytes)?;
        Ok(OlmPrekeyBundle {
            aid: self.identity.aid().clone(),
            olm_identity_key: id_bytes,
            olm_one_time_key: otk_bytes,
            olm_fallback_key: fallback_bytes,
            signature,
        })
    }

    /// Initiator side of the join: create an outbound Olm session against a verified
    /// bundle's **single-use one-time key** (full first-message forward secrecy). The
    /// first message the returned channel seals is an Olm *prekey* message; the rest
    /// are normal.
    pub fn establish_outbound(&self, rooted: &OlmRootedBundle) -> CoreResult<OlmChannel> {
        self.outbound_with(rooted.identity_key, rooted.one_time_key)
    }

    /// Initiator side of the join when the one-time key is already spent: create an
    /// outbound session against the verified bundle's **reusable fallback key**.
    /// First-message forward secrecy is weaker (the fallback is shared across
    /// initiators until rotated); the established ratchet's forward secrecy is the
    /// same.
    pub fn establish_outbound_on_fallback(
        &self,
        rooted: &OlmRootedBundle,
    ) -> CoreResult<OlmChannel> {
        self.outbound_with(rooted.identity_key, rooted.fallback_key)
    }

    fn outbound_with(
        &self,
        identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> CoreResult<OlmChannel> {
        let session = self
            .account
            .create_outbound_session(session_config(), identity_key, one_time_key)
            .map_err(|_| {
                CoreError::Rejected(
                    "outbound Olm session could not be created (non-contributory key)",
                )
            })?;
        Ok(OlmChannel { session })
    }

    /// Responder side of the join: consume a one-time (or fallback) key to create the
    /// inbound Olm session from the sender's first (prekey) wire message, also
    /// yielding the first plaintext.
    ///
    /// **Contract (audit-critical):** `sender_olm_identity_key` MUST be the sender's
    /// Olm identity key as learned from the sender's *KERI-verified* bundle — never
    /// taken from the inbound message itself. Olm binds the channel to whatever key
    /// actually sent (a mismatched key is rejected), but it cannot prove that key
    /// belongs to the sender's AID; that proof is the per-message inner signature
    /// layer above this module. Until that layer is wired and mandatory, an inbound
    /// channel is authenticated-as-a-channel, not authenticated-as-an-AID.
    ///
    /// The session config is required to be v2 — a v1 (truncated-MAC, downgraded)
    /// first message is rejected here with a distinct error, not accepted.
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
            .map_err(map_inbound_error)?;
        Ok((
            OlmChannel {
                session: created.session,
            },
            created.plaintext,
        ))
    }
}

/// Map vodozemac's session-creation error to a distinct, actionable rejection, so a
/// caller can tell a spent one-time key (re-fetch / republish) apart from a downgrade
/// attempt or a key mismatch, instead of a single opaque failure.
fn map_inbound_error(error: SessionCreationError) -> CoreError {
    match error {
        SessionCreationError::MissingOneTimeKey(_) => CoreError::Rejected(
            "inbound Olm session: the one-time key is already consumed or unknown — \
             the recipient must republish a bundle (or the sender must use the fallback key)",
        ),
        SessionCreationError::MismatchedSessionConfig { .. } => CoreError::Rejected(
            "inbound Olm session: session-version mismatch — a downgraded (v1, truncated-MAC) \
             first message is rejected",
        ),
        SessionCreationError::MismatchedIdentityKey(_, _) => CoreError::Rejected(
            "inbound Olm session: the sender's Olm identity key does not match the prekey message",
        ),
        SessionCreationError::NonContributoryKey => CoreError::Rejected(
            "inbound Olm session: a non-contributory (low-order) key was supplied",
        ),
        SessionCreationError::Decryption(_) => {
            CoreError::Rejected("inbound Olm session: the prekey message could not be decrypted")
        }
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
    /// ratchet step cannot open traffic sealed after it; the forward-secrecy property
    /// is that a snapshot taken after advancing past a message cannot reopen it.
    pub fn snapshot(&self) -> OlmChannel {
        OlmChannel {
            session: Session::from_pickle(self.session.pickle()),
        }
    }

    /// Serialize the session encrypted under a storage key (the pickle key, held in
    /// the Keychain wrapped by the Secure Enclave). This is how a session survives
    /// app restarts without ever writing key bytes in the clear.
    ///
    /// **Anti-rollback is the caller's responsibility.** This blob carries no
    /// freshness/generation marker: [`from_encrypted_pickle`] will faithfully restore
    /// *any* valid blob produced under the key, including a stale one. An attacker who
    /// can substitute an older at-rest blob rolls the ratchet back and resurrects
    /// message keys the live session already destroyed — defeating forward secrecy on
    /// the *persistence* path. Callers MUST store the blob in rollback-protected
    /// storage (e.g. a monotonically versioned Keychain item) and reject a regression.
    /// Use a **distinct pickle key per stored session** — vodozemac's pickle
    /// encryption derives its AES-CBC IV from the key alone, so one key across many
    /// sessions reuses the IV (structural-prefix leak, not key recovery).
    ///
    /// [`from_encrypted_pickle`]: OlmChannel::from_encrypted_pickle
    pub fn to_encrypted_pickle(&self, pickle_key: &[u8; 32]) -> String {
        self.session.pickle().encrypt(pickle_key)
    }

    /// Restore a session from its encrypted pickle. See the anti-rollback contract on
    /// [`to_encrypted_pickle`](OlmChannel::to_encrypted_pickle): a stale-but-valid blob
    /// restores successfully, so freshness must be enforced by the storage layer.
    pub fn from_encrypted_pickle(blob: &str, pickle_key: &[u8; 32]) -> CoreResult<OlmChannel> {
        let pickle = SessionPickle::from_encrypted(blob, pickle_key)
            .map_err(|_| CoreError::Rejected("session pickle could not be decrypted"))?;
        Ok(OlmChannel {
            session: Session::from_pickle(pickle),
        })
    }

    /// Encrypt the session bound to a **monotonic generation** for anti-rollback
    /// (R10). The record is `"<generation>:<blob>"`, where the blob is encrypted
    /// under a key derived from `(pickle_key, generation)`. The storage layer
    /// increments the generation on every persist and keeps the last value in
    /// rollback-protected storage; [`from_versioned_pickle`] then rejects a
    /// stale-or-tampered generation. Editing the cleartext generation up does not
    /// help an attacker — the blob only decrypts under the key for the generation it
    /// was actually written with.
    ///
    /// [`from_versioned_pickle`]: OlmChannel::from_versioned_pickle
    pub fn to_versioned_pickle(
        &self,
        pickle_key: &[u8; 32],
        generation: u64,
    ) -> CoreResult<String> {
        let kg = generation_pickle_key(pickle_key, generation)?;
        let blob = self.session.pickle().encrypt(&kg);
        Ok(format!("{generation}:{blob}"))
    }

    /// Restore a generation-bound session, **rejecting a rollback**: a record whose
    /// generation is below `min_generation` (the last value the storage layer
    /// committed) is refused, and a record whose generation was tampered upward
    /// fails to decrypt (the key is bound to the generation). Returns the channel and
    /// its generation so the caller can advance `min_generation`.
    pub fn from_versioned_pickle(
        record: &str,
        pickle_key: &[u8; 32],
        min_generation: u64,
    ) -> CoreResult<(OlmChannel, u64)> {
        let (gen_str, blob) = record
            .split_once(':')
            .ok_or(CoreError::Rejected("malformed versioned session pickle"))?;
        let generation: u64 = gen_str
            .parse()
            .map_err(|_| CoreError::Rejected("malformed session pickle generation"))?;
        if generation < min_generation {
            return Err(CoreError::Rejected(
                "stale session pickle rejected (rollback to an earlier generation)",
            ));
        }
        let kg = generation_pickle_key(pickle_key, generation)?;
        let pickle = SessionPickle::from_encrypted(blob, &kg)
            .map_err(|_| CoreError::Rejected("session pickle could not be decrypted"))?;
        Ok((
            OlmChannel {
                session: Session::from_pickle(pickle),
            },
            generation,
        ))
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
    // message_type is 0 (prekey) or 1 (normal) — always one byte. The tag is outside
    // the Olm MAC, but a flipped tag is rejected by the inner version/protobuf shape.
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

    /// Stand up a verified outbound session from Alice to Bob through the full join.
    /// Returns (alice endpoint, alice→bob channel, bob endpoint, first prekey wire).
    fn joined() -> (OlmIdentity, OlmChannel, OlmIdentity, Vec<u8>) {
        let alice = OlmIdentity::new(identity(1));
        let mut bob = OlmIdentity::new(identity(2));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut alice_to_bob = alice.establish_outbound(&rooted).unwrap();
        let first = alice_to_bob.encrypt(b"hello bob").unwrap();
        (alice, alice_to_bob, bob, first)
    }

    #[test]
    fn session_config_is_v2_full_mac() {
        // Pin the MAC-strength decision: a future vodozemac bump must not silently
        // drop us back to the version-1 8-byte truncated MAC.
        assert_eq!(session_config().version(), 2);
    }

    #[test]
    fn join_round_trips_both_directions() {
        let (alice, mut a2b, mut bob, first) = joined();
        let (mut b2a, first_plain) = bob
            .establish_inbound(alice.olm_identity_key(), &first)
            .unwrap();
        assert_eq!(first_plain, b"hello bob");
        let reply = b2a.encrypt(b"hi alice").unwrap();
        assert_eq!(a2b.decrypt(&reply).unwrap(), b"hi alice");
        assert_eq!(a2b.session_id(), b2a.session_id());
    }

    #[test]
    fn forward_secrecy_a_later_state_cannot_reopen_an_earlier_message() {
        // Real forward secrecy (not just replay-rejection): take a DISTINCT later
        // state — a snapshot of the receiver after it has advanced past a message —
        // and prove that later state cannot reopen the earlier ciphertext. The key
        // was destroyed on consumption, so it is absent from the later state.
        let alice = OlmIdentity::new(identity(3));
        let mut bob = OlmIdentity::new(identity(4));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut a = alice.establish_outbound(&rooted).unwrap();
        let w0 = a.encrypt(b"m0").unwrap();
        let (mut b, p0) = bob
            .establish_inbound(alice.olm_identity_key(), &w0)
            .unwrap();
        assert_eq!(p0, b"m0");
        let w1 = a.encrypt(b"m1").unwrap();
        let w2 = a.encrypt(b"m2").unwrap();
        assert_eq!(b.decrypt(&w1).unwrap(), b"m1");
        assert_eq!(b.decrypt(&w2).unwrap(), b"m2");

        // The compromised LATER state, captured after advancing past m1/m2.
        let mut later_state = b.snapshot();
        assert!(
            later_state.decrypt(&w1).is_err(),
            "a later receiver state must not reopen an already-consumed earlier message"
        );
        // And the live receiver likewise rejects the replay.
        assert!(b.decrypt(&w1).is_err());
    }

    #[test]
    fn post_compromise_a_pre_step_snapshot_cannot_read_post_step_traffic() {
        // Compromise Bob right after he reads Alice's first message, then let the
        // conversation take a DH ratchet step. The snapshot must fail to open the
        // post-step traffic (healing), but — the positive control — must FIRST be
        // shown able to open pre-step traffic, or the test would pass vacuously if
        // `snapshot()` silently dropped state.
        let alice = OlmIdentity::new(identity(10));
        let mut bob = OlmIdentity::new(identity(11));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut a2b = alice.establish_outbound(&rooted).unwrap();

        let w0 = a2b.encrypt(b"m0").unwrap();
        let (mut b2a, _p0) = bob
            .establish_inbound(alice.olm_identity_key(), &w0)
            .unwrap();

        // Attacker seizes Bob's full session state here.
        let attacker = b2a.snapshot();

        // POSITIVE CONTROL: the snapshot is faithful — a sibling clone opens a
        // pre-step Alice→Bob message. (Done on a clone so `attacker` stays pristine.)
        let pre = a2b.encrypt(b"pre-step").unwrap();
        let mut control = attacker.snapshot();
        assert_eq!(
            control.decrypt(&pre).unwrap(),
            b"pre-step",
            "snapshot must be a faithful compromise (can read pre-step traffic)"
        );
        // Bob also consumes the pre-step message to stay in sync.
        assert_eq!(b2a.decrypt(&pre).unwrap(), b"pre-step");

        // Healing exchange: Bob replies (mints a new ratchet key), Alice consumes it
        // and replies; Alice's next message is on the post-step chain.
        let r0 = b2a.encrypt(b"r0").unwrap();
        assert_eq!(a2b.decrypt(&r0).unwrap(), b"r0");
        let post = a2b.encrypt(b"post-step").unwrap();
        assert_eq!(b2a.decrypt(&post).unwrap(), b"post-step");

        // The pre-step snapshot cannot read the post-step traffic — locked out.
        let mut attacker = attacker;
        assert!(
            attacker.decrypt(&post).is_err(),
            "a pre-ratchet-step snapshot must not open post-step traffic (post-compromise security)"
        );
    }

    #[test]
    fn one_time_key_is_single_use_and_fallback_recovers_first_contact() {
        // The OTK is consumed exactly once. A second initiator using the same bundle
        // (or an attacker who raced to burn the OTK) gets a DISTINCT, actionable
        // error — and can still establish via the fallback key.
        let alice1 = OlmIdentity::new(identity(60));
        let alice2 = OlmIdentity::new(identity(61));
        let mut bob = OlmIdentity::new(identity(62));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();

        // First initiator consumes the OTK.
        let mut a1 = alice1.establish_outbound(&rooted).unwrap();
        let w1 = a1.encrypt(b"from alice1").unwrap();
        let (_c1, p1) = bob
            .establish_inbound(alice1.olm_identity_key(), &w1)
            .unwrap();
        assert_eq!(p1, b"from alice1");

        // Second initiator reuses the OTK → rejected (consumed), with a message that
        // names the cause (not the generic catch-all).
        let mut a2 = alice2.establish_outbound(&rooted).unwrap();
        let w2 = a2.encrypt(b"from alice2").unwrap();
        // `match` rather than `unwrap_err` — the Ok variant carries OlmChannel, which
        // deliberately has no Debug (secret hygiene).
        match bob.establish_inbound(alice2.olm_identity_key(), &w2) {
            Ok(_) => panic!("a reused (consumed) one-time key must be rejected"),
            Err(CoreError::Rejected(msg)) => {
                assert!(
                    msg.contains("one-time key"),
                    "expected a one-time-key error, got: {msg}"
                )
            }
            Err(other) => panic!("expected Rejected, got {other:?}"),
        }

        // The fallback key recovers first contact for the second initiator.
        let mut a2f = alice2.establish_outbound_on_fallback(&rooted).unwrap();
        let w2f = a2f.encrypt(b"from alice2 via fallback").unwrap();
        let (_c2, p2) = bob
            .establish_inbound(alice2.olm_identity_key(), &w2f)
            .unwrap();
        assert_eq!(p2, b"from alice2 via fallback");
    }

    #[test]
    fn join_rejects_a_bundle_signed_by_the_wrong_key() {
        let mut bob = OlmIdentity::new(identity(20));
        let bundle = bob.publish_bundle().unwrap();
        let mallory = identity(21);
        assert!(bundle.verify_rooted(mallory.public_key()).is_err());
    }

    #[test]
    fn join_rejects_a_tampered_bundle() {
        let mut bob = OlmIdentity::new(identity(30));
        let mut bundle = bob.publish_bundle().unwrap();
        bundle.olm_one_time_key[0] ^= 0x01;
        assert!(bundle.verify_rooted(bob.identity.public_key()).is_err());
        // The fallback field is also covered by the signature.
        let mut bundle2 = bob.publish_bundle().unwrap();
        bundle2.olm_fallback_key[0] ^= 0x01;
        assert!(bundle2.verify_rooted(bob.identity.public_key()).is_err());
    }

    #[test]
    fn inbound_rejects_a_downgraded_v1_first_message() {
        use vodozemac::olm::Account as RawAccount;
        let mut bob = OlmIdentity::new(identity(40));
        let bundle = bob.publish_bundle().unwrap();
        let attacker = RawAccount::new();
        let mut v1_session = attacker
            .create_outbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_bytes(bundle.olm_identity_key),
                Curve25519PublicKey::from_bytes(bundle.olm_one_time_key),
            )
            .unwrap();
        let v1_wire = encode_wire(&v1_session.encrypt(b"downgrade me").unwrap());
        match bob.establish_inbound(attacker.curve25519_key(), &v1_wire) {
            Ok(_) => panic!("a v1 (truncated-MAC) first message must be rejected"),
            Err(CoreError::Rejected(msg)) => {
                assert!(
                    msg.contains("version"),
                    "expected a version/downgrade error, got: {msg}"
                )
            }
            Err(other) => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_message_ciphertext_is_rejected_by_the_mac() {
        // Flip a byte inside an established normal-message ciphertext (past the type
        // tag) and prove the full v2 MAC rejects it.
        let (alice, mut a2b, mut bob, first) = joined();
        let (mut b2a, _p) = bob
            .establish_inbound(alice.olm_identity_key(), &first)
            .unwrap();
        let reply = b2a.encrypt(b"genuine").unwrap();
        a2b.decrypt(&reply).unwrap();
        let next = b2a.encrypt(b"second genuine").unwrap();
        let mut tampered = next.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            a2b.decrypt(&tampered).is_err(),
            "a MAC-broken ciphertext must be rejected"
        );
    }

    #[test]
    fn relocating_a_ciphertext_to_a_different_session_fails() {
        let (alice, _a2b, mut bob, first) = joined();
        let (mut b2a, _p) = bob
            .establish_inbound(alice.olm_identity_key(), &first)
            .unwrap();
        let from_bob = b2a.encrypt(b"for alice only").unwrap();
        let carol = OlmIdentity::new(identity(50));
        let mut dave = OlmIdentity::new(identity(51));
        let cb = dave.publish_bundle().unwrap();
        let cr = cb.verify_rooted(dave.identity.public_key()).unwrap();
        let mut c2d = carol.establish_outbound(&cr).unwrap();
        let cw = c2d.encrypt(b"unrelated").unwrap();
        let (mut d2c, _pp) = dave
            .establish_inbound(carol.olm_identity_key(), &cw)
            .unwrap();
        assert!(
            d2c.decrypt(&from_bob).is_err(),
            "cross-session decrypt must fail"
        );
    }

    #[test]
    fn encrypted_pickle_round_trips_a_live_session() {
        let (alice, mut a2b, mut bob, first) = joined();
        let (b2a, _p) = bob
            .establish_inbound(alice.olm_identity_key(), &first)
            .unwrap();
        let key = [0x42u8; 32];
        let blob = b2a.to_encrypted_pickle(&key);
        let mut restored = OlmChannel::from_encrypted_pickle(&blob, &key).unwrap();
        let reply = restored.encrypt(b"after restart").unwrap();
        assert_eq!(a2b.decrypt(&reply).unwrap(), b"after restart");
        assert!(OlmChannel::from_encrypted_pickle(&blob, &[0x00u8; 32]).is_err());
    }

    #[test]
    fn versioned_pickle_rejects_rollback_and_tamper() {
        // R10: a generation-bound pickle lets the storage layer detect rollback.
        let (alice, mut a2b, mut bob, first) = joined();
        let (b2a, _p) = bob
            .establish_inbound(alice.olm_identity_key(), &first)
            .unwrap();
        let key = [0x55u8; 32];

        // Persist at generation 5; a fresh restore at the expected generation works.
        let record5 = b2a.to_versioned_pickle(&key, 5).unwrap();
        let (mut restored, g) = OlmChannel::from_versioned_pickle(&record5, &key, 5).unwrap();
        assert_eq!(g, 5);
        let reply = restored.encrypt(b"current").unwrap();
        assert_eq!(a2b.decrypt(&reply).unwrap(), b"current");

        // Rollback: an older blob (generation 3) presented when the layer has already
        // committed generation 5 is rejected.
        let record3 = b2a.to_versioned_pickle(&key, 3).unwrap();
        assert!(
            OlmChannel::from_versioned_pickle(&record3, &key, 5).is_err(),
            "a rolled-back (earlier-generation) pickle must be rejected"
        );

        // Tamper: editing the cleartext generation upward does not help — the key is
        // bound to the generation, so the blob no longer decrypts.
        let (_g5, blob5) = record5.split_once(':').unwrap();
        let forged = format!("9:{blob5}");
        assert!(
            OlmChannel::from_versioned_pickle(&forged, &key, 5).is_err(),
            "a generation-tampered pickle must fail to decrypt"
        );
    }

    #[test]
    fn out_of_order_messages_within_the_skip_window_decrypt() {
        // R12: Olm caches skipped message keys (default cap 40), so reordered delivery
        // within the window still decrypts. Beyond the cap, out-of-order messages are
        // dropped — a documented bound the relay must respect (best-effort ordering).
        let alice = OlmIdentity::new(identity(70));
        let mut bob = OlmIdentity::new(identity(71));
        let bundle = bob.publish_bundle().unwrap();
        let rooted = bundle.verify_rooted(bob.identity.public_key()).unwrap();
        let mut a = alice.establish_outbound(&rooted).unwrap();

        let w0 = a.encrypt(b"m0").unwrap();
        let (mut b, p0) = bob
            .establish_inbound(alice.olm_identity_key(), &w0)
            .unwrap();
        assert_eq!(p0, b"m0");

        let wires: Vec<Vec<u8>> = (1..6)
            .map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();
        // Deliver out of order: 4, 2, 0, 3, 1 (indices into wires → m5, m3, m1, m4, m2).
        for &i in &[4usize, 2, 0, 3, 1] {
            let expect = format!("m{}", i + 1);
            assert_eq!(b.decrypt(&wires[i]).unwrap(), expect.as_bytes());
        }
    }
}
