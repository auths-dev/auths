//! Establishing a pairwise session with a contact — the first-contact bootstrap
//! the app drives, with the MITM defense made explicit.
//!
//! The engine already has every primitive: a signed [`PrekeyBundle`], the
//! verify-then-agree [`x3dh_initiator`]/[`x3dh_responder`] join, the AEAD
//! [`Session`], and the authenticate-or-reject [`Endpoint`]. What was missing is the
//! thin layer that wires them into "I scanned Alice's contact code, fetched her
//! published bundle, and now hold a session I can seal to her" — *safely*, when the
//! directory the bundle came from is an **untrusted relay**.
//!
//! ## The first-contact MITM, and why this is safe
//! A relay that serves prekey bundles can try to serve *its own* keys for a victim
//! AID. The defense is that a Murmur AID is **self-certifying**: `Aid::from_public_key`
//! is `SHA256(signing_key)`, so the AID you scanned out-of-band is a *commitment* to
//! the real signing key. [`establish_initiator`] therefore rejects any published key
//! that does not hash to the **scanned** AID before it will run X3DH — a swapped key
//! (or a whole swapped bundle for a different AID) cannot pass. `verify_rooted` then
//! ties that key to the bundle's signature. The relay is reduced to a dumb pipe; it
//! cannot interpose.
//!
//! First contact is still **trust-on-first-use** in one respect this layer cannot fix:
//! nothing binds the AID to the human "Alice" except the channel that delivered the
//! code. In-person SAS pairing (`murmur-ffi::pairing`) is the only defense against
//! being handed the *wrong AID* to begin with; a pasted/linked AID must render as
//! unverified until that happens.
//!
//! ## Mailboxes are unlinkable to the AID
//! The relay must not be able to read the social graph off the mailbox ids. Each
//! direction's mailbox is a PRF of the **shared session secret** (which the relay
//! never sees), not of either AID — see [`mailbox_pair`]. Two directional mailboxes
//! keep a sender from draining its own messages.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::address::Aid;
use crate::prekey::{PrekeyBundle, PrekeySecrets, x3dh_initiator, x3dh_responder};
use crate::session::Session;
use crate::{
    ContactDirectory, CoreError, CoreResult, Endpoint, Identity, MailboxId, Message, OuterEnvelope,
};

/// Domain-separating labels for the two directional mailbox derivations.
const MAILBOX_TO_LOW: &[u8] = b"murmur/mailbox/v1/to-low";
const MAILBOX_TO_HIGH: &[u8] = b"murmur/mailbox/v1/to-high";

/// What the initiator hands the responder so the responder can complete X3DH and
/// authenticate the sender. It carries only **public** material — the sender's AID,
/// its signing public key (so the responder can bind the AID and verify the sender's
/// messages), and the two X3DH public keys. No secret crosses this struct.
///
/// In the app this travels as the first thing deposited for a new contact (alongside,
/// or just before, the first sealed message).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handshake {
    /// The sender's AID (self-certifying — committed to `sender_signing_key`).
    pub sender_aid: Aid,
    /// The sender's KERI signing public key. The responder checks it derives
    /// `sender_aid` and admits it so [`Endpoint::open`] can authenticate the sender.
    pub sender_signing_key: Vec<u8>,
    /// The sender's X3DH Signal-identity public key.
    pub sender_x3dh_identity: [u8; 32],
    /// The sender's per-session X3DH ephemeral public key.
    pub sender_ephemeral: [u8; 32],
}

/// A live pairwise session with one contact: the authenticated/sealing [`Endpoint`],
/// the directory that resolves the peer's key, and the two directional mailbox ids.
/// `seal` produces an envelope the app deposits; `open` authenticates a drained one.
pub struct ContactSession {
    endpoint: Endpoint,
    directory: ContactDirectory,
    /// Where THIS side deposits (the peer drains it).
    deposit_mailbox: MailboxId,
    /// Where THIS side drains (the peer deposits here).
    drain_mailbox: MailboxId,
}

impl ContactSession {
    /// Seal `body` for the peer, addressed to this session's deposit mailbox. The
    /// returned envelope is what the app `POST`s to the relay's `/deposit`.
    pub fn seal(&self, body: &str) -> CoreResult<OuterEnvelope> {
        self.endpoint
            .seal_to(self.endpoint.peer(), &self.deposit_mailbox, body)
    }

    /// Seal `body` with explicit end-to-end metadata (a stable `message_id` for recipient
    /// dedup/receipts, a `content_type`, and `flags`) — all signed and sealed.
    pub fn seal_with(
        &self,
        body: &str,
        message_id: Vec<u8>,
        content_type: &str,
        flags: u32,
    ) -> CoreResult<OuterEnvelope> {
        self.endpoint.seal_to_with(
            self.endpoint.peer(),
            &self.deposit_mailbox,
            body,
            message_id,
            content_type,
            flags,
        )
    }

    /// Open an envelope drained from this session's drain mailbox — AEAD-decrypt and
    /// **authenticate** the sender, or reject. Never returns unverified plaintext: the
    /// whole authenticate-or-reject contract is [`Endpoint::open`]'s, projected here.
    pub fn open(&self, envelope: &OuterEnvelope) -> CoreResult<Message> {
        self.endpoint.open(envelope, &self.directory)
    }

    /// The mailbox id this side deposits under (the peer drains it).
    pub fn deposit_mailbox(&self) -> &str {
        self.deposit_mailbox.as_str()
    }

    /// The mailbox id this side drains (the peer deposits here).
    pub fn drain_mailbox(&self) -> &str {
        self.drain_mailbox.as_str()
    }

    /// The peer this session is with.
    pub fn peer(&self) -> &Aid {
        self.endpoint.peer()
    }
}

/// Derive the two directional mailbox ids from the shared session secret. Both sides
/// compute the identical pair; which one each *deposits to* vs *drains* is decided by
/// the lexical order of the two AIDs (used only locally — it never enters the mailbox
/// value, so the ids stay unlinkable to either AID). Returns `(deposit, drain)` from
/// the perspective of `my_aid`.
fn mailbox_pair(
    session: &Session,
    my_aid: &Aid,
    peer_aid: &Aid,
) -> CoreResult<(MailboxId, MailboxId)> {
    let to_low = derive_mailbox(session, MAILBOX_TO_LOW)?;
    let to_high = derive_mailbox(session, MAILBOX_TO_HIGH)?;
    // The lexically-smaller AID is "low". Messages addressed to the low party land in
    // `to_low`; to the high party in `to_high`. I deposit to my peer; I drain my own.
    if my_aid.as_str() < peer_aid.as_str() {
        // I am low: I drain `to_low` (addressed to me), deposit `to_high` (to peer).
        Ok((to_high, to_low))
    } else {
        // I am high (or equal — note-to-self): deposit `to_low`, drain `to_high`.
        Ok((to_low, to_high))
    }
}

/// HKDF-SHA256 a 16-byte mailbox tag out of the session secret under `label`, hex it,
/// and prefix `mbx-`. The relay never sees the session secret, so it cannot invert
/// this to the secret or correlate it to an AID.
fn derive_mailbox(session: &Session, label: &[u8]) -> CoreResult<MailboxId> {
    let hk = Hkdf::<Sha256>::new(None, session.secret_bytes());
    let mut tag = [0u8; 16];
    hk.expand(label, &mut tag)
        .map_err(|_| CoreError::Malformed("mailbox derivation failed".into()))?;
    let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    Ok(MailboxId::new(format!("mbx-{hex}")))
}

/// Establish a session as the **initiator** (the one who scanned the contact code).
///
/// `scanned_peer_aid` is the AID obtained out-of-band (the contact code) — it is the
/// trust anchor. `peer_signing_key` and `peer_bundle` come from the (untrusted) relay
/// directory. Returns the live session plus the [`Handshake`] to deposit so the peer
/// can establish the matching side.
///
/// Fails closed if `peer_signing_key` does not derive `scanned_peer_aid` (sec: the
/// relay tried to swap keys) or if the bundle is not validly signed by it.
pub fn establish_initiator(
    my_identity: &Identity,
    my_x3dh_identity_seed: [u8; 32],
    my_x3dh_ephemeral_seed: [u8; 32],
    scanned_peer_aid: &Aid,
    peer_signing_key: &[u8],
    peer_bundle: &PrekeyBundle,
) -> CoreResult<(ContactSession, Handshake)> {
    // The published signing key MUST derive the AID we scanned out-of-band. This is
    // the whole first-contact MITM defense: a relay that substitutes its own key (or a
    // valid bundle for a different AID) breaks this equality and is rejected before any
    // key agreement runs.
    if Aid::from_public_key(peer_signing_key) != *scanned_peer_aid {
        return Err(CoreError::Rejected(
            "first contact: published key does not derive the scanned AID (possible relay MITM)",
        ));
    }
    // Verify-then-agree: this ties `peer_signing_key` to the bundle's signature; X3DH
    // is unreachable without it (the type system enforces it via `RootedBundle`).
    let rooted = peer_bundle.verify_rooted(peer_signing_key)?;

    let my_id_secret = X25519Secret::from(my_x3dh_identity_seed);
    let my_eph_secret = X25519Secret::from(my_x3dh_ephemeral_seed);
    let session = x3dh_initiator(&my_id_secret, &my_eph_secret, &rooted)?;
    let (deposit_mailbox, drain_mailbox) =
        mailbox_pair(&session, my_identity.aid(), scanned_peer_aid)?;

    let endpoint = Endpoint::new(my_identity.clone(), scanned_peer_aid.clone(), session);
    let mut directory = ContactDirectory::new();
    directory.admit(scanned_peer_aid.clone(), peer_signing_key.to_vec());

    let handshake = Handshake {
        sender_aid: my_identity.aid().clone(),
        sender_signing_key: my_identity.public_key().to_vec(),
        sender_x3dh_identity: X25519Public::from(&my_id_secret).to_bytes(),
        sender_ephemeral: X25519Public::from(&my_eph_secret).to_bytes(),
    };

    Ok((
        ContactSession {
            endpoint,
            directory,
            deposit_mailbox,
            drain_mailbox,
        },
        handshake,
    ))
}

/// Establish the matching session as the **responder**, from a drained [`Handshake`].
///
/// The two prekey seeds MUST be the ones whose public keys this party published in its
/// bundle (otherwise the X3DH roots will not agree). Fails closed if the handshake's
/// signing key does not derive the claimed sender AID — so a forged `from` cannot be
/// admitted into the directory.
pub fn establish_responder(
    my_identity: &Identity,
    my_x3dh_identity_seed: [u8; 32],
    my_x3dh_signed_prekey_seed: [u8; 32],
    handshake: &Handshake,
) -> CoreResult<ContactSession> {
    // The sender's claimed signing key must derive the AID it claims. A stranger's
    // first message is only as trustworthy as this self-consistency; the app then shows
    // it as an unverified Request (TOFU), never a verified contact.
    if Aid::from_public_key(&handshake.sender_signing_key) != handshake.sender_aid {
        return Err(CoreError::Rejected(
            "first contact: sender key does not derive the claimed sender AID",
        ));
    }
    let my_prekeys = PrekeySecrets::from_seeds(my_x3dh_identity_seed, my_x3dh_signed_prekey_seed);
    let session = x3dh_responder(
        &my_prekeys,
        handshake.sender_x3dh_identity,
        handshake.sender_ephemeral,
    )?;
    let (deposit_mailbox, drain_mailbox) =
        mailbox_pair(&session, my_identity.aid(), &handshake.sender_aid)?;

    let endpoint = Endpoint::new(my_identity.clone(), handshake.sender_aid.clone(), session);
    let mut directory = ContactDirectory::new();
    directory.admit(
        handshake.sender_aid.clone(),
        handshake.sender_signing_key.clone(),
    );

    Ok(ContactSession {
        endpoint,
        directory,
        deposit_mailbox,
        drain_mailbox,
    })
}

// ── Single-seed convenience: a device persists ONE identity seed ───────────────
// The X3DH prekey seeds are derived from it (domain-separated, distinct from the
// Ed25519 signing key), so the FFI and the app carry one secret, not three. These
// wrap the explicit-seed functions above so the crypto stays in one place.

/// Derive a 32-byte sub-secret from the device seed under a domain label.
fn derive32(seed: &[u8; 32], info: &[u8]) -> CoreResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Malformed("x3dh seed derivation failed".into()))?;
    Ok(out)
}

/// The (Signal-identity, signed-prekey) X3DH seeds for a device identity seed.
fn x3dh_seeds(identity_seed: &[u8; 32]) -> CoreResult<([u8; 32], [u8; 32])> {
    Ok((
        derive32(identity_seed, b"murmur/x3dh/identity/v1")?,
        derive32(identity_seed, b"murmur/x3dh/signed-prekey/v1")?,
    ))
}

/// Publish a prekey bundle from a single device identity seed. Returns the device
/// [`Identity`] (so the caller can read its AID + signing key) and the signed bundle.
pub fn publish_bundle_seeded(identity_seed: [u8; 32]) -> CoreResult<(Identity, PrekeyBundle)> {
    let identity = Identity::from_seed(identity_seed)?;
    let (x_id, x_pk) = x3dh_seeds(&identity_seed)?;
    let secrets = PrekeySecrets::from_seeds(x_id, x_pk);
    let bundle = PrekeyBundle::publish(&identity, &secrets)?;
    Ok((identity, bundle))
}

/// [`establish_initiator`] from a single device seed (deriving the X3DH identity).
pub fn establish_initiator_seeded(
    identity_seed: [u8; 32],
    ephemeral_seed: [u8; 32],
    scanned_peer_aid: &Aid,
    peer_signing_key: &[u8],
    peer_bundle: &PrekeyBundle,
) -> CoreResult<(ContactSession, Handshake)> {
    let identity = Identity::from_seed(identity_seed)?;
    let (x_id, _x_pk) = x3dh_seeds(&identity_seed)?;
    establish_initiator(
        &identity,
        x_id,
        ephemeral_seed,
        scanned_peer_aid,
        peer_signing_key,
        peer_bundle,
    )
}

/// [`establish_responder`] from a single device seed (deriving the X3DH prekeys —
/// the same seeds [`publish_bundle_seeded`] used, so the agreement matches).
pub fn establish_responder_seeded(
    identity_seed: [u8; 32],
    handshake: &Handshake,
) -> CoreResult<ContactSession> {
    let identity = Identity::from_seed(identity_seed)?;
    let (x_id, x_pk) = x3dh_seeds(&identity_seed)?;
    establish_responder(&identity, x_id, x_pk, handshake)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MailboxStore;
    use crate::prekey::PrekeyBundle;

    /// A recipient: an identity plus the X3DH prekey seeds it publishes a bundle from.
    struct Party {
        identity: Identity,
        x3dh_identity_seed: [u8; 32],
        x3dh_prekey_seed: [u8; 32],
    }

    impl Party {
        fn new(id_byte: u8, x_id: u8, x_pk: u8) -> Self {
            Party {
                identity: Identity::from_seed([id_byte; 32]).unwrap(),
                x3dh_identity_seed: [x_id; 32],
                x3dh_prekey_seed: [x_pk; 32],
            }
        }
        fn bundle(&self) -> PrekeyBundle {
            let secrets = PrekeySecrets::from_seeds(self.x3dh_identity_seed, self.x3dh_prekey_seed);
            PrekeyBundle::publish(&self.identity, &secrets).unwrap()
        }
        fn signing_key(&self) -> Vec<u8> {
            self.identity.public_key().to_vec()
        }
    }

    /// Alice scans Bob's code, fetches his published bundle, establishes, and the two
    /// exchange an authenticated message each way — over a real `MailboxStore`, with
    /// each side draining only the other's deposits.
    #[test]
    fn first_contact_round_trips_both_directions() {
        let alice = Party::new(1, 11, 12);
        let bob = Party::new(2, 21, 22);
        let mut relay = MailboxStore::new();

        // Alice establishes against Bob's published bundle (scanned AID = bob's real AID).
        let (alice_session, handshake) = establish_initiator(
            &alice.identity,
            alice.x3dh_identity_seed,
            [99u8; 32], // fresh ephemeral
            bob.identity.aid(),
            &bob.signing_key(),
            &bob.bundle(),
        )
        .unwrap();

        // Bob establishes the matching side from Alice's handshake.
        let bob_session = establish_responder(
            &bob.identity,
            bob.x3dh_identity_seed,
            bob.x3dh_prekey_seed,
            &handshake,
        )
        .unwrap();

        // The directional mailboxes line up: Alice deposits where Bob drains.
        assert_eq!(alice_session.deposit_mailbox(), bob_session.drain_mailbox());
        assert_eq!(bob_session.deposit_mailbox(), alice_session.drain_mailbox());

        // Alice → Bob.
        let env = alice_session.seal("hi bob, it's alice").unwrap();
        assert_eq!(relay.deposit(&env), crate::DepositOutcome::Queued);
        let drained = relay.handle(&crate::RelayRequest::Drain(MailboxId::new(
            bob_session.drain_mailbox(),
        )));
        assert_eq!(drained.len(), 1);
        let msg = bob_session.open(&drained[0]).unwrap();
        assert_eq!(msg.body, "hi bob, it's alice");
        assert_eq!(msg.from, *alice.identity.aid());

        // Bob → Alice.
        let reply = bob_session.seal("hey alice").unwrap();
        assert_eq!(relay.deposit(&reply), crate::DepositOutcome::Queued);
        let drained = relay.handle(&crate::RelayRequest::Drain(MailboxId::new(
            alice_session.drain_mailbox(),
        )));
        assert_eq!(drained.len(), 1);
        let msg = alice_session.open(&drained[0]).unwrap();
        assert_eq!(msg.body, "hey alice");
        assert_eq!(msg.from, *bob.identity.aid());
    }

    /// A relay that serves a bundle under the WRONG key for the scanned AID is rejected
    /// before any session is formed — the first-contact MITM defense.
    #[test]
    fn a_swapped_bundle_for_the_scanned_aid_is_rejected() {
        let alice = Party::new(1, 11, 12);
        let bob = Party::new(2, 21, 22);
        let mallory = Party::new(9, 91, 92);

        // The relay tries to pass Mallory's key + bundle while Alice scanned BOB's AID.
        let attempt = establish_initiator(
            &alice.identity,
            alice.x3dh_identity_seed,
            [99u8; 32],
            bob.identity.aid(),     // Alice believes she's reaching Bob
            &mallory.signing_key(), // relay-substituted key
            &mallory.bundle(),      // relay-substituted bundle
        );
        assert!(
            matches!(attempt, Err(CoreError::Rejected(_))),
            "a key that does not derive the scanned AID must be rejected"
        );
    }

    /// The responder rejects a handshake whose signing key does not derive the claimed
    /// sender AID (a forged `from`).
    #[test]
    fn a_forged_sender_aid_in_a_handshake_is_rejected() {
        let bob = Party::new(2, 21, 22);
        let mut handshake = Handshake {
            sender_aid: Aid::new("did:keri:Esomeone-else"),
            sender_signing_key: Identity::from_seed([5u8; 32])
                .unwrap()
                .public_key()
                .to_vec(),
            sender_x3dh_identity: [1u8; 32],
            sender_ephemeral: [2u8; 32],
        };
        // The signing key derives some AID, but not the one claimed.
        handshake.sender_aid = Aid::new("did:keri:Enot-the-key-digest");
        let attempt = establish_responder(
            &bob.identity,
            bob.x3dh_identity_seed,
            bob.x3dh_prekey_seed,
            &handshake,
        );
        assert!(matches!(attempt, Err(CoreError::Rejected(_))));
    }

    /// The single-seed wrappers agree a session end-to-end: a device persists one
    /// seed, publishes from it, and both sides exchange an authenticated message.
    #[test]
    fn seeded_wrappers_round_trip() {
        let alice_seed = [3u8; 32];
        let bob_seed = [4u8; 32];
        let alice_aid = Identity::from_seed(alice_seed).unwrap().aid().clone();
        let mut relay = MailboxStore::new();

        // Bob publishes from his single seed; Alice establishes against his bundle.
        let (bob_identity, bob_bundle) = publish_bundle_seeded(bob_seed).unwrap();
        let (alice_session, handshake) = establish_initiator_seeded(
            alice_seed,
            [77u8; 32],
            bob_identity.aid(),
            bob_identity.public_key(),
            &bob_bundle,
        )
        .unwrap();
        let bob_session = establish_responder_seeded(bob_seed, &handshake).unwrap();

        // Alice → Bob, authenticated as Alice.
        let env = alice_session.seal("seeded hello").unwrap();
        relay.deposit(&env);
        let drained = relay.handle(&crate::RelayRequest::Drain(MailboxId::new(
            bob_session.drain_mailbox(),
        )));
        assert_eq!(drained.len(), 1);
        let msg = bob_session.open(&drained[0]).unwrap();
        assert_eq!(msg.body, "seeded hello");
        assert_eq!(msg.from, alice_aid);
    }

    /// The mailbox ids leak neither AID — they are a PRF of the shared secret.
    #[test]
    fn mailbox_ids_are_unlinkable_to_the_aid() {
        let alice = Party::new(1, 11, 12);
        let bob = Party::new(2, 21, 22);
        let (session, _handshake) = establish_initiator(
            &alice.identity,
            alice.x3dh_identity_seed,
            [99u8; 32],
            bob.identity.aid(),
            &bob.signing_key(),
            &bob.bundle(),
        )
        .unwrap();
        // The AID digests must not appear inside the mailbox ids.
        let alice_hex = alice
            .identity
            .aid()
            .as_str()
            .trim_start_matches("did:keri:");
        let bob_hex = bob.identity.aid().as_str().trim_start_matches("did:keri:");
        for mbx in [session.deposit_mailbox(), session.drain_mailbox()] {
            assert!(!mbx.contains(alice_hex), "mailbox leaks the sender AID");
            assert!(!mbx.contains(bob_hex), "mailbox leaks the recipient AID");
        }
    }
}
