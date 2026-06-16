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
//!     real sender AID, authenticated by a signature checked against the key the
//!     AID resolves to, wrapping the message body.
//!
//! ## The end-to-end leg
//!
//! An [`Endpoint`] is one side of a conversation: a local [`identity::Identity`]
//! (the signing key the AID is derived from) plus a [`session::Session`] (the
//! shared secret the AEAD keys off). The whole flagship gesture — *send from the
//! Mac, watch it arrive verified on the phone* — is:
//!
//! ```text
//!   alice.seal_to(bob_aid, "hi")  ──▶  OuterEnvelope (mailbox id + opaque bytes)
//!        │                                        │
//!        └── store ──▶ MailboxStore (the relay) ──┘
//!                                  │ drain
//!   bob.open(env, &directory)  ◀───┘   verify signature → authenticated Message
//! ```
//!
//! The relay (`MailboxStore`) only ever touches the outer envelope, so it sees
//! neither the plaintext nor the sender AID. `open` surfaces a message only once
//! its signature verifies under the key the sender's AID resolves to — so a
//! message that *arrived* but did not *authenticate* is rejected, never shown.
//!
//! ## What is real here and what is later work
//!
//! The signing (Ed25519), the AEAD (ChaCha20-Poly1305), and the KDF
//! (HKDF-SHA256) are the real, audited constructions. Deliberately *not* here
//! yet, each its own later feature: the full KERI key-log replay that turns a
//! resolved key into a *witnessed* one with pre-rotation continuity; the X3DH
//! key agreement and forward-secret Double Ratchet that *derive* the session
//! secret instead of establishing it out-of-band; the delegated-device and
//! revocation chain. The seams are named so each lands as a real feature, never
//! a stub that pretends.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod address;
pub mod channel;
pub mod corroboration;
pub mod delegation;
pub mod dh_ratchet;
pub mod envelope;
pub mod identity;
pub mod kel;
pub mod leakcheck;
pub mod number_free;
#[cfg(feature = "olm")]
pub mod olm_backend;
pub mod prekey;
pub mod ratchet;
pub mod relay;
pub mod rotation;
pub mod session;
pub mod trust;
pub mod vetted;

pub use address::Aid;
pub use channel::SecureChannel;
pub use corroboration::{CorroboratedState, Provenance, RevocationResolution, provenance_token};
pub use delegation::{DelegatedDevice, DelegationAnchor, DelegationState, DeviceRevocation};
pub use dh_ratchet::{DhRatchet, DhStep};
pub use envelope::{InnerEnvelope, OuterEnvelope};
pub use identity::{Identity, verify_sender};
pub use kel::{Kel, KelEvent, WitnessPolicy, WitnessReceipt};
pub use leakcheck::{RoutingOnlyReport, prove_routing_only, relay_visible_bytes};
pub use number_free::{NumberFreeReport, prove_number_free};
#[cfg(feature = "olm")]
pub use olm_backend::{OlmChannel, OlmIdentity, OlmPrekeyBundle, OlmRootedBundle};
pub use prekey::{PrekeyBundle, PrekeySecrets, RootedBundle, x3dh_initiator, x3dh_responder};
pub use ratchet::Ratchet;
pub use relay::{DepositOutcome, MailboxId, MailboxStore, RelayLimits, RelayRequest};
pub use rotation::{
    KeyState, RotationRekeyReceipt, compute_next_commitment, verified_rotation_rekey,
    verify_continuation,
};
pub use session::Session;
pub use trust::{TrustState, TrustVerdict};
pub use vetted::{OneTimePrekeyJar, VettedReport, prove_vetted};

/// The crate's error type. `NotBuilt` names a seam that is specified but not yet
/// wired, so a caller — and a probe — can tell "absent" apart from "broke".
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
/// plaintext in, an addressed [`OuterEnvelope`] out. No phone number or email
/// appears anywhere in this type — the address is the AID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    /// The recipient's self-certifying address.
    pub to: Aid,
    /// The sender's self-certifying address (authenticated, never asserted).
    pub from: Aid,
    /// The cleartext the user typed. Never leaves the device in the clear.
    pub body: String,
}

/// Resolve an AID to the public key that controls it. In the full engine this is
/// a witnessed KEL replay (`replay_with_receipts`); here, a directory built from
/// the AIDs of the endpoints in a conversation. A resolver that cannot place an
/// AID returns `None`, and `open` then rejects the message rather than guessing.
pub trait Directory {
    /// The controlling public key for `aid`, or `None` if unknown.
    fn resolve(&self, aid: &Aid) -> Option<Vec<u8>>;
}

/// A trivial in-memory directory: a list of known `(AID, public key)` bindings.
/// The hermetic round-trip and the relay self-test resolve against this; a real
/// deployment resolves against witnesses.
#[derive(Debug, Default, Clone)]
pub struct ContactDirectory {
    entries: Vec<(Aid, Vec<u8>)>,
}

impl ContactDirectory {
    /// An empty directory.
    pub fn new() -> Self {
        ContactDirectory::default()
    }

    /// Admit a contact's AID ↔ public key binding (the "admit your AID" step of
    /// opt-in contact, §8). The binding is checked at use: a key that does not
    /// derive the claimed AID never authenticates a message.
    pub fn admit(&mut self, aid: Aid, public_key: Vec<u8>) {
        self.entries.push((aid, public_key));
    }
}

impl Directory for ContactDirectory {
    fn resolve(&self, aid: &Aid) -> Option<Vec<u8>> {
        self.entries
            .iter()
            .find(|(a, _)| a == aid)
            .map(|(_, pk)| pk.clone())
    }
}

/// Domain-separating prefix for the AEAD AAD, so the routing/identity context an
/// envelope is bound to can never collide with another protocol's AAD derived off
/// the same bytes.
const AEAD_AAD_CONTEXT: &[u8] = b"murmur/aead-aad/v1\n";

/// Build the AEAD additional-authenticated-data binding the full pairwise routing
/// and identity context — `sender_aid ‖ recipient_aid ‖ mailbox_id` — so a sealed
/// ciphertext validates only under the exact (sender, recipient, mailbox) it was
/// sealed for.
///
/// **Defense-in-depth, honestly scoped (H4).** Content forgery is already
/// prevented by the inner signature, which binds `sender ‖ recipient ‖ body` and
/// is verified in [`Endpoint::open`] before any body surfaces. Binding the same
/// context into the AEAD AAD additionally hardens *relocation*: an attacker who
/// holds the session secret cannot unseal a ciphertext for one (sender, recipient,
/// mailbox) and re-seal it under another without the recipient's AAD differing and
/// the tag failing. Both sides reconstruct this AAD from data they each hold (the
/// recipient knows its own AID and the peer it shares the pairwise session with),
/// so the binding is symmetric.
pub(crate) fn aead_aad(sender: &Aid, recipient: &Aid, mailbox: &MailboxId) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(AEAD_AAD_CONTEXT);
    aad.extend_from_slice(sender.as_str().as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(recipient.as_str().as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(mailbox.as_str().as_bytes());
    aad
}

/// One side of a conversation: a local identity, the AID of the peer the pairwise
/// session is shared with, and that session. The endpoint seals outgoing messages
/// and opens incoming ones.
pub struct Endpoint {
    identity: Identity,
    /// The peer this pairwise session is with. Held so the AEAD AAD can bind the
    /// full `sender ‖ recipient ‖ mailbox` context symmetrically: on `seal_to` the
    /// sender is `self` and the recipient is the peer; on `open` the recipient is
    /// `self` and the sender is the peer. A pairwise session is *with* someone —
    /// carrying the peer AID makes that explicit and lets the AAD bind it.
    peer: Aid,
    session: Session,
}

impl Endpoint {
    /// Build an endpoint from a local identity, the AID of the peer the session is
    /// shared with, and an established session.
    pub fn new(identity: Identity, peer: Aid, session: Session) -> Self {
        Endpoint {
            identity,
            peer,
            session,
        }
    }

    /// The AID of the peer this endpoint's pairwise session is with.
    pub fn peer(&self) -> &Aid {
        &self.peer
    }

    /// This endpoint's own address.
    pub fn aid(&self) -> &Aid {
        self.identity.aid()
    }

    /// This endpoint's public key (so a peer can admit it into a directory).
    pub fn public_key(&self) -> &[u8] {
        self.identity.public_key()
    }

    /// Seal a `body` for `recipient`, addressed to `mailbox`. Signs the inner
    /// envelope (authenticating *this* endpoint's AID as the sender), then
    /// AEAD-seals it under the session so the relay sees only the mailbox id and
    /// opaque bytes.
    ///
    /// `recipient` is the peer this endpoint's pairwise session is with — the AAD
    /// binds `self.aid() ‖ recipient ‖ mailbox`, the same context the recipient
    /// reconstructs on [`open`](Self::open).
    pub fn seal_to(
        &self,
        recipient: &Aid,
        mailbox: &MailboxId,
        body: &str,
    ) -> CoreResult<OuterEnvelope> {
        let signing_bytes = InnerEnvelope::signing_bytes(self.aid(), recipient, body);
        let signature = self.identity.sign(&signing_bytes)?;
        let inner = InnerEnvelope {
            sender: self.aid().clone(),
            recipient: recipient.clone(),
            body: body.to_string(),
            signature,
        };
        let inner_bytes = serde_json::to_vec(&inner)
            .map_err(|e| CoreError::Malformed(format!("serialize inner: {e}")))?;
        // The full sender ‖ recipient ‖ mailbox context is bound into the AEAD as
        // AAD (defense-in-depth, H4), so a relay holding the session secret cannot
        // re-file the bytes under another mailbox — or re-attribute them to another
        // (sender, recipient) pair — without the tag failing.
        let aad = aead_aad(self.aid(), recipient, mailbox);
        let nonce = session::fresh_nonce()?;
        let ciphertext = self.session.seal(nonce, &aad, &inner_bytes)?;
        Ok(OuterEnvelope {
            to_mailbox: mailbox.clone(),
            ciphertext,
        })
    }

    /// Open an outer envelope drained from this endpoint's mailbox: AEAD-decrypt
    /// under the session, resolve the claimed sender AID to its key via the
    /// `directory`, and verify the signature. A message that decrypts but whose
    /// signature does not verify — or whose sender cannot be resolved — is
    /// **rejected**, never surfaced as plaintext. This is the authentication
    /// gate the whole end-to-end leg turns on.
    ///
    /// The AAD reconstructs the same `sender ‖ recipient ‖ mailbox` binding the
    /// seal used: the sender is the peer this pairwise session is with, the
    /// recipient is `self`. A ciphertext relocated to a different mailbox — or one
    /// whose (sender, recipient) context differs — fails the AEAD tag here.
    pub fn open(&self, outer: &OuterEnvelope, directory: &dyn Directory) -> CoreResult<Message> {
        let aad = aead_aad(self.peer(), self.aid(), &outer.to_mailbox);
        let inner_bytes = self.session.open(&outer.ciphertext, &aad)?;
        let inner: InnerEnvelope = serde_json::from_slice(&inner_bytes)
            .map_err(|e| CoreError::Malformed(format!("parse inner: {e}")))?;
        let sender_key = directory.resolve(&inner.sender).ok_or(CoreError::Rejected(
            "sender AID could not be resolved to a key",
        ))?;
        verify_sender(
            &inner.sender,
            &sender_key,
            &inner.signing_bytes_for(),
            &inner.signature,
        )?;
        Ok(Message {
            to: inner.recipient,
            from: inner.sender,
            body: inner.body,
        })
    }
}

/// Seal a [`Message`] into the two-layer envelope. The FFI seam the SwiftUI
/// shell calls today carries only addresses and a body — it does not yet carry
/// the device's Secure-Enclave signing handle or the established session, so a
/// full seal cannot be produced here. That app-side wiring (mint the SE key →
/// derive the session over the pairing channel → call [`Endpoint::seal_to`]) is
/// the shell's own work; until it lands this fails closed rather than emitting an
/// unauthenticated or unencrypted envelope.
pub fn seal(_msg: &Message) -> CoreResult<OuterEnvelope> {
    Err(CoreError::NotBuilt(
        "seal via the FFI: bind the device Secure-Enclave key + session, then Endpoint::seal_to",
    ))
}

/// Open an [`OuterEnvelope`] pulled from a mailbox via the FFI seam. Same gap as
/// [`seal`]: the FFI does not yet carry the session/identity, so the
/// authenticated path runs through [`Endpoint::open`] instead. Fails closed so
/// an unverified message is never surfaced as plaintext.
pub fn open(_outer: &OuterEnvelope) -> CoreResult<Message> {
    Err(CoreError::NotBuilt(
        "open via the FFI: bind the device session + a witnessed directory, then Endpoint::open",
    ))
}

/// The hermetic proof harness (the `deliver_*` / `prove_*` / `hold_*` legs the
/// relay binary's self-test drives) lives behind the `proofs` feature, so the
/// engine's default public surface is the engine, not its test evidence.
#[cfg(any(feature = "proofs", test))]
pub mod proofs;

// Test-only shims so the adversarial test can reach an endpoint's signing/sealing
// without exposing the secret key or session on the public API.
#[cfg(test)]
impl Endpoint {
    fn identity_sign(&self, message: &[u8]) -> CoreResult<Vec<u8>> {
        self.identity.sign(message)
    }
    fn session_seal(&self, nonce: [u8; 12], aad: &[u8], pt: &[u8]) -> CoreResult<Vec<u8>> {
        self.session.seal(nonce, aad, pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proofs::*;

    /// The AID an identity minted from a single repeated seed byte resolves to —
    /// so a test can name an endpoint's peer by seed without building the peer
    /// first.
    fn aid_of_seed(seed_byte: u8) -> Aid {
        Identity::from_seed([seed_byte; 32]).unwrap().aid().clone()
    }

    fn endpoint(seed_byte: u8, peer_seed: u8, session_secret: [u8; 32]) -> Endpoint {
        let id = Identity::from_seed([seed_byte; 32]).unwrap();
        Endpoint::new(
            id,
            aid_of_seed(peer_seed),
            Session::from_secret(session_secret),
        )
    }

    fn directory_of(endpoints: &[&Endpoint]) -> ContactDirectory {
        let mut dir = ContactDirectory::new();
        for ep in endpoints {
            dir.admit(ep.aid().clone(), ep.public_key().to_vec());
        }
        dir
    }

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn a_delegated_device_sends_as_the_root_and_is_clawed_back_when_revoked() {
        // The phone holds the root identity; the Mac is a delegated device that mints
        // its own key and sends as the root. A contact verifies a message from the Mac
        // as the *root*; after the root revokes the Mac, the Mac's next message is
        // rejected — clawback from the chain.
        let root = Identity::from_seed([0x01u8; 32]).unwrap();
        let mac = DelegatedDevice::new(
            Identity::from_seed([0x02u8; 32]).unwrap(),
            root.aid().clone(),
        );
        let contact = Identity::from_seed([0x03u8; 32]).unwrap();
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:contact");

        let receipt = prove_delegated_device(
            &root,
            &mac,
            &contact,
            [0x5au8; 32],
            &mailbox,
            ["sent from the Mac", "sent after I lost the Mac"],
            &mut relay,
        )
        .unwrap();

        // The Mac authenticated as the root identity, not as its own device AID.
        assert_eq!(&receipt.authenticated_root, root.aid());
        assert_eq!(&receipt.device_aid, mac.device_aid());
        assert_ne!(&receipt.device_aid, root.aid());
        assert_eq!(receipt.body, "sent from the Mac");
    }

    #[test]
    fn a_revoked_device_that_still_authenticated_as_the_root_is_an_error() {
        // The trap, exercised in-process: if resolve_device_to_root ever accepted a
        // revoked device, prove_delegated_device must surface it as an error rather
        // than a receipt. We assert the post-revocation resolve genuinely rejects, so
        // the only path to a receipt is a real clawback.
        let root = Identity::from_seed([0x01u8; 32]).unwrap();
        let mac = DelegatedDevice::new(
            Identity::from_seed([0x02u8; 32]).unwrap(),
            root.aid().clone(),
        );
        let anchor = DelegationAnchor::issue(&root, &mac).unwrap();
        let mut state = DelegationState::for_root(&root);
        state.admit_device(anchor).unwrap();
        let revocation = DeviceRevocation::issue(&root, mac.device_aid()).unwrap();
        state.revoke_device(revocation).unwrap();
        assert!(matches!(
            state.resolve_device_to_root(mac.device_aid(), mac.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_message_from_the_mac_arrives_authenticated_on_the_phone() {
        let secret = [9u8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let dir = directory_of(&[&mac, &phone]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:phone");

        let receipt = deliver_once(
            &mac,
            &phone,
            &mailbox,
            "sent from the Mac",
            &mut relay,
            &dir,
        )
        .unwrap();

        assert_eq!(&receipt.authenticated_sender, mac.aid());
        assert_eq!(&receipt.recipient, phone.aid());
        assert_eq!(receipt.body, "sent from the Mac");
    }

    #[test]
    fn a_message_that_arrived_but_did_not_authenticate_is_rejected() {
        // Mallory shares the session with the phone (so the AEAD opens) but signs
        // and claims to *be* the Mac — without holding the Mac's key.
        let secret = [9u8; 32];
        // The phone's pairwise session is with the Mac, so its open-side AAD binds
        // the Mac as the sender. Mallory shares the same session bytes but is not
        // the Mac.
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let mallory = endpoint(3, 2, secret);
        // The phone only knows the real Mac; the directory binds the Mac AID to
        // the Mac key. Mallory tries to pass a forged inner envelope.
        let dir = directory_of(&[&mac, &phone]);

        // Mallory crafts an inner envelope claiming to be the Mac and signs it
        // with his own key, then seals it under the shared session.
        let forged = InnerEnvelope {
            sender: mac.aid().clone(),
            recipient: phone.aid().clone(),
            body: "I am the Mac".into(),
            signature: mallory
                .identity_sign(&InnerEnvelope::signing_bytes(
                    mac.aid(),
                    phone.aid(),
                    "I am the Mac",
                ))
                .unwrap(),
        };
        let mailbox = MailboxId::new("mbx:phone");
        let inner_bytes = serde_json::to_vec(&forged).unwrap();
        let nonce = session::fresh_nonce().unwrap();
        // Seal with the SAME AAD the phone reconstructs on open (claimed sender ‖
        // recipient ‖ mailbox), so the forgery decrypts and is caught at the
        // signature gate, not merely bounced by the AEAD tag.
        let aad = aead_aad(mac.aid(), phone.aid(), &mailbox);
        let ciphertext = mallory.session_seal(nonce, &aad, &inner_bytes).unwrap();
        let outer = OuterEnvelope {
            to_mailbox: mailbox,
            ciphertext,
        };

        // It arrives and decrypts, but the Mac's key does not verify Mallory's
        // signature — rejected, never surfaced.
        assert!(matches!(
            phone.open(&outer, &dir),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn the_relay_never_sees_the_plaintext() {
        let secret = [9u8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let mailbox = MailboxId::new("mbx:phone");
        let outer = mac
            .seal_to(phone.aid(), &mailbox, "top secret body")
            .unwrap();
        // The bytes the relay holds contain neither the plaintext nor a sender AID.
        assert!(
            !outer
                .ciphertext
                .windows("top secret body".len())
                .any(|w| w == b"top secret body")
        );
        assert!(
            !outer
                .ciphertext
                .windows(mac.aid().as_str().len())
                .any(|w| w == mac.aid().as_str().as_bytes())
        );
    }

    #[test]
    fn a_session_rooted_in_a_keri_signed_bundle_delivers_authenticated() {
        // The KERI-rooted-bundle leg: Bob publishes a bundle signed by his AID key; Alice
        // resolves Bob's AID, verifies the bundle, runs X3DH, and sends. The
        // message arrives authenticated as Alice over a session rooted in keys
        // Alice *verified* belong to Bob.
        let alice = Identity::from_seed([1u8; 32]).unwrap();
        let bob = Identity::from_seed([2u8; 32]).unwrap();
        let bob_prekeys = prekey::PrekeySecrets::from_seeds([0x20; 32], [0x21; 32]);
        let dir = directory_of(&[
            &Endpoint::new(
                alice.clone(),
                bob.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
            &Endpoint::new(
                bob.clone(),
                alice.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
        ]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:bob");

        let receipt = deliver_rooted(
            &alice,
            &bob,
            &bob_prekeys,
            [0x10; 32],
            [0x11; 32],
            &mailbox,
            "rooted in a verified bundle",
            &mut relay,
            &dir,
        )
        .unwrap();

        assert_eq!(&receipt.rooted_aid, bob.aid());
        assert_eq!(&receipt.authenticated_sender, alice.aid());
        assert_eq!(receipt.body, "rooted in a verified bundle");
    }

    #[test]
    fn a_wrong_key_bundle_never_roots_a_session() {
        // Mallory publishes a bundle for Bob's AID but signs it with his own key.
        // The directory resolves Bob's AID to *Bob's* key, so verify_rooted
        // rejects the bundle before any DH — no session is ever rooted.
        let bob = Identity::from_seed([2u8; 32]).unwrap();
        let mallory = Identity::from_seed([3u8; 32]).unwrap();
        let bob_prekeys = prekey::PrekeySecrets::from_seeds([0x20; 32], [0x21; 32]);
        let id_key = bob_prekeys.identity_public();
        let spk = bob_prekeys.prekey_public();
        // A bundle claiming Bob's AID but signed by Mallory.
        let signing = {
            let mut b = Vec::new();
            b.extend_from_slice(b"murmur/prekey-bundle/v1\n");
            b.extend_from_slice(bob.aid().as_str().as_bytes());
            b.push(b'\n');
            b.extend_from_slice(&id_key);
            b.extend_from_slice(&spk);
            b
        };
        let forged = PrekeyBundle {
            aid: bob.aid().clone(),
            signal_identity_key: id_key,
            signed_prekey: spk,
            signature: mallory.sign(&signing).unwrap(),
        };
        // Verified against Bob's resolved key: rejected.
        assert!(matches!(
            forged.verify_rooted(bob.public_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn the_relay_boundary_holds_against_tamper_replay_and_link() {
        let secret = [0x5au8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let dir = directory_of(&[&mac, &phone]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:phone");

        let receipt = hold_relay_boundary(
            &mac,
            &phone,
            &mailbox,
            "held at the boundary",
            &mut relay,
            &dir,
        )
        .unwrap();

        // Exactly one copy survived the replay, and the envelope routed only.
        assert_eq!(receipt.copies_delivered, 1);
        assert_eq!(receipt.mailbox, mailbox);
        assert_eq!(receipt.routing_only.mailbox, mailbox);
    }

    #[test]
    fn the_aead_aad_binds_sender_recipient_and_mailbox() {
        // H4 (defense-in-depth) regression: the AEAD AAD binds the full
        // sender ‖ recipient ‖ mailbox context, so a ciphertext sealed for one
        // (sender, recipient, mailbox) cannot be opened by a recipient whose
        // reconstructed AAD differs in ANY of the three — the relocation an
        // attacker holding the session secret would attempt fails the tag.
        let secret = [0x5au8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let mailbox = MailboxId::new("mbx:phone");
        let dir = directory_of(&[&mac, &phone]);

        let outer = mac
            .seal_to(phone.aid(), &mailbox, "addressed precisely")
            .unwrap();
        // The legitimate recipient, sharing the exact (sender, recipient, mailbox)
        // context, opens it.
        assert_eq!(
            phone.open(&outer, &dir).unwrap().body,
            "addressed precisely"
        );

        // (a) Relocated to a different mailbox: the recipient's AAD now binds a
        // different mailbox id, so the AEAD tag fails — the relay cannot re-file it.
        let relocated = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx:elsewhere"),
            ciphertext: outer.ciphertext.clone(),
        };
        assert!(matches!(
            phone.open(&relocated, &dir),
            Err(CoreError::Rejected(_))
        ));

        // (b) Re-attributed to a different sender context: a recipient whose
        // pairwise peer is someone OTHER than the Mac (but somehow holds the same
        // session bytes) reconstructs a different sender AID into its AAD, so the
        // same ciphertext fails to open.
        let phone_expecting_someone_else = endpoint(2, 3, secret);
        assert!(matches!(
            phone_expecting_someone_else.open(&outer, &dir),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_message_is_addressed_to_and_authenticated_by_an_aid_number_free() {
        // The floor: a message addressed to an AID's pairwise mailbox, authenticated
        // as the sender AID, with no phone number or email anywhere — and a forgery
        // claiming the sender's AID is rejected.
        let secret = [0x5au8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let impostor = endpoint(3, 2, secret);
        let dir = directory_of(&[&mac, &phone]); // the impostor is NOT admitted-as-Mac
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:pairwise");

        let receipt = prove_addressed(
            &mac,
            &phone,
            &impostor,
            &mailbox,
            "see you at the usual place",
            &mut relay,
            &dir,
        )
        .unwrap();

        assert_eq!(&receipt.addressed_to, phone.aid());
        assert_eq!(&receipt.authenticated_as, mac.aid());
        assert!(receipt.addressed_to.as_str().starts_with("did:keri:"));
        assert!(receipt.authenticated_as.as_str().starts_with("did:keri:"));
        assert_eq!(receipt.number_free.forms_scanned, 3);
    }

    #[test]
    fn a_message_carrying_a_phone_number_is_rejected_by_the_floor() {
        // A body that smuggles a dialable number must fail the number-free scan —
        // the floor proves the *absence*, it does not merely narrate it.
        let secret = [0x5au8; 32];
        let mac = endpoint(1, 2, secret);
        let phone = endpoint(2, 1, secret);
        let impostor = endpoint(3, 2, secret);
        let dir = directory_of(&[&mac, &phone]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:pairwise");

        let err = prove_addressed(
            &mac,
            &phone,
            &impostor,
            &mailbox,
            "call me at +1 415-555-0123",
            &mut relay,
            &dir,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn seal_via_the_ffi_is_honestly_unbuilt() {
        let m = Message {
            to: Aid::placeholder(),
            from: Aid::placeholder(),
            body: "hi".into(),
        };
        assert!(matches!(seal(&m), Err(CoreError::NotBuilt(_))));
    }

    #[test]
    fn open_via_the_ffi_is_honestly_unbuilt() {
        let outer = OuterEnvelope::placeholder();
        assert!(matches!(open(&outer), Err(CoreError::NotBuilt(_))));
    }

    #[test]
    fn the_relay_queue_holds_only_forward_secret_routing_bytes() {
        // The privacy floor: several bodies are sealed on a forward-secret ratchet,
        // stored-and-forwarded through the relay's real queue, and the queued bytes
        // are proven to carry the mailbox id and opaque ciphertext only.
        let desktop = Identity::from_seed([0x11u8; 32]).unwrap();
        let handset = Identity::from_seed([0x22u8; 32]).unwrap();
        let dir = directory_of(&[
            &Endpoint::new(
                desktop.clone(),
                handset.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
            &Endpoint::new(
                handset.clone(),
                desktop.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
        ]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:pairwise-mailbox");
        let bodies = ["the body the relay must never read", "and one more"];

        let receipt = prove_relay_queue(
            &desktop,
            &handset,
            [0x5au8; 32],
            &mailbox,
            &bodies,
            &mut relay,
            &dir,
        )
        .unwrap();

        assert_eq!(receipt.mailbox, mailbox);
        assert_eq!(receipt.envelopes_queued, bodies.len() as u64);
        assert_eq!(receipt.routing_only.mailbox, mailbox);
        // Every secret (body, sender address, session key, chain state) was checked.
        assert_eq!(receipt.routing_only.secrets_checked, 4);
    }

    #[test]
    fn a_queued_envelope_that_leaked_the_body_is_caught() {
        // The adversarial twin (the trap): if the relay queue ever held the cleartext
        // body instead of opaque ciphertext, the leakcheck scan over the queued bytes
        // must reject it — the privacy floor proves the absence, never narrates it.
        // We deposit a malformed envelope whose "ciphertext" is the body verbatim and
        // confirm prove_routing_only over the queued bytes fails closed.
        let desktop = Identity::from_seed([0x11u8; 32]).unwrap();
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:pairwise-mailbox");
        let body = b"the body the relay must never read";
        relay.deposit(&OuterEnvelope {
            to_mailbox: mailbox.clone(),
            ciphertext: body.to_vec(),
        });
        let queued = relay.handle(&RelayRequest::Drain(mailbox.clone()));
        let leaked = queued.first().unwrap();
        let err = leakcheck::prove_routing_only(
            leaked,
            body,
            desktop.aid().as_str(),
            &[0u8; 32],
            &[1u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_compromised_state_cannot_follow_past_the_next_dh_ratchet_step() {
        // Post-compromise healing: after a simulated full state compromise, a message
        // sealed on the post-step (healed) chain delivers to the legitimate peer but
        // cannot be opened from the compromised pre-step state — the attacker is
        // locked back out.
        let mac = Identity::from_seed([0x11u8; 32]).unwrap();
        let phone = Identity::from_seed([0x22u8; 32]).unwrap();
        let dir = directory_of(&[
            &Endpoint::new(
                mac.clone(),
                phone.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
            &Endpoint::new(
                phone.clone(),
                mac.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
        ]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:phone");
        let bodies = ["after the compromise", "still healed"];

        let receipt = prove_post_compromise_healing(
            &mac,
            &phone,
            [0x5au8; 32],
            [0x10u8; 32],
            [0x20u8; 32],
            [0x11u8; 32],
            &mailbox,
            &bodies,
            &mut relay,
            &dir,
        )
        .unwrap();

        assert_eq!(receipt.healed_at_step, 1);
        assert_eq!(receipt.healed_messages_delivered, bodies.len() as u64);
        assert!(receipt.attacker_locked_out);
    }

    #[test]
    fn the_post_compromise_proof_rejects_an_empty_body_list() {
        let mac = Identity::from_seed([0x11u8; 32]).unwrap();
        let phone = Identity::from_seed([0x22u8; 32]).unwrap();
        let dir = directory_of(&[
            &Endpoint::new(
                mac.clone(),
                phone.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
            &Endpoint::new(
                phone.clone(),
                mac.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
        ]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:phone");
        assert!(matches!(
            prove_post_compromise_healing(
                &mac,
                &phone,
                [0x5au8; 32],
                [0x10u8; 32],
                [0x20u8; 32],
                [0x11u8; 32],
                &mailbox,
                &[],
                &mut relay,
                &dir,
            ),
            Err(CoreError::Malformed(_))
        ));
    }

    #[test]
    fn an_empty_body_list_is_rejected_not_silently_passed() {
        let desktop = Identity::from_seed([0x11u8; 32]).unwrap();
        let handset = Identity::from_seed([0x22u8; 32]).unwrap();
        let dir = directory_of(&[
            &Endpoint::new(
                desktop.clone(),
                handset.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
            &Endpoint::new(
                handset.clone(),
                desktop.aid().clone(),
                Session::from_secret([0u8; 32]),
            ),
        ]);
        let mut relay = MailboxStore::new();
        let mailbox = MailboxId::new("mbx:pairwise-mailbox");
        assert!(matches!(
            prove_relay_queue(
                &desktop,
                &handset,
                [0x5au8; 32],
                &mailbox,
                &[],
                &mut relay,
                &dir
            ),
            Err(CoreError::Malformed(_))
        ));
    }
}
