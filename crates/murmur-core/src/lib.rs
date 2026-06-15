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
pub mod envelope;
pub mod identity;
pub mod leakcheck;
pub mod prekey;
pub mod ratchet;
pub mod relay;
pub mod session;
pub mod trust;

pub use address::Aid;
pub use envelope::{InnerEnvelope, OuterEnvelope};
pub use identity::{Identity, verify_sender};
pub use leakcheck::{RoutingOnlyReport, prove_routing_only, relay_visible_bytes};
pub use prekey::{PrekeyBundle, PrekeySecrets, RootedBundle, x3dh_initiator, x3dh_responder};
pub use ratchet::Ratchet;
pub use relay::{DepositOutcome, MailboxId, MailboxStore, RelayRequest};
pub use session::Session;
pub use trust::{TrustState, TrustVerdict};

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

/// One side of a conversation: a local identity and the session shared with the
/// peer. The endpoint seals outgoing messages and opens incoming ones.
pub struct Endpoint {
    identity: Identity,
    session: Session,
}

impl Endpoint {
    /// Build an endpoint from a local identity and an established session.
    pub fn new(identity: Identity, session: Session) -> Self {
        Endpoint { identity, session }
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
        // The mailbox id is bound into the AEAD as AAD, so a relay cannot re-file
        // the bytes under another mailbox without the tag failing.
        let nonce = session::fresh_nonce()?;
        let ciphertext = self
            .session
            .seal(nonce, mailbox.as_str().as_bytes(), &inner_bytes)?;
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
    pub fn open(&self, outer: &OuterEnvelope, directory: &dyn Directory) -> CoreResult<Message> {
        let inner_bytes = self
            .session
            .open(&outer.ciphertext, outer.to_mailbox.as_str().as_bytes())?;
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

/// The verdict of driving one message all the way through the engine: sealed by
/// the sender, stored-and-forwarded through the relay, drained and opened by the
/// recipient, and authenticated as the sender. Returned by [`deliver_once`] so a
/// caller (the relay binary's self-test, the harness) can assert the leg holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// The AID the opened message authenticated as — equal to the sender's AID
    /// only because the signature verified.
    pub authenticated_sender: Aid,
    /// The recipient AID the message arrived for.
    pub recipient: Aid,
    /// The body that arrived, after verify + decrypt.
    pub body: String,
}

/// Drive the whole end-to-end leg once, hermetically: `sender` seals `body` for
/// `recipient` to `mailbox`, deposits it in `relay`, the recipient drains and
/// opens it against `directory`. Returns a [`DeliveryReceipt`] iff the message
/// arrived **and** authenticated; any failure to verify is an error, never a
/// silent pass. This is the function the relay binary's `serve` self-test runs
/// to prove "delivered-and-authenticated".
pub fn deliver_once(
    sender: &Endpoint,
    recipient: &Endpoint,
    mailbox: &MailboxId,
    body: &str,
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<DeliveryReceipt> {
    let outer = sender.seal_to(recipient.aid(), mailbox, body)?;
    // The relay only ever sees the outer envelope.
    relay.handle(&RelayRequest::Deposit(outer));
    let mut drained = relay.handle(&RelayRequest::Drain(mailbox.clone()));
    let pulled = drained
        .pop()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let msg = recipient.open(&pulled, directory)?;
    Ok(DeliveryReceipt {
        authenticated_sender: msg.from,
        recipient: msg.to,
        body: msg.body,
    })
}

/// The verdict of rooting a session in a KERI-authenticated prekey bundle and
/// driving one message through it. Returned by [`deliver_rooted`] so the relay
/// binary's self-test (and the harness) can assert the join held: the bundle
/// verified against the AID's current key, X3DH agreed a session against the
/// *verified* keys, and the delivered message authenticated as the sender — and
/// that a wrong-key bundle would have been rejected before any DH ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootedReceipt {
    /// The AID whose KERI-signed bundle rooted the session — equal to the
    /// recipient only because the bundle's signature verified.
    pub rooted_aid: Aid,
    /// The AID the delivered message authenticated as.
    pub authenticated_sender: Aid,
    /// The body that arrived after verify + decrypt over the rooted session.
    pub body: String,
}

/// Drive the KERI→Signal join once, hermetically (PRD §10, the prekey-bundle
/// claim):
///
///  1. the recipient publishes a prekey bundle **signed by their AID's current
///     key** (a *distinct* Signal identity key — no signing↔DH reuse);
///  2. the sender resolves the recipient's AID to its key via `directory` (a
///     witnessed KEL replay in the full engine) and **verifies the bundle**
///     against it — a wrong-key bundle is rejected here, before any DH runs;
///  3. X3DH derives the initial session secret against the *verified* keys (both
///     sides agree the same secret);
///  4. the sender seals a message under that rooted session; it is
///     stored-and-forwarded through `relay`, drained, and opened — authenticating
///     as the sender.
///
/// Returns a [`RootedReceipt`] iff the bundle verified, the session agreed, and
/// the message authenticated. Any failure to verify the bundle is an error, never
/// a silent pass — this is the gate that closes the MITM the safety-number
/// warning exists to catch.
#[allow(clippy::too_many_arguments)]
pub fn deliver_rooted(
    sender: &Identity,
    recipient: &Identity,
    recipient_prekeys: &PrekeySecrets,
    sender_x3dh_identity: [u8; 32],
    sender_x3dh_ephemeral: [u8; 32],
    mailbox: &MailboxId,
    body: &str,
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<RootedReceipt> {
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

    // (1) The recipient publishes a bundle signed by their AID key.
    let bundle = PrekeyBundle::publish(recipient, recipient_prekeys)?;

    // (2) The sender resolves the recipient's AID → current key, then verifies the
    // bundle against it. A wrong-key bundle is rejected here (see the adversarial
    // test) — there is no path to X3DH without a verified bundle.
    let recipient_key = directory
        .resolve(recipient.aid())
        .ok_or(CoreError::Rejected(
            "recipient AID could not be resolved to a key",
        ))?;
    let rooted = bundle.verify_rooted(&recipient_key)?;

    // (3) X3DH against the *verified* keys. Both sides agree the same secret.
    let sender_id_secret = X25519Secret::from(sender_x3dh_identity);
    let sender_eph_secret = X25519Secret::from(sender_x3dh_ephemeral);
    let sender_session = x3dh_initiator(&sender_id_secret, &sender_eph_secret, &rooted)?;
    let recipient_session = x3dh_responder(
        recipient_prekeys,
        X25519Public::from(&sender_id_secret).to_bytes(),
        X25519Public::from(&sender_eph_secret).to_bytes(),
    )?;

    // (4) Seal under the rooted session, store-and-forward, drain, open.
    let sender_endpoint = Endpoint::new(sender.clone(), sender_session);
    let recipient_endpoint = Endpoint::new(recipient.clone(), recipient_session);
    let receipt = deliver_once(
        &sender_endpoint,
        &recipient_endpoint,
        mailbox,
        body,
        relay,
        directory,
    )?;

    Ok(RootedReceipt {
        rooted_aid: rooted.aid().clone(),
        authenticated_sender: receipt.authenticated_sender,
        body: receipt.body,
    })
}

/// The verdict of proving forward secrecy across our wiring (PRD §10, the
/// forward-secrecy claim):
/// several messages were sealed over a forward-secret [`Ratchet`] and
/// stored-and-forwarded through the relay, and a *later* receiving-chain state —
/// the state an attacker would seize — could **not** decrypt an *earlier*
/// captured ciphertext, because the key that sealed it was ratcheted past and
/// zeroized. Returned by [`deliver_forward_secret`] so the relay self-test (and
/// the harness) can assert the property held rather than merely that messages
/// flowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSecrecyReceipt {
    /// How many messages were driven through the ratcheted session in order.
    pub messages_delivered: u64,
    /// The receiving-chain message index the captured early ciphertext was sealed
    /// at (the one a later state must fail to open).
    pub captured_index: u64,
    /// The receiving-chain index the "compromised" later state had advanced to
    /// when it was made to attempt the earlier ciphertext.
    pub compromised_index: u64,
}

/// Drive the forward-secrecy property once, hermetically (PRD §10, the
/// forward-secrecy claim).
///
/// Both endpoints seed a [`Ratchet`] from the same agreed root secret (the X3DH
/// output stands in here as a fixed root). The sender seals `bodies` in order;
/// each is stored-and-forwarded through `relay` and opened by the receiver,
/// advancing the receiving chain. We **capture the first ciphertext off the
/// relay** before it is opened, let the receiving chain advance past it by
/// processing the rest, then take the *advanced* receiving chain — the
/// compromised later state — and prove it **cannot** decrypt the captured early
/// ciphertext: its key was ratcheted forward and the spent key zeroized.
///
/// Returns a [`ForwardSecrecyReceipt`] iff every in-order message opened **and**
/// the later state failed to open the early one. A later state that *did* manage
/// to decrypt the early ciphertext (forward secrecy broken) is an error, never a
/// silent pass — that is the RED the trap records.
pub fn deliver_forward_secret(
    sender: &Identity,
    recipient: &Identity,
    root_secret: [u8; 32],
    mailbox: &MailboxId,
    bodies: &[&str],
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<ForwardSecrecyReceipt> {
    if bodies.len() < 2 {
        return Err(CoreError::Malformed(
            "forward-secrecy proof needs at least two messages (capture one, advance past it)"
                .into(),
        ));
    }
    let root = Session::from_secret(root_secret);
    let mut send_chain = Ratchet::from_session(&root)?;
    let mut recv_chain = Ratchet::from_session(&root)?;
    let mailbox_aad = mailbox.as_str().as_bytes();

    // (1) Seal every message over the sending chain and store-and-forward it. We
    // sign+wrap the body as the inner envelope so what flows is a real
    // authenticated message, then ratchet-seal that — the relay sees only the
    // mailbox id and opaque ratcheted bytes.
    let mut wires: Vec<Vec<u8>> = Vec::with_capacity(bodies.len());
    for body in bodies {
        let signing_bytes = InnerEnvelope::signing_bytes(sender.aid(), recipient.aid(), body);
        let signature = sender.sign(&signing_bytes)?;
        let inner = InnerEnvelope {
            sender: sender.aid().clone(),
            recipient: recipient.aid().clone(),
            body: (*body).to_string(),
            signature,
        };
        let inner_bytes = serde_json::to_vec(&inner)
            .map_err(|e| CoreError::Malformed(format!("serialize inner: {e}")))?;
        let ciphertext = send_chain.seal(mailbox_aad, &inner_bytes)?;
        relay.handle(&RelayRequest::Deposit(OuterEnvelope {
            to_mailbox: mailbox.clone(),
            ciphertext,
        }));
    }
    for env in relay.handle(&RelayRequest::Drain(mailbox.clone())) {
        wires.push(env.ciphertext);
    }
    if wires.len() != bodies.len() {
        return Err(CoreError::Rejected(
            "not every sealed message arrived at the mailbox",
        ));
    }

    // (2) Capture the FIRST ciphertext as the attacker would off the relay,
    // before the receiver opens it.
    let captured_early = wires[0].clone();
    let captured_index = recv_chain.counter();

    // (3) The receiver opens every message in order, advancing its chain past the
    // captured one. Each open authenticates the sender — a message that decrypts
    // but does not authenticate would be rejected, never counted.
    let mut delivered = 0u64;
    for wire in &wires {
        let inner_bytes = recv_chain.open(mailbox_aad, wire)?;
        let inner: InnerEnvelope = serde_json::from_slice(&inner_bytes)
            .map_err(|e| CoreError::Malformed(format!("parse inner: {e}")))?;
        let sender_key = directory
            .resolve(&inner.sender)
            .ok_or(CoreError::Rejected("sender AID could not be resolved"))?;
        verify_sender(
            &inner.sender,
            &sender_key,
            &inner.signing_bytes_for(),
            &inner.signature,
        )?;
        delivered += 1;
    }

    // (4) The compromised later state: the receiving chain is now advanced past
    // the captured message. Attempt the captured early ciphertext against it — it
    // MUST fail, because the key that sealed it was ratcheted past and zeroized.
    let compromised_index = recv_chain.counter();
    match recv_chain.open(mailbox_aad, &captured_early) {
        Ok(_) => Err(CoreError::Rejected(
            "late-state-decrypts-old: a later compromised state decrypted an earlier ciphertext",
        )),
        Err(CoreError::Rejected(_)) => Ok(ForwardSecrecyReceipt {
            messages_delivered: delivered,
            captured_index,
            compromised_index,
        }),
        Err(other) => Err(other),
    }
}

/// The verdict of capturing a real sealed envelope as the untrusted relay sees it
/// and proving it leaks nothing but routing (PRD §10, the metadata-hygiene claim).
/// Two captures are proven, one per send path the engine has — the fixed-session
/// path ([`Endpoint::seal_to`]) and the forward-secret ratchet path
/// ([`Ratchet::seal`]) — so a leak in either is caught. Returned by
/// [`deliver_routing_only`] so the relay binary's self-test can assert the
/// property held over genuine wire bytes, not merely trust the envelope's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingHygieneReceipt {
    /// The routing-only report for the fixed-session ([`Endpoint::seal_to`]) path.
    pub session_path: RoutingOnlyReport,
    /// The routing-only report for the forward-secret ([`Ratchet::seal`]) path.
    pub ratchet_path: RoutingOnlyReport,
}

/// Drive the metadata-hygiene proof once, hermetically (PRD §10, the
/// metadata-hygiene claim): seal a real message on each of the engine's two send
/// paths, store-and-forward it through `relay`, capture the outer envelope exactly
/// as the relay queued it, and prove by a leakcheck-style scan that the
/// relay-visible bytes carry **only** the pairwise mailbox id — no message body,
/// no sender address, no session key, no forward-secret chain state.
///
///  * Fixed-session path: the sender seals via [`Endpoint::seal_to`]; the captured
///    envelope is scanned against the plaintext, the sender AID, and the session
///    secret.
///  * Forward-secret path: the sender seals via a [`Ratchet`]; the captured
///    envelope is scanned against the plaintext, the sender AID, and the live chain
///    state.
///
/// Returns a [`RoutingHygieneReceipt`] iff **both** captures scan clean; if either
/// envelope is found to carry any of the sensitive material, the scan returns
/// [`CoreError::Rejected`] naming what leaked, so the caller fails closed. The
/// captures are taken by draining the relay, so what is scanned is literally what
/// the relay forwarded.
pub fn deliver_routing_only(
    sender: &Endpoint,
    recipient: &Aid,
    mailbox: &MailboxId,
    body: &str,
    relay: &mut MailboxStore,
) -> CoreResult<RoutingHygieneReceipt> {
    // ── Fixed-session path ────────────────────────────────────────────────────
    let outer = sender.seal_to(recipient, mailbox, body)?;
    relay.handle(&RelayRequest::Deposit(outer));
    let captured = relay
        .handle(&RelayRequest::Drain(mailbox.clone()))
        .pop()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let session_path = leakcheck::prove_routing_only(
        &captured,
        body.as_bytes(),
        sender.aid().as_str(),
        sender.session.secret_bytes(),
        sender.session.secret_bytes(),
    )?;

    // ── Forward-secret (ratchet) path ─────────────────────────────────────────
    // Seal the same body over a fresh sending chain seeded from the session root,
    // capture the envelope off the relay, and scan it against the *live* chain
    // state as well — so a ratcheted envelope is held to the same routing-only bar.
    let mut send_chain = Ratchet::from_session(&sender.session)?;
    let ratchet_wire = send_chain.seal(mailbox.as_str().as_bytes(), body.as_bytes())?;
    let ratchet_outer = OuterEnvelope {
        to_mailbox: mailbox.clone(),
        ciphertext: ratchet_wire,
    };
    relay.handle(&RelayRequest::Deposit(ratchet_outer));
    let ratchet_captured = relay
        .handle(&RelayRequest::Drain(mailbox.clone()))
        .pop()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let ratchet_path = leakcheck::prove_routing_only(
        &ratchet_captured,
        body.as_bytes(),
        sender.aid().as_str(),
        sender.session.secret_bytes(),
        send_chain.chain_state(),
    )?;

    Ok(RoutingHygieneReceipt {
        session_path,
        ratchet_path,
    })
}

/// The verdict of holding the untrusted-relay boundary against tamper, replay, and
/// linkage (PRD §10, the untrusted-relay claim). Driving it proves three properties
/// at once over a real sealed envelope, so a regression in any one fails the leg
/// closed:
///
///  * **tamper** — a bit-flipped ciphertext fails the recipient's AEAD and is
///    rejected with the *same* uniform error a wrong key or a moved mailbox
///    produces, so a relay flipping bytes learns nothing (no decryption oracle);
///  * **replay** — a byte-identical capture re-presented to the relay is deduped at
///    the boundary, so the recipient drains the message once, not twice;
///  * **link** — the relay-visible envelope carries only the pairwise mailbox id;
///    the body, the sender address, and the session key are each absent from the
///    wire bytes.
///
/// Returned by [`hold_relay_boundary`] so the relay binary's self-test (and the
/// harness) can assert the boundary held rather than merely that a message flowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBoundaryReceipt {
    /// The mailbox the deduped replay was addressed to — the routing handle the
    /// relay correlates on, and the only thing the routing-only scan permits in the
    /// wire bytes.
    pub mailbox: MailboxId,
    /// How many copies of one capture the relay forwarded after a replay was
    /// re-presented — exactly one, the dedup having dropped the second.
    pub copies_delivered: usize,
    /// The routing-only report for the relay-visible envelope: the body, sender
    /// address, and session key were each scanned for and found absent.
    pub routing_only: RoutingOnlyReport,
}

/// Drive the untrusted-relay boundary guard once, hermetically (PRD §10, the
/// untrusted-relay claim): prove that the relay cannot tamper, replay, or link.
///
///  1. The sender seals a message for the recipient and deposits it; the relay
///     queues fresh ciphertext.
///  2. **Tamper:** a single bit of the captured ciphertext is flipped and the
///     tampered envelope is opened by the recipient — it MUST fail AEAD and be
///     [`CoreError::Rejected`]. A tampered ciphertext that *opened* would mean the
///     relay can forge, and is returned as an error (the RED the trap records).
///  3. **Replay:** the original (un-flipped) capture is re-deposited; the relay
///     MUST dedup it ([`DepositOutcome::DedupedReplay`]). The recipient then drains
///     and opens exactly one copy, authenticating as the sender.
///  4. **Link:** the captured outer envelope is scanned and proven to carry only
///     the pairwise mailbox id — body, sender address, and session key all absent.
///
/// Returns a [`RelayBoundaryReceipt`] iff the tampered open was rejected, the
/// replay was deduped to a single delivery, and the envelope scanned routing-only.
/// Any property that fails to hold is an error, never a silent pass.
pub fn hold_relay_boundary(
    sender: &Endpoint,
    recipient: &Endpoint,
    mailbox: &MailboxId,
    body: &str,
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<RelayBoundaryReceipt> {
    // (1) Seal and deposit. The relay only ever sees the outer envelope.
    let outer = sender.seal_to(recipient.aid(), mailbox, body)?;
    if relay.deposit(&outer) != DepositOutcome::Queued {
        return Err(CoreError::Rejected(
            "fresh ciphertext was not queued by the relay",
        ));
    }

    // (2) Tamper: flip one bit of the captured ciphertext and prove the recipient's
    // AEAD rejects it — with the same uniform error a wrong key produces, so the
    // relay gets no oracle distinguishing "tampered" from "wrong key".
    let mut tampered = outer.clone();
    let last = tampered
        .ciphertext
        .len()
        .checked_sub(1)
        .ok_or(CoreError::Malformed("sealed ciphertext was empty".into()))?;
    tampered.ciphertext[last] ^= 0xff;
    match recipient.open(&tampered, directory) {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "tamper-accepted: a bit-flipped ciphertext opened — the relay can forge",
            ));
        }
        Err(CoreError::Rejected(_)) => { /* AEAD rejected the tampered bytes, as required */ }
        Err(other) => return Err(other),
    }

    // (3) Replay: re-present the exact original capture; the relay must dedup it.
    if relay.deposit(&outer) != DepositOutcome::DedupedReplay {
        return Err(CoreError::Rejected(
            "replay-delivered-twice: a byte-identical capture was queued a second time",
        ));
    }
    let drained = relay.handle(&RelayRequest::Drain(mailbox.clone()));
    let copies_delivered = drained.len();
    if copies_delivered != 1 {
        return Err(CoreError::Rejected(
            "replay-delivered-twice: the recipient drained more than one copy of one capture",
        ));
    }
    let pulled = drained
        .into_iter()
        .next()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let message = recipient.open(&pulled, directory)?;
    if &message.from != sender.aid() {
        return Err(CoreError::Rejected(
            "the deduped delivery did not authenticate as the sender",
        ));
    }

    // (4) Link: the relay-visible envelope carries only the pairwise mailbox id.
    let routing_only = leakcheck::prove_routing_only(
        &outer,
        body.as_bytes(),
        sender.aid().as_str(),
        sender.session.secret_bytes(),
        sender.session.secret_bytes(),
    )?;

    Ok(RelayBoundaryReceipt {
        mailbox: mailbox.clone(),
        copies_delivered,
        routing_only,
    })
}

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

    fn endpoint(seed_byte: u8, session_secret: [u8; 32]) -> Endpoint {
        let id = Identity::from_seed([seed_byte; 32]).unwrap();
        Endpoint::new(id, Session::from_secret(session_secret))
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
    fn a_message_from_the_mac_arrives_authenticated_on_the_phone() {
        let secret = [9u8; 32];
        let mac = endpoint(1, secret);
        let phone = endpoint(2, secret);
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
        let mac = endpoint(1, secret);
        let phone = endpoint(2, secret);
        let mallory = endpoint(3, secret);
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
        let ciphertext = mallory
            .session_seal(nonce, mailbox.as_str().as_bytes(), &inner_bytes)
            .unwrap();
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
        let mac = endpoint(1, secret);
        let phone = endpoint(2, secret);
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
            &Endpoint::new(alice.clone(), Session::from_secret([0u8; 32])),
            &Endpoint::new(bob.clone(), Session::from_secret([0u8; 32])),
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
        let mac = endpoint(1, secret);
        let phone = endpoint(2, secret);
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
}
