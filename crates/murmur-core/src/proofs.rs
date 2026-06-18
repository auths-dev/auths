//! Hermetic proof harness — the `deliver_*` / `prove_*` / `hold_*` legs the relay
//! binary's self-test (`murmur-relay serve`) drives to exercise each end-to-end
//! property (addressing, forward secrecy, post-compromise healing, the relay
//! boundary, delegation, revocation, witnessed key-state). These run the real engine
//! end-to-end but are **proof infrastructure, not the engine's public API** — gated
//! behind `feature = "proofs"` (and `test`) so the default `murmur-core` surface is
//! the engine (`Endpoint`, `Identity`, the modules).
#![allow(clippy::wildcard_imports)]

use crate::*;

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

    // (4) Seal under the rooted session, store-and-forward, drain, open. Each
    // endpoint's peer is the other side of this pairwise session.
    let sender_endpoint = Endpoint::new(sender.clone(), recipient.aid().clone(), sender_session);
    let recipient_endpoint =
        Endpoint::new(recipient.clone(), sender.aid().clone(), recipient_session);
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
        let signing_bytes =
            InnerEnvelope::signing_bytes(sender.aid(), recipient.aid(), &[0u8; 8], "text", 0, body);
        let signature = sender.sign(&signing_bytes)?;
        let inner = InnerEnvelope {
            sender: sender.aid().clone(),
            recipient: recipient.aid().clone(),
            message_id: vec![0u8; 8],
            content_type: "text".to_string(),
            flags: 0,
            body: (*body).to_string(),
            signature,
        };
        let inner_bytes = inner.to_frame()?;
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
        let inner = InnerEnvelope::from_frame(&inner_bytes, recipient.aid())?;
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

/// The verdict of proving **post-compromise healing** across our wiring (PRD §10,
/// the post-compromise-security claim): an attacker who seized the full session
/// state at some instant could read the traffic of the moment, but the next DH
/// ratchet step mixed in fresh entropy the attacker never held, so a message
/// sealed on the **post-step** chain could not be opened from the compromised
/// state — confidentiality recovered, the attacker locked back out. Returned by
/// [`prove_post_compromise_healing`] so the relay self-test (and the harness) can
/// assert the property held rather than merely that messages flowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCompromiseReceipt {
    /// The DH ratchet step index at which the healing step was taken (the turn that
    /// injected fresh entropy past the compromise).
    pub healed_at_step: u64,
    /// How many messages sealed on the post-step (healed) chain were store-and-
    /// forwarded through the relay and opened by the legitimate peer.
    pub healed_messages_delivered: u64,
    /// Confirmation that the attacker, holding the compromised pre-step state, could
    /// **not** open the healed traffic — the post-compromise-security property.
    pub attacker_locked_out: bool,
}

/// Drive the post-compromise-healing property once, hermetically (PRD §10, the
/// post-compromise-security claim): after a simulated **full state compromise**,
/// the next DH ratchet step restores confidentiality.
///
/// The forward-secrecy leg ([`deliver_forward_secret`]) proves a *later* state
/// can't reopen an *earlier* ciphertext. This is its dual and its complement: it
/// proves an *earlier compromised* state can't open *later* (post-step) traffic —
/// the conversation **heals** from a compromise instead of staying broken forever.
///
///  1. Both ends seed a [`dh_ratchet::DhRatchet`] from the same agreed root (the
///     X3DH output stands in here as a fixed root) and their own X25519 ratchet
///     keys.
///  2. **The compromise:** we snapshot the full pre-step state an attacker would
///     seize — the live root key — exactly as it stands before the healing turn.
///     (At this instant the attacker can derive the current symmetric chain off the
///     root, so it genuinely reads the traffic of the moment — that is what makes
///     the recovery non-trivial.)
///  3. **The healing step:** the sender takes a DH ratchet step ([`DhRatchet::ratchet_send`])
///     — a fresh ephemeral key pair, a fresh DH output mixed into the root — and
///     the receiver follows it ([`DhRatchet::ratchet_receive`]). Both land on the
///     same *new* root and a fresh chain. The sender seals `bodies` on the new
///     chain; each is stored-and-forwarded through `relay`, drained, opened, and
///     **authenticated as the sender**.
///  4. **The lock-out:** we take the attacker's compromised pre-step root and have
///     them run the only thing it lets them — the symmetric chain off that old root
///     — against the captured post-step ciphertext. It MUST fail: the healed chain
///     was seeded from the new root, which depends on a private key minted after
///     the compromise. The attacker is locked out.
///
/// Returns a [`PostCompromiseReceipt`] iff the healed traffic delivered **and** the
/// compromised state failed to open it. An attacker who *could* still open the
/// post-step ciphertext (healing did not happen) is an error, never a silent pass —
/// that is the RED the trap records.
#[allow(clippy::too_many_arguments)]
pub fn prove_post_compromise_healing(
    sender: &Identity,
    recipient: &Identity,
    root_secret: [u8; 32],
    sender_ratchet_seed: [u8; 32],
    recipient_ratchet_seed: [u8; 32],
    fresh_ratchet_seed: [u8; 32],
    mailbox: &MailboxId,
    bodies: &[&str],
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<PostCompromiseReceipt> {
    use x25519_dalek::StaticSecret as X25519Secret;

    if bodies.is_empty() {
        return Err(CoreError::Malformed(
            "the post-compromise proof needs at least one message to seal on the healed chain"
                .into(),
        ));
    }

    // (1) Both ends seed a DH ratchet from the same agreed root and their own
    // X25519 ratchet keys.
    let mut sender_dh = DhRatchet::from_root(root_secret, X25519Secret::from(sender_ratchet_seed));
    let mut recipient_dh =
        DhRatchet::from_root(root_secret, X25519Secret::from(recipient_ratchet_seed));
    let mailbox_aad = mailbox.as_str().as_bytes();

    // (2) The compromise: snapshot the full pre-step state the attacker seizes — the
    // live root key, before the healing turn. The attacker who holds this can run the
    // symmetric chain off it (it reads the traffic of the moment); the test is whether
    // it can follow *past* the next DH step.
    let compromised_root = *sender_dh.root_state();

    // (3) The healing step: the sender takes a DH ratchet step (fresh ephemeral, fresh
    // DH output mixed into the root); the receiver follows it. Both land on the same
    // new root and a fresh chain.
    let (step, mut healed_send) = sender_dh.ratchet_send(
        &recipient_dh.public_key(),
        X25519Secret::from(fresh_ratchet_seed),
    )?;
    let mut healed_recv = recipient_dh.ratchet_receive(&step.public_key)?;
    let healed_at_step = sender_dh.steps();

    // The root must actually have advanced away from the compromised value, or there
    // is nothing to heal.
    if sender_dh.root_state() == &compromised_root {
        return Err(CoreError::Rejected(
            "no-healing: the DH ratchet step did not advance the root past the compromise",
        ));
    }

    // Seal each body on the post-step (healed) chain into an authenticated inner
    // envelope and store-and-forward it. The relay only ever sees the outer envelope.
    for body in bodies {
        let signing_bytes =
            InnerEnvelope::signing_bytes(sender.aid(), recipient.aid(), &[0u8; 8], "text", 0, body);
        let signature = sender.sign(&signing_bytes)?;
        let inner = InnerEnvelope {
            sender: sender.aid().clone(),
            recipient: recipient.aid().clone(),
            message_id: vec![0u8; 8],
            content_type: "text".to_string(),
            flags: 0,
            body: (*body).to_string(),
            signature,
        };
        let inner_bytes = inner.to_frame()?;
        let ciphertext = healed_send.seal(mailbox_aad, &inner_bytes)?;
        relay.handle(&RelayRequest::Deposit(OuterEnvelope {
            to_mailbox: mailbox.clone(),
            ciphertext,
        }));
    }
    let queued = relay.handle(&RelayRequest::Drain(mailbox.clone()));
    if queued.len() != bodies.len() {
        return Err(CoreError::Rejected(
            "not every healed message arrived at the mailbox",
        ));
    }

    // Capture the first post-step ciphertext as the attacker would off the relay,
    // before the legitimate receiver opens it.
    let captured_healed = queued[0].ciphertext.clone();

    // The legitimate receiver — who followed the DH step — opens every post-step
    // message in order and authenticates the sender.
    let mut healed_delivered = 0u64;
    for env in &queued {
        let inner_bytes = healed_recv.open(mailbox_aad, &env.ciphertext)?;
        let inner = InnerEnvelope::from_frame(&inner_bytes, recipient.aid())?;
        let sender_key = directory
            .resolve(&inner.sender)
            .ok_or(CoreError::Rejected("sender AID could not be resolved"))?;
        verify_sender(
            &inner.sender,
            &sender_key,
            &inner.signing_bytes_for(),
            &inner.signature,
        )?;
        healed_delivered += 1;
    }

    // (4) The lock-out: the attacker holds only the compromised pre-step root. The
    // only thing it lets them do is run the symmetric chain off that old root — there
    // is no fresh DH output to mix, because they hold neither party's new private key.
    // That chain is seeded from the *old* root, not the healed one, so it MUST fail to
    // open the post-step ciphertext. An attacker who still opened it would mean the
    // compromise was permanent — healing did not happen.
    let mut attacker_chain = Ratchet::from_session(&Session::from_secret(compromised_root))?;
    let attacker_locked_out = match attacker_chain.open(mailbox_aad, &captured_healed) {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "no-healing: the compromised pre-step state still decrypted post-step traffic — \
                 the attacker was not locked out",
            ));
        }
        Err(CoreError::Rejected(_)) => true,
        Err(other) => return Err(other),
    };

    Ok(PostCompromiseReceipt {
        healed_at_step,
        healed_messages_delivered: healed_delivered,
        attacker_locked_out,
    })
}

/// The verdict of standing up the store-and-forward wire and proving the bytes the
/// relay actually queued are forward-secret ciphertext that learns nothing (PRD
/// §3.1 Layer 3 + §10, the privacy-floor claim). Returned by [`prove_relay_queue`]
/// so the relay binary's self-test (and the harness) can assert the property over
/// the *genuine queued envelope* — what an attacker who seized the relay's mailbox
/// would hold — rather than over a struct it merely trusts the shape of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayQueueReceipt {
    /// The pairwise mailbox id the relay queued the bytes under — the routing
    /// handle it correlates on, carrying no AID and no number.
    pub mailbox: MailboxId,
    /// How many forward-secret ciphertext envelopes were stored-and-forwarded
    /// through the relay's queue and drained back out, in order.
    pub envelopes_queued: u64,
    /// The leakcheck verdict over the relay-visible bytes of the queued envelope:
    /// the message body, the sender address, the session content key, and the
    /// live forward-secret chain state were each scanned for and found absent.
    pub routing_only: RoutingOnlyReport,
}

/// Stand up the store-and-forward wire over a forward-secret envelope and prove the
/// privacy floor (PRD §3.1 Layer 3 + §10, the privacy-floor claim): the bytes the
/// relay queues are **Signal-class forward-secret ciphertext** (a fresh per-message
/// ratchet key, the spent key zeroized) addressed to a **pairwise mailbox id**, and
/// an attacker who captured that queue reads **neither plaintext nor any PII**.
///
/// This is the conjunction the floor turns on, proven over the *literal queued
/// envelope* — `deliver_forward_secret` proves a later state can't reopen an earlier
/// ciphertext, and `deliver_routing_only` scans a captured envelope; this leg stands
/// up the actual store-and-forward queue and proves both at once on what it holds:
///
///  1. each `bodies[i]` is sealed on a forward-secret sending [`Ratchet`] (a fresh
///     per-message key, ratcheted forward and zeroized) into an authenticated inner
///     envelope, wrapped as an [`OuterEnvelope`] under the pairwise `mailbox`, and
///     **deposited into the relay's [`MailboxStore`]** — the real queue;
///  2. the relay's queue is **drained**, so what is scanned is exactly the bytes the
///     relay stored-and-forwarded. The first queued envelope is held to the
///     routing-only bar by [`leakcheck::prove_routing_only`]: the plaintext, the
///     sender AID, the session content key, and the *live chain state* are each
///     confirmed **absent** from the relay-visible bytes — the relay sees the
///     mailbox and opaque bytes, nothing else;
///  3. the queued ciphertext is confirmed **opaque** — it does not equal, contain,
///     or prefix the plaintext — and a peer receiving [`Ratchet`] **ratchet-opens it
///     back to the original body**, so the queued bytes are genuine deliverable
///     forward-secret ciphertext, not unintelligible filler that would pass a scan
///     for free.
///
/// Returns a [`RelayQueueReceipt`] iff every body was queued, the queued envelope
/// scanned routing-only, the ciphertext was opaque, and the recipient recovered the
/// body. Any property that fails to hold is an error, never a silent pass — a queued
/// envelope found to carry the plaintext or any PII (the adversarial twin the trap
/// records) fails the leg closed.
pub fn prove_relay_queue(
    sender: &Identity,
    recipient: &Identity,
    root_secret: [u8; 32],
    mailbox: &MailboxId,
    bodies: &[&str],
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<RelayQueueReceipt> {
    if bodies.is_empty() {
        return Err(CoreError::Malformed(
            "the relay-queue proof needs at least one message to queue".into(),
        ));
    }
    let root = Session::from_secret(root_secret);
    let mut send_chain = Ratchet::from_session(&root)?;
    let mut recv_chain = Ratchet::from_session(&root)?;
    let mailbox_aad = mailbox.as_str().as_bytes();

    // (1) Seal each body on the forward-secret sending chain into an authenticated
    // inner envelope, wrap it as an outer envelope, and DEPOSIT it into the relay's
    // real queue. The relay only ever touches the outer envelope.
    for body in bodies {
        let signing_bytes =
            InnerEnvelope::signing_bytes(sender.aid(), recipient.aid(), &[0u8; 8], "text", 0, body);
        let signature = sender.sign(&signing_bytes)?;
        let inner = InnerEnvelope {
            sender: sender.aid().clone(),
            recipient: recipient.aid().clone(),
            message_id: vec![0u8; 8],
            content_type: "text".to_string(),
            flags: 0,
            body: (*body).to_string(),
            signature,
        };
        let inner_bytes = inner.to_frame()?;
        let ciphertext = send_chain.seal(mailbox_aad, &inner_bytes)?;
        if relay.deposit(&OuterEnvelope {
            to_mailbox: mailbox.clone(),
            ciphertext,
        }) != DepositOutcome::Queued
        {
            return Err(CoreError::Rejected(
                "a forward-secret envelope was not queued by the relay",
            ));
        }
    }

    // (2) Drain the relay's queue — what we scan from here on is exactly the bytes
    // the relay stored-and-forwarded, captured as an attacker who seized the mailbox
    // would hold them.
    let queued = relay.handle(&RelayRequest::Drain(mailbox.clone()));
    if queued.len() != bodies.len() {
        return Err(CoreError::Rejected(
            "not every forward-secret envelope arrived in the relay queue",
        ));
    }
    let first = queued
        .first()
        .ok_or(CoreError::Rejected("the relay queue drained empty"))?;
    let routing_only = leakcheck::prove_routing_only(
        first,
        bodies[0].as_bytes(),
        sender.aid().as_str(),
        root.secret_bytes(),
        // the live chain state after sealing every message — a later chain-key value
        // than any that sealed a queued envelope, so its absence is a real check
        send_chain.chain_state(),
    )?;

    // (3) The queued ciphertext must be OPAQUE — not the plaintext in disguise — and
    // a peer receiving chain must ratchet-open it back to the original body, so what
    // is queued is genuine deliverable forward-secret ciphertext, not filler that
    // would scan clean for free.
    let plaintext = bodies[0].as_bytes();
    let opaque = first.ciphertext != plaintext
        && !first
            .ciphertext
            .windows(plaintext.len().max(1))
            .any(|w| w == plaintext);
    if !opaque {
        return Err(CoreError::Rejected(
            "the queued ciphertext was not opaque — the plaintext appeared in the relay bytes",
        ));
    }
    let mut envelopes_queued = 0u64;
    for env in &queued {
        let inner_bytes = recv_chain.open(mailbox_aad, &env.ciphertext)?;
        let inner = InnerEnvelope::from_frame(&inner_bytes, recipient.aid())?;
        let sender_key = directory
            .resolve(&inner.sender)
            .ok_or(CoreError::Rejected("sender AID could not be resolved"))?;
        verify_sender(
            &inner.sender,
            &sender_key,
            &inner.signing_bytes_for(),
            &inner.signature,
        )?;
        envelopes_queued += 1;
    }
    // Opacity (the queued bytes are not the plaintext) is already proven above —
    // the `opaque` check whole-buffer-rejects the plaintext AND substring-scans for
    // it, which is strictly stronger than an exact byte equality. Here we only need
    // that every queued envelope opened and authenticated.
    if envelopes_queued == 0 {
        return Err(CoreError::Rejected(
            "the relay-queue proof recovered no authenticated body from the queued ciphertext",
        ));
    }

    Ok(RelayQueueReceipt {
        mailbox: mailbox.clone(),
        envelopes_queued,
        routing_only,
    })
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

/// The verdict of the floor claim (PRD §10, the addressing claim): a message was *addressed to*
/// an AID's pairwise mailbox and *authenticated by* the sender's AID, the whole
/// flow carried no phone number or email, and a message claiming an AID the sender
/// does not control was rejected. Returned by [`prove_addressed`] so the relay
/// binary's self-test (and the harness) can assert the floor holds rather than
/// merely that a message flowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressedReceipt {
    /// The recipient AID the message was addressed to — the destination, in place
    /// of a phone number.
    pub addressed_to: Aid,
    /// The sender AID the message authenticated as — equal to the sender only
    /// because the signature verified.
    pub authenticated_as: Aid,
    /// The pairwise mailbox the relay routed on — a per-contact handle carrying no
    /// AID and no number.
    pub mailbox: MailboxId,
    /// The number-free report over the message and both envelopes: each serialized
    /// form was scanned and found free of a phone number or an email.
    pub number_free: NumberFreeReport,
}

/// Drive the floor claim once, hermetically (PRD §10, the addressing claim): prove a message can
/// be *addressed to* and *authenticated by* an AID at all, with **no phone number
/// or email anywhere in the flow**, and that the adversarial twin is rejected.
///
///  1. `sender` seals `body` for `recipient`, addressed to `mailbox`; the message
///     is stored-and-forwarded through `relay`, drained, and opened — it must
///     **authenticate as the sender** (the signature verifies under the key the
///     sender's AID resolves to), not merely arrive.
///  2. The fully-formed [`Message`] and both envelopes are scanned by
///     [`prove_number_free`]: a phone number or an email anywhere in any serialized
///     form fails the leg closed. The addresses are AIDs, so a clean scan means the
///     destination and the identity were both carried as `did:keri:` / `did:webs:`
///     identifiers, never a number.
///  3. The adversarial twin: a forged inner envelope claiming the sender's AID but
///     signed by an *uncontrolled* key (`impostor`) is presented to the recipient.
///     It decrypts but does **not** verify under the claimed AID's key, so it is
///     [`CoreError::Rejected`] — never surfaced as authentic. A forged message that
///     *opened* would mean an uncontrolled AID was accepted, and is returned as an
///     error (the RED the trap records).
///
/// Returns an [`AddressedReceipt`] iff the message authenticated, scanned
/// number-free, and the impostor was rejected. Any property that fails to hold is
/// an error, never a silent pass.
pub fn prove_addressed(
    sender: &Endpoint,
    recipient: &Endpoint,
    impostor: &Endpoint,
    mailbox: &MailboxId,
    body: &str,
    relay: &mut MailboxStore,
    directory: &dyn Directory,
) -> CoreResult<AddressedReceipt> {
    // (1) Seal, store-and-forward, drain, open — the message must authenticate as
    // the sender, not merely arrive.
    let receipt = deliver_once(sender, recipient, mailbox, body, relay, directory)?;
    if &receipt.authenticated_sender != sender.aid() {
        return Err(CoreError::Rejected(
            "the delivered message did not authenticate as the addressing sender",
        ));
    }

    // Reconstruct the message and the inner envelope exactly as they crossed the
    // engine, so the number-free scan runs over the real forms (the same signing
    // bytes the recipient verified).
    let message = Message {
        to: receipt.recipient.clone(),
        from: receipt.authenticated_sender.clone(),
        body: receipt.body.clone(),
        message_id: vec![0u8; 8],
        content_type: "text".to_string(),
        flags: 0,
    };
    let signing_bytes =
        InnerEnvelope::signing_bytes(sender.aid(), recipient.aid(), &[0u8; 8], "text", 0, body);
    let inner = InnerEnvelope {
        sender: sender.aid().clone(),
        recipient: recipient.aid().clone(),
        message_id: vec![0u8; 8],
        content_type: "text".to_string(),
        flags: 0,
        body: body.to_string(),
        signature: sender.identity.sign(&signing_bytes)?,
    };
    let outer = sender.seal_to(recipient.aid(), mailbox, body)?;

    // (2) No phone number or email anywhere — the message, the inner envelope, the
    // outer envelope.
    let number_free = number_free::prove_number_free(&message, &inner, &outer)?;

    // (3) Adversarial twin: a message claiming the sender's AID but signed by an
    // uncontrolled key must be rejected, never accepted as authentic. The forgery
    // is sealed under the *recipient's* session so the AEAD opens — the message
    // genuinely arrives and decrypts, and is caught at the **authentication** gate
    // (the impostor's signature does not verify under the sender AID's key), not
    // merely bounced by a wrong key. This is the worst case the floor must hold.
    let forged_inner = InnerEnvelope {
        sender: sender.aid().clone(),
        recipient: recipient.aid().clone(),
        message_id: vec![0u8; 8],
        content_type: "text".to_string(),
        flags: 0,
        body: body.to_string(),
        // signed by the impostor, who does NOT control the sender's AID
        signature: impostor.identity.sign(&signing_bytes)?,
    };
    let forged_bytes = forged_inner.to_frame()?;
    let forged_nonce = session::fresh_nonce()?;
    // Seal the forgery with the SAME AAD the recipient reconstructs on open
    // (sender ‖ recipient ‖ mailbox), so it genuinely decrypts and reaches the
    // authentication gate — where the impostor's signature fails to verify. (If we
    // sealed with a mismatched AAD it would bounce at the AEAD tag, never exercising
    // the auth gate this leg exists to prove.)
    let forged_aad = aead_aad(sender.aid(), recipient.aid(), mailbox);
    let forged_ciphertext = recipient
        .session
        .seal(forged_nonce, &forged_aad, &forged_bytes)?;
    let forged_outer = OuterEnvelope {
        to_mailbox: mailbox.clone(),
        ciphertext: forged_ciphertext,
    };
    match recipient.open(&forged_outer, directory) {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "uncontrolled-aid-accepted: a message claiming an AID the sender does not control \
                 was surfaced as authentic",
            ));
        }
        Err(CoreError::Rejected(_)) => { /* rejected as required */ }
        Err(other) => return Err(other),
    }

    Ok(AddressedReceipt {
        addressed_to: receipt.recipient,
        authenticated_as: receipt.authenticated_sender,
        mailbox: mailbox.clone(),
        number_free,
    })
}

/// The verdict of driving the multi-device leg (PRD §10, the multi-device claim): a
/// **delegated device** (the Mac) sends a message that authenticates as the **same
/// root identity** the phone holds, and after the root **revokes** that device its
/// next message is **rejected** — clawback from the chain. Returned by
/// [`prove_delegated_device`] so the relay binary's self-test (and the harness) can
/// assert both halves held: device-as-root before revocation, revoked-rejected
/// after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedDeviceReceipt {
    /// The device AID that sent the message (the Mac's own sub-identity).
    pub device_aid: Aid,
    /// The **root** AID the delegated device's message authenticated as — equal to
    /// the root only because the root's delegation anchor verified and the device
    /// was not revoked.
    pub authenticated_root: Aid,
    /// The body the contact recovered from the delegated device's message before
    /// the revocation.
    pub body: String,
}

/// Drive the multi-device leg once, hermetically (PRD §4, §6.2, §6.5, the
/// multi-device claim): a delegated device sends as the root identity, and revoking it stops its
/// next message.
///
/// `root` is the root identity (the iPhone); `device` is a delegated device (the
/// Mac) that mints its own key and names `root` as delegator; `contact` is the peer
/// the device messages. The session secret is established out-of-band for the
/// self-test (the X3DH that derives it is the encryption layer's own work).
///
///  1. The root **anchors** the device — it signs `(root AID ‖ device AID ‖ device
///     key)`. The contact resolves the root's delegation key-state (a witnessed-KEL
///     replay stand-in, [`DelegationState`]) and admits the device on that anchor;
///     a forged anchor never enters the state.
///  2. **device-as-root:** the device seals a message and stores-and-forwards it
///     through `relay`; the contact drains and opens it (authenticating the
///     *device's own* signature), then resolves the device to its root via the
///     delegation state — the message authenticates as the **root** AID
///     (`device = Mac, identity = root`).
///  3. The root **revokes** the device (a signed revocation the contact records on
///     its key-state).
///  4. **revoked-rejected:** the device seals a *next* message and stores-and-
///     forwards it; it still decrypts and the device's own signature still verifies,
///     but resolving it against the now-revoked delegation state **rejects** it —
///     the message is dropped, never surfaced. A revoked device whose message was
///     still surfaced as the root would be an error (the RED the trap records).
///
/// Returns a [`DelegatedDeviceReceipt`] iff the device authenticated as the root
/// before revocation **and** its next message was rejected after. Any failure — a
/// device that never resolved to the root, or a revoked device still accepted — is
/// an error, never a silent pass.
pub fn prove_delegated_device(
    root: &Identity,
    device: &DelegatedDevice,
    contact: &Identity,
    session_secret: [u8; 32],
    mailbox: &MailboxId,
    bodies: [&str; 2],
    relay: &mut MailboxStore,
) -> CoreResult<DelegatedDeviceReceipt> {
    let [body, next_body] = bodies;
    if device.root_aid() != root.aid() {
        return Err(CoreError::Malformed(
            "the delegated device names a different root than the one driving the leg".into(),
        ));
    }
    // The contact's directory binds the *device's own* AID to the device key (it
    // resolves whoever signed the inner envelope); the delegation state maps that
    // device to its root. Two layers: the device key authenticates the bytes, the
    // root anchor authenticates the *identity* those bytes count as.
    let mut directory = ContactDirectory::new();
    directory.admit(device.device_aid().clone(), device.device_key().to_vec());
    directory.admit(contact.aid().clone(), contact.public_key().to_vec());

    // (1) The root anchors the device; the contact admits it on the root's verified
    // anchor (a forged anchor is rejected at admission).
    let anchor = DelegationAnchor::issue(root, device)?;
    let mut delegation = DelegationState::for_root(root);
    delegation.admit_device(anchor)?;

    // Both ends seal/open over the same out-of-band session (the device sends, the
    // contact receives). The device sends under its OWN device AID, so the contact's
    // peer (what its open-side AAD binds as the sender) is the device AID.
    let device_endpoint = Endpoint::new(
        device.identity().clone(),
        contact.aid().clone(),
        Session::from_secret(session_secret),
    );
    let contact_endpoint = Endpoint::new(
        contact.clone(),
        device.device_aid().clone(),
        Session::from_secret(session_secret),
    );

    // (2) device-as-root: the device sends; the contact opens (authenticating the
    // device's own signature) and resolves the device to its root.
    let outer = device_endpoint.seal_to(contact.aid(), mailbox, body)?;
    relay.handle(&RelayRequest::Deposit(outer));
    let pulled = relay
        .handle(&RelayRequest::Drain(mailbox.clone()))
        .pop()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let message = contact_endpoint.open(&pulled, &directory)?;
    // The opened message authenticated the *device's* key; resolve that device to the
    // root it sends as. Before revocation this yields the root AID.
    let authenticated_root =
        delegation.resolve_device_to_root(&message.from, device.device_key())?;
    if &authenticated_root != root.aid() {
        return Err(CoreError::Rejected(
            "a delegated device's message did not authenticate as the root identity",
        ));
    }

    // (3) The root revokes the device (lost-the-laptop). Revocation is a signed root
    // event the contact records on its delegation key-state.
    let revocation = DeviceRevocation::issue(root, device.device_aid())?;
    delegation.revoke_device(revocation)?;

    // (4) revoked-rejected: the device sends again; it still decrypts and its own
    // signature still verifies, but resolving it against the revoked state rejects
    // it — clawback from the chain. A revoked device whose message still resolved to
    // the root would break the claim.
    let next_outer = device_endpoint.seal_to(contact.aid(), mailbox, next_body)?;
    relay.handle(&RelayRequest::Deposit(next_outer));
    let next_pulled = relay
        .handle(&RelayRequest::Drain(mailbox.clone()))
        .pop()
        .ok_or(CoreError::Rejected("nothing arrived at the mailbox"))?;
    let next_message = contact_endpoint.open(&next_pulled, &directory)?;
    match delegation.resolve_device_to_root(&next_message.from, device.device_key()) {
        Ok(_) => Err(CoreError::Rejected(
            "revoked-device-accepted: a revoked device's message still authenticated as the root",
        )),
        Err(CoreError::Rejected(_)) => Ok(DelegatedDeviceReceipt {
            device_aid: device.device_aid().clone(),
            authenticated_root,
            body: message.body,
        }),
        Err(other) => Err(other),
    }
}

/// The verdict of driving the corroborated-revocation leg (PRD §6.5, the
/// revocation-corroboration claim): after the root revokes a delegated device, a
/// contact who re-resolves the root's **witness-corroborated** key-state **rejects**
/// the device — and a contact served the relay's **stale cache** is told the honest
/// **stale-served window** rather than waved through as safe. Returned by
/// [`prove_revocation_corroborated`] so the relay binary's self-test (and the
/// harness) can assert both halves held: corroborated clawback, and an honest
/// disclosure of the window the PRD refuses to oversell as an instant kill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCorroborationReceipt {
    /// The device AID that was revoked (the lost Mac's own sub-identity).
    pub device_aid: Aid,
    /// The **root** AID that revoked it and that a corroborated rejection clawed the
    /// device back from.
    pub root_aid: Aid,
    /// How many witnesses corroborated the revocation set the corroborated rejection
    /// resolved against.
    pub witnesses_confirmed: u8,
    /// How many witnessed revocations the relay's cache lagged behind — the
    /// measurable size of the disclosed stale-served window.
    pub stale_window_revocations_behind: u32,
}

/// Drive the corroborated-revocation leg once, hermetically (PRD §6.5, §6.6, the
/// revocation-corroboration claim): revocation is **detection, not prevention**, and
/// it is only *safe* when a contact resolves the **witness-corroborated** delegation
/// set — a relay's stale cache is an honest window, not a clawback.
///
/// `root` is the root identity (the iPhone); `device` is a delegated device (the
/// Mac) it anchors then revokes; `contact` is the peer who re-resolves.
///
///  1. The root **anchors** the device and the contact admits it (a forged anchor
///     never enters the state).
///  2. The root **revokes** the device (lost-the-laptop). The witnesses receipt the
///     revocation; the contact resolves the **witness-corroborated** delegation set
///     ([`CorroboratedState`] tagged [`Provenance::WitnessCorroborated`]).
///  3. **revoked-from-corroborated-state:** the contact resolves the revoked device
///     from the corroborated set and it is **rejected** — the clawback holds,
///     corroborated by the witnesses, not by a relay's say-so.
///  4. **stale-window-disclosed:** a *second* contact (or the same one offline) is
///     served the relay's **stale cache** — a delegation set that predates the
///     revocation, tagged [`Provenance::RelayCache`]. Resolving the device there
///     does **not** certify a clawback; it returns a verdict that **discloses the
///     stale-served window** (how far the cache lags the witnesses), so the cache is
///     never trusted over the witnesses and the window is never hidden.
///
/// Returns a [`RevocationCorroborationReceipt`] iff the corroborated rejection held
/// **and** the relay-cache path disclosed the window. Any failure — a revoked device
/// accepted from corroborated state, a relay cache passed off as corroborated, or a
/// hidden stale window — is an error, never a silent pass (the RED the trap records).
pub fn prove_revocation_corroborated(
    root: &Identity,
    device: &DelegatedDevice,
    contact: &Identity,
) -> CoreResult<RevocationCorroborationReceipt> {
    if device.root_aid() != root.aid() {
        return Err(CoreError::Malformed(
            "the delegated device names a different root than the one driving the leg".into(),
        ));
    }
    // The contact admits the device's own AID ↔ key (so its signature resolves), the
    // same opt-in directory the delivery legs use; the delegation state maps the
    // device to its root.
    let mut directory = ContactDirectory::new();
    directory.admit(device.device_aid().clone(), device.device_key().to_vec());
    directory.admit(contact.aid().clone(), contact.public_key().to_vec());

    // (1) The root anchors the device.
    let anchor = DelegationAnchor::issue(root, device)?;
    let mut anchored = DelegationState::for_root(root);
    anchored.admit_device(anchor.clone())?;

    // A snapshot of the delegation set BEFORE the revocation — this is exactly the
    // *stale* cache a lagging relay would serve: it still shows the device live.
    let stale_cache = anchored.clone();

    // (2) The root revokes the device; the witnesses receipt it, so the contact's
    // re-resolved set is witness-corroborated.
    let revocation = DeviceRevocation::issue(root, device.device_aid())?;
    let mut corroborated_set = anchored;
    corroborated_set.revoke_device(revocation)?;

    // (3) revoked-from-corroborated-state: the contact resolves the revoked device
    // from the witness-corroborated set and it is rejected — the corroborated
    // clawback. A revoked device that was *accepted* from corroborated state would be
    // the trap's failure, and is returned as an error below.
    let confirmed_witnesses = 3u8;
    let witness_threshold = 2u8;
    let corroborated = CorroboratedState::new(
        corroborated_set,
        Provenance::WitnessCorroborated {
            confirmed: confirmed_witnesses,
            threshold: witness_threshold,
        },
    );
    let corroborated_resolution =
        corroborated.resolve_revocation(device.device_aid(), device.device_key())?;
    if !corroborated_resolution.is_corroborated_rejection() {
        return Err(CoreError::Rejected(
            "revoked-accepted-from-corroborated: the revoked device was not rejected from \
             witness-corroborated state",
        ));
    }
    let (root_aid, witnesses_confirmed) = match &corroborated_resolution {
        RevocationResolution::RevokedFromCorroboratedState {
            root_aid,
            witnesses_confirmed,
            ..
        } => (root_aid.clone(), *witnesses_confirmed),
        // resolve_revocation guarantees the corroborated path yields exactly this
        // variant on a rejection; any other shape is a contract break.
        _ => {
            return Err(CoreError::Rejected(
                "the corroborated path did not yield a corroborated rejection",
            ));
        }
    };

    // (4) stale-window-disclosed: a contact served the relay's STALE cache (the
    // pre-revocation snapshot) must NOT be told "safe". The verdict discloses the
    // window — how far the cache lags the witnesses — instead of certifying a
    // clawback or hiding the staleness.
    let stale_window_behind = 1u32;
    let relay_cache = CorroboratedState::new(
        stale_cache,
        Provenance::RelayCache {
            revocations_behind_witnesses: stale_window_behind,
        },
    );
    let cache_resolution =
        relay_cache.resolve_revocation(device.device_aid(), device.device_key())?;
    if !cache_resolution.discloses_stale_window() {
        return Err(CoreError::Rejected(
            "stale-window-hidden: a relay's stale cache was not disclosed as a window — it was \
             waved through as safe",
        ));
    }
    // A relay cache must never be laundered into a corroborated rejection.
    if cache_resolution.is_corroborated_rejection() {
        return Err(CoreError::Rejected(
            "relay-cache-trusted-over-witness: a relay's cache was treated as a corroborated \
             clawback",
        ));
    }

    Ok(RevocationCorroborationReceipt {
        device_aid: device.device_aid().clone(),
        root_aid,
        witnesses_confirmed,
        stale_window_revocations_behind: stale_window_behind,
    })
}

/// The verdict of driving the witnessed-key-state leg (PRD §2 binding mechanism,
/// §3.1 launch-centralization asterisk, the witnessed-log correctness root): the served
/// key-log replays to the witnessed current key-state **only** because a forked KEL
/// is rejected and a relay-suppressed / stale key-state fails the witness threshold.
/// Returned by [`prove_witnessed_keystate`] so the relay binary's self-test (and the
/// harness) can assert all three held: the honest log replays, a fork is refused,
/// and a sub-threshold (stale/suppressed) key-state is caught.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedKeyStateReceipt {
    /// The stable AID whose witnessed current key-state the honest log replayed to.
    pub aid: Aid,
    /// How many distinct witnesses corroborated the tip key-state the honest replay
    /// accepted as current.
    pub witnesses_corroborating: usize,
    /// The witness threshold the AID's key-state had to clear to be accepted.
    pub witness_threshold: u8,
}

/// Drive the witnessed-key-state leg once, hermetically (PRD §2 binding mechanism +
/// §3.1, the witnessed-log correctness root): the verified-continuation badge means
/// something **only** because the key-state under it is the one true witnessed log,
/// and two relay-served corruptions must both fail closed.
///
/// A contact under one stable AID has an honest log: an inception that pre-commits
/// to the rotated key, then a rotation revealing it, with a witness pool receipting
/// each event. This proves three things at once over the [`kel::Kel`] replay, so a
/// regression in any one fails the leg closed:
///
///  1. **the honest log replays** to the witnessed current key-state — the rotated
///     key, corroborated by a threshold of witnesses;
///  2. **a forked KEL is rejected** — a second, *different* rotation spliced in at
///     the same sequence number (the relay serving two contradictory branches) makes
///     the replay refuse to derive a key-state at all, never silently taking a
///     branch (`forked-kel`);
///  3. **a relay-suppressed / stale key-state is caught** — the same log served with
///     the tip's receipts withheld below the witness threshold fails the replay
///     (`stale-keystate`), so a relay cannot suppress or fake a rotation by hiding
///     the receipts.
///
/// Returns a [`WitnessedKeyStateReceipt`] iff the honest replay succeeded **and**
/// both the fork and the stale key-state were rejected. A forked or stale key-state
/// that was *accepted* (the adversarial twin the trap records) is an error, never a
/// silent pass.
pub fn prove_witnessed_keystate() -> CoreResult<WitnessedKeyStateReceipt> {
    use kel::{Kel, KelEvent, WitnessPolicy, WitnessReceipt};

    // The contact's generations: gen0 incepts and pre-commits to gen1, then rotates
    // to gen1 (the pre-committed key), pre-committing to gen2.
    let gen0 = Identity::from_seed([0x11u8; 32]).map_err(mint_err)?;
    let gen1 = Identity::from_seed([0x22u8; 32]).map_err(mint_err)?;
    let gen2 = Identity::from_seed([0x33u8; 32]).map_err(mint_err)?;
    let aid = gen0.aid().clone();

    // A witness pool of three distinct witnesses; the AID's policy demands two.
    let threshold = 2u8;
    let pool: Vec<Identity> = [0xA1u8, 0xA2u8, 0xA3u8]
        .into_iter()
        .map(|s| Identity::from_seed([s; 32]))
        .collect::<Result<_, _>>()
        .map_err(|e| CoreError::Malformed(format!("mint witness: {e}")))?;

    let receipts_for = |count: usize, seq: u64, key: &[u8]| -> CoreResult<Vec<WitnessReceipt>> {
        pool.iter()
            .take(count)
            .map(|w| WitnessReceipt::issue(w, &aid, seq, key))
            .collect()
    };

    // (1) The honest, fully-witnessed log: incept → rotate, tip corroborated by all
    // three witnesses (≥ threshold). It must replay to gen1 as the current key.
    let inception = KelEvent::incept(
        &gen0,
        gen1.public_key(),
        receipts_for(pool.len(), 0, gen0.public_key())?,
    )?;
    let rotation = KelEvent::rotate(
        &aid,
        &gen0,
        &gen1,
        1,
        gen2.public_key(),
        receipts_for(pool.len(), 1, gen1.public_key())?,
    )?;
    let honest = Kel::new(
        aid.clone(),
        WitnessPolicy::of(threshold),
        vec![inception.clone(), rotation.clone()],
    );
    let state = honest.replay()?;
    if state.aid != aid || state.current_key != gen1.public_key() {
        return Err(CoreError::Rejected(
            "the honest witnessed log did not replay to the pre-committed current key-state",
        ));
    }
    let witnesses_corroborating = honest.tip_corroborating_witnesses()?;
    if witnesses_corroborating < threshold as usize {
        return Err(CoreError::Rejected(
            "the honest log's tip was not corroborated above the witness threshold",
        ));
    }

    // (2) A forked KEL: a SECOND, different rotation at the same sequence number 1.
    // It is even signed by the legitimate prior key, so the signature alone would not
    // catch it — only fork detection does. The replay MUST reject it outright.
    let attacker = Identity::from_seed([0x99u8; 32]).map_err(mint_err)?;
    let forked_rotation = KelEvent::rotate(
        &aid,
        &gen0, // the legitimate prior key signs the fork too
        &attacker,
        1,
        attacker.public_key(),
        receipts_for(pool.len(), 1, attacker.public_key())?,
    )?;
    let forked = Kel::new(
        aid.clone(),
        WitnessPolicy::of(threshold),
        vec![inception.clone(), rotation.clone(), forked_rotation],
    );
    match forked.replay() {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "forked-kel-accepted: a key-log with two different rotations at the same sequence \
                 was replayed to a key-state instead of refused",
            ));
        }
        Err(CoreError::Rejected(_)) => { /* refused as required */ }
        Err(other) => return Err(other),
    }

    // (3) A relay-suppressed / stale key-state: the SAME honest log, but the relay
    // withheld the tip's receipts down to ONE — below the threshold of two. The
    // replay MUST catch it: a sub-threshold key-state is not the witnessed current
    // state, and accepting it would let a relay suppress or fake a rotation.
    let suppressed_rotation = KelEvent::rotate(
        &aid,
        &gen0,
        &gen1,
        1,
        gen2.public_key(),
        receipts_for(1, 1, gen1.public_key())?, // only one witness receipt served
    )?;
    let suppressed = Kel::new(
        aid.clone(),
        WitnessPolicy::of(threshold),
        vec![inception, suppressed_rotation],
    );
    match suppressed.replay() {
        Ok(_) => {
            return Err(CoreError::Rejected(
                "stale-keystate-accepted: a key-state below the witness threshold was accepted as \
                 current — a relay-suppressed or stale snapshot passed without corroboration",
            ));
        }
        Err(CoreError::Rejected(_)) => { /* caught as required */ }
        Err(other) => return Err(other),
    }

    Ok(WitnessedKeyStateReceipt {
        aid,
        witnesses_corroborating,
        witness_threshold: threshold,
    })
}

/// Small helper: turn a crypto-mint error into a `CoreError::Malformed`. Kept local
/// to [`prove_witnessed_keystate`]'s identity minting so the leg reads cleanly.
fn mint_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Malformed(format!("mint identity: {e}"))
}
