// This is a CLI process boundary: the relay binary prints its banner/diagnostics
// to stdout/stderr and reads its configuration from the environment. These are the
// sanctioned boundary allowances every binary in this workspace takes.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::disallowed_methods)]
#![forbid(unsafe_code)]

//! # murmur-relay — the untrusted store-and-forward mailbox (the binary)
//!
//! A relay is dumb and untrusted by design (PRD §3.1, Layer 3). It accepts an
//! opaque mailbox id and opaque ciphertext, queues it for an offline recipient,
//! and lets that recipient pull or subscribe to drain the mailbox. It never sees
//! plaintext, a sender AID, or a phone number — unlike Signal's relay it never
//! had a number to begin with.
//!
//! The binary reports its version, and `serve` drives the store-and-forward
//! queue. The network wire (HTTPS / WebSocket / QUIC) that exposes the queue to
//! remote devices is the relay's later surface; what `serve` proves *today* is
//! the end-to-end leg itself, hermetically: a message sealed by one endpoint is
//! stored-and-forwarded through the relay's `MailboxStore`, drained by the other
//! endpoint, and verified+decrypted — arriving authenticated as the sender. The
//! relay only ever touches the outer envelope (a mailbox id and opaque bytes),
//! so the leg it proves never lets it see plaintext or a sender AID.

use std::process::ExitCode;

use murmur_core::{
    Aid, ContactDirectory, Endpoint, Identity, MailboxId, MailboxStore, PrekeyBundle,
    PrekeySecrets, Session, TrustState, deliver_forward_secret, deliver_once, deliver_rooted,
    deliver_routing_only, hold_relay_boundary, prove_addressed, prove_vetted,
    verified_rotation_rekey,
};

/// What the relay was asked to do.
enum Mode {
    /// Print the version and exit 0 — the liveness check the probe harness uses.
    Version,
    /// Drive the store-and-forward leg end-to-end.
    Serve,
    /// Anything else.
    Usage,
}

fn parse(args: &[String]) -> Mode {
    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => Mode::Version,
        Some("serve") | None => Mode::Serve,
        _ => Mode::Usage,
    }
}

/// Prove the floor claim (PRD §10, the addressing claim): a message is *addressed to* and
/// *authenticated by* an AID, with **no phone number or email anywhere in the
/// flow**, and a message claiming an AID the sender does not control is rejected.
///
/// A "desktop" endpoint seals a message for a "handset" endpoint, addressed to a
/// pairwise mailbox; it is stored-and-forwarded through the relay, drained, and
/// opened — authenticating as the desktop. The fully-formed message and both
/// envelopes are then scanned and found free of any dialable number or email
/// address (the addresses are `did:keri:` AIDs, not numbers). Finally an impostor
/// who does not control the desktop's AID forges a message claiming it; verified
/// against the desktop's resolved key it is rejected, never surfaced as authentic.
///
/// The output line carries the marker a reader greps for — `aid-authenticated`
/// over a number-free flow — and is itself written without any number- or
/// email-shaped token, because the claim under test is precisely that none belongs
/// in the flow.
fn run_addressed() -> Result<String, String> {
    let session_secret = [0x5au8; 32];
    let desktop = Endpoint::new(
        Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint desktop identity: {e}"))?,
        Session::from_secret(session_secret),
    );
    let handset = Endpoint::new(
        Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint handset identity: {e}"))?,
        Session::from_secret(session_secret),
    );
    // The impostor holds a key it controls — but NOT the desktop's AID key. It is
    // never admitted into the directory as the desktop.
    let impostor = Endpoint::new(
        Identity::from_seed([0x33u8; 32]).map_err(|e| format!("mint impostor identity: {e}"))?,
        Session::from_secret(session_secret),
    );

    // The handset admits the desktop's AID (opt-in contact, §8); the directory
    // stands in for a witnessed key-log replay.
    let mut directory = ContactDirectory::new();
    directory.admit(desktop.aid().clone(), desktop.public_key().to_vec());
    directory.admit(handset.aid().clone(), handset.public_key().to_vec());

    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:pairwise-handle");

    let receipt = prove_addressed(
        &desktop,
        &handset,
        &impostor,
        &mailbox,
        "see you at the usual place",
        &mut relay,
        &directory,
    )
    .map_err(|e| format!("the floor leg failed: {e}"))?;

    if &receipt.authenticated_as != desktop.aid() {
        return Err(format!(
            "addressed message authenticated as {} not the desktop",
            receipt.authenticated_as
        ));
    }

    Ok(format!(
        "aid-authenticated-number-free: a message was addressed to the recipient AID {to} via the \
         pairwise mailbox {mbx} and authenticated as the sender AID {from} — the message and both \
         envelopes were scanned and held only self-certifying identifiers ({scanned} forms scanned \
         clean, no telco identifier of any kind); a forgery claiming an AID the sender does not \
         control was rejected",
        to = receipt.addressed_to.as_str(),
        from = receipt.authenticated_as.as_str(),
        mbx = receipt.mailbox.as_str(),
        scanned = receipt.number_free.forms_scanned,
    ))
}

/// Drive one message all the way through the leg: a "Mac" endpoint seals a
/// message for a "phone" endpoint, deposits it in the relay's queue, the phone
/// drains and opens it, and the result must authenticate as the Mac. Returns the
/// proof line on success, or an error describing where the leg broke.
fn run_delivery() -> Result<String, String> {
    // Two endpoints of one conversation. In a real deployment the Mac and the
    // phone mint Secure-Enclave keys and derive the session over the pairing
    // channel (§6.2); for the relay's self-test they are built from fixed seeds
    // and a session secret established out-of-band (the X3DH that derives it is
    // the encryption layer's own later work).
    let session_secret = [0x5au8; 32];
    let mac = Endpoint::new(
        Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint Mac identity: {e}"))?,
        Session::from_secret(session_secret),
    );
    let phone = Endpoint::new(
        Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint phone identity: {e}"))?,
        Session::from_secret(session_secret),
    );

    // The phone admits the Mac's AID (opt-in contact, §8); the directory stands
    // in for a witnessed key-log replay.
    let mut directory = ContactDirectory::new();
    directory.admit(mac.aid().clone(), mac.public_key().to_vec());
    directory.admit(phone.aid().clone(), phone.public_key().to_vec());

    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:phone");

    let receipt = deliver_once(
        &mac,
        &phone,
        &mailbox,
        "sent from the Mac",
        &mut relay,
        &directory,
    )
    .map_err(|e| format!("the leg failed: {e}"))?;

    // The message must have authenticated as the Mac, not merely arrived.
    if &receipt.authenticated_sender != mac.aid() {
        return Err(format!(
            "arrived-unauthenticated: opened message authenticated as {} not the Mac",
            receipt.authenticated_sender
        ));
    }
    Ok(format!(
        "delivered-and-authenticated: a message sealed on the Mac was stored-and-forwarded \
         through the relay and arrived authenticated as {} on the phone",
        receipt.authenticated_sender
    ))
}

/// Prove the KERI→Signal join (PRD §10, the prekey-bundle claim): a session is
/// rooted only in a prekey bundle **verified** against the recipient's AID key,
/// and a bundle signed by the wrong key is rejected before any X3DH runs.
///
/// Two assertions, both required for the proof line:
///  * the good path — Bob publishes a bundle signed by his AID key, Alice
///    resolves Bob's AID, verifies the bundle, runs X3DH, and her message arrives
///    authenticated over the rooted session;
///  * the adversarial twin — Mallory publishes a bundle for Bob's AID signed with
///    *his own* key; verified against Bob's resolved key it is rejected, so no
///    session is ever rooted (the MITM the safety-number warning exists to catch).
fn run_rooted() -> Result<String, String> {
    // Alice (the sender / initiator) and Bob (the recipient who publishes a bundle).
    let alice = Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint Alice: {e}"))?;
    let bob = Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint Bob: {e}"))?;
    // Bob's Signal DH key material — DISTINCT from his AID signing key.
    let bob_prekeys = PrekeySecrets::from_seeds([0x31u8; 32], [0x32u8; 32]);

    // The directory stands in for a witnessed KEL replay: Alice admits Bob's AID
    // (opt-in contact, §8), which resolves to Bob's current key.
    let mut directory = ContactDirectory::new();
    directory.admit(alice.aid().clone(), alice.public_key().to_vec());
    directory.admit(bob.aid().clone(), bob.public_key().to_vec());

    // Good path: a verified bundle roots the session and the message authenticates.
    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:bob");
    let rooted = deliver_rooted(
        &alice,
        &bob,
        &bob_prekeys,
        [0x41u8; 32],
        [0x42u8; 32],
        &mailbox,
        "rooted in a verified bundle",
        &mut relay,
        &directory,
    )
    .map_err(|e| format!("the rooted leg failed: {e}"))?;
    if &rooted.authenticated_sender != alice.aid() {
        return Err(format!(
            "rooted message authenticated as {} not Alice",
            rooted.authenticated_sender
        ));
    }

    // Adversarial twin: Mallory publishes a bundle for Bob's AID signed with his
    // OWN key. We mint it by publishing under Mallory's identity but stamping Bob's
    // AID — verified against Bob's resolved key it MUST be rejected.
    let mallory = Identity::from_seed([0x55u8; 32]).map_err(|e| format!("mint Mallory: {e}"))?;
    let mallory_bundle = PrekeyBundle::publish(&mallory, &bob_prekeys)
        .map_err(|e| format!("mint Mallory's bundle: {e}"))?;
    let forged = PrekeyBundle {
        aid: bob.aid().clone(), // claims Bob's AID …
        signal_identity_key: mallory_bundle.signal_identity_key,
        signed_prekey: mallory_bundle.signed_prekey,
        signature: mallory_bundle.signature, // … but signed by Mallory
    };
    match forged.verify_rooted(bob.public_key()) {
        Ok(_) => {
            return Err(
                "wrong-key-bundle-accepted: a bundle signed by the wrong key rooted the session"
                    .to_string(),
            );
        }
        Err(_) => { /* rejected as required */ }
    }

    Ok(format!(
        "bundle-verified-against-aid: a session was rooted only in a prekey bundle \
         verified against {}'s current key (a distinct Signal identity key); a \
         wrong-key bundle was rejected before X3DH",
        rooted.rooted_aid
    ))
}

/// Prove forward secrecy across our wiring (PRD §10, the forward-secrecy claim):
/// a ciphertext
/// captured off the relay cannot be decrypted from a *later*, compromised session
/// state, and used message keys are zeroized.
///
/// The Mac seals several messages to the phone over a forward-secret ratchet;
/// each is stored-and-forwarded through the relay. We capture the first
/// ciphertext as an attacker would, let the phone's receiving chain advance past
/// it by draining the rest, then take that advanced ("compromised") receiving
/// state and prove it cannot decrypt the captured early ciphertext — its key was
/// ratcheted forward and zeroized. A later state that *did* decrypt the earlier
/// message would break forward secrecy and is returned as an error (the RED the
/// trap records).
fn run_forward_secret() -> Result<String, String> {
    let mac = Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint Mac: {e}"))?;
    let phone = Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint phone: {e}"))?;

    // The phone admits the Mac's AID (opt-in contact, §8); the directory stands in
    // for a witnessed KEL replay so each opened message authenticates as the Mac.
    let mut directory = ContactDirectory::new();
    directory.admit(mac.aid().clone(), mac.public_key().to_vec());
    directory.admit(phone.aid().clone(), phone.public_key().to_vec());

    // The X3DH root the two ends agreed (established out-of-band for the self-test).
    let root_secret = [0x5au8; 32];
    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:phone");
    let bodies = ["msg-0 (the captured one)", "msg-1", "msg-2", "msg-3"];

    let receipt = deliver_forward_secret(
        &mac,
        &phone,
        root_secret,
        &mailbox,
        &bodies,
        &mut relay,
        &directory,
    )
    .map_err(|e| format!("the forward-secret leg failed: {e}"))?;

    Ok(format!(
        "forward-secrecy-held: {} messages were store-and-forwarded over a ratcheted session; a \
         ciphertext captured at index {} could NOT be decrypted from the later compromised state \
         at index {} (used message keys zeroized)",
        receipt.messages_delivered, receipt.captured_index, receipt.compromised_index
    ))
}

/// Prove metadata hygiene over genuine wire bytes (PRD §10, the metadata-hygiene
/// claim): a message is sealed on each of the engine's two send paths, stored-and-
/// forwarded through the relay, and the outer envelope is captured exactly as the
/// relay queued it. A leakcheck-style scan over those captured bytes confirms they
/// carry **only** the pairwise mailbox id — the message body, the sender address,
/// the session key, and the forward-secret chain state are each found absent.
///
/// This is the relay-capture assertion the claim turns on: the scan runs over the
/// literal bytes the relay forwarded, so a green report means an attacker who
/// captured the envelope off the relay learns nothing but where to route it. A
/// leak in either path returns an error naming what escaped, failing the leg —
/// and the whole self-test — closed.
fn run_routing_only() -> Result<String, String> {
    let mac = Endpoint::new(
        Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint Mac identity: {e}"))?,
        Session::from_secret([0x5au8; 32]),
    );
    let phone = Endpoint::new(
        Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint phone identity: {e}"))?,
        Session::from_secret([0x5au8; 32]),
    );

    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:phone");

    let receipt = deliver_routing_only(
        &mac,
        phone.aid(),
        &mailbox,
        "the body the relay must never read",
        &mut relay,
    )
    .map_err(|e| format!("the envelope leaked: {e}"))?;

    // Both captures must agree on the mailbox they routed on — the one thing the
    // relay legitimately reads.
    if receipt.session_path.mailbox != mailbox || receipt.ratchet_path.mailbox != mailbox {
        return Err("captured envelope routed on an unexpected mailbox".to_string());
    }

    Ok(format!(
        "routing-only-envelope: a captured outer envelope held only the pairwise mailbox id \
         {mbx} ({sess} + {rat} opaque wire bytes across two send paths); the message body, the \
         sender address, the session key, and the chain state were each scanned for and found \
         absent — the relay sees where to route and nothing more",
        mbx = mailbox.as_str(),
        sess = receipt.session_path.wire_len,
        rat = receipt.ratchet_path.wire_len,
    ))
}

/// Prove the untrusted-relay boundary holds (PRD §10, the untrusted-relay claim):
/// the relay can tamper, replay, or link **nothing**. A message is sealed and
/// deposited; a
/// bit-flipped copy is opened and must fail AEAD (rejected, no oracle); the
/// original capture is re-presented and must be deduped so the recipient drains
/// exactly one copy; and the relay-visible envelope is scanned and must carry only
/// the pairwise mailbox id. Any property that does not hold fails the leg closed.
///
/// The output line carries the markers a reader greps for — `aead-rejected` (the
/// bit-flip failed the tag) and `replay-deduped` (the re-presented capture was
/// dropped) — alongside the mailbox the envelope routed on.
fn run_relay_boundary() -> Result<String, String> {
    let session_secret = [0x5au8; 32];
    let mac = Endpoint::new(
        Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint Mac identity: {e}"))?,
        Session::from_secret(session_secret),
    );
    let phone = Endpoint::new(
        Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint phone identity: {e}"))?,
        Session::from_secret(session_secret),
    );

    let mut directory = ContactDirectory::new();
    directory.admit(mac.aid().clone(), mac.public_key().to_vec());
    directory.admit(phone.aid().clone(), phone.public_key().to_vec());

    let mut relay = MailboxStore::new();
    let mailbox = MailboxId::new("mbx:phone");

    let receipt = hold_relay_boundary(
        &mac,
        &phone,
        &mailbox,
        "held at the untrusted boundary",
        &mut relay,
        &directory,
    )
    .map_err(|e| format!("the boundary broke: {e}"))?;

    Ok(format!(
        "aead-rejected + replay-deduped: a bit-flipped ciphertext failed AEAD and was rejected (no \
         oracle); a byte-identical replay was deduped at the relay so the recipient drained {} copy; \
         the envelope carried only the pairwise mailbox id {mbx} (body, sender address, and session \
         key each scanned for and found absent)",
        receipt.copies_delivered,
        mbx = receipt.mailbox.as_str(),
    ))
}

/// Prove the integration is *used correctly*, not merely that the primitives are
/// audited (PRD §10, the vetted-implementation claim): the misuse-resistant wrapper
/// passes the official known-answer test vectors of every primitive it composes
/// (ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, X25519), an independent reference
/// Double-Ratchet decrypts a message our ratchet sealed (the differential / interop
/// leg), and a batch of one-time prekeys and per-message keys are each handed out
/// exactly once (the no-reuse property).
///
/// The output line carries the marker a reader greps for — the audited-implementation
/// vectors-pass token — alongside the interop and no-reuse counts. A vector miss, a
/// reference-decrypt mismatch, or a reused key each fails the leg closed (the RED the
/// trap records).
fn run_vetted() -> Result<String, String> {
    let report = prove_vetted().map_err(|e| format!("the vetted-wrapper self-test failed: {e}"))?;
    Ok(format!(
        "libsignal-vectors-pass: the misuse-resistant wrapper matched {} official test vectors \
         of the audited primitives it composes, an independent reference Double-Ratchet decrypted \
         our {}-byte ciphertext (the differential/interop leg), and {} one-time prekeys + {} \
         per-message keys were each used exactly once (no reuse)",
        report.vectors_passed,
        report.interop_plaintext_len,
        report.prekeys_consumed,
        report.message_keys_distinct,
    ))
}

/// Prove the headline win (PRD §10, the verified-continuation claim with the
/// §2 binding mechanism): a contact's pre-committed key rotation verifies as a
/// *continuation of the same identity*, the Signal session is re-keyed
/// deterministically against the freshly-replayed key-state (the old ratchet is
/// never continued across the change), the republished prekey bundle is re-verified
/// against the new current key (a stale-signer bundle is rejected), and a
/// *substituted* key the prior state never pre-committed to is **warned, not
/// re-pinned**.
///
/// A contact under one stable AID rotates from a prior signing key to the key it
/// had pre-committed. The beat checks the rotation against the prior commitment,
/// re-keys, and re-verifies; the adversarial twin (a substituted key) must surface
/// the non-continuation warning. The output line carries the markers a reader greps
/// for — `verified-continuation`, `session-rekeyed`, `prekey-reverified` — so a
/// regression in any of the three fails the whole self-test closed.
fn run_continuation() -> Result<String, String> {
    // The contact's stable AID — the inception SAID, unchanged across the rotation.
    let stable_aid = Aid::new("did:keri:contact-stable-aid");
    // The prior signing key and the pre-committed key it rotates to (different keys —
    // that is what a rotation is), both bound to the same stable AID.
    let prior = Identity::from_seed([0x11u8; 32]).map_err(|e| format!("mint prior key: {e}"))?;
    let rotated = Identity::from_seed([0x22u8; 32]).map_err(|e| format!("mint rotated key: {e}"))?;
    // The contact's republished prekey secrets (DISTINCT from the AID signing key).
    let rotated_prekeys = PrekeySecrets::from_seeds([0x31u8; 32], [0x32u8; 32]);

    let receipt = verified_rotation_rekey(
        &stable_aid,
        &prior,
        &rotated,
        [0x5au8; 32], // the prior session's root, established before the rotation
        &rotated_prekeys,
        [0x41u8; 32], // our (initiator) Signal identity secret for the re-key X3DH
        [0x42u8; 32], // our fresh ephemeral for the re-key X3DH
    )
    .map_err(|e| format!("the continuation beat failed: {e}"))?;

    if receipt.continuation != TrustState::VerifiedContinuation {
        return Err("the pre-committed rotation did not verify as a continuation".to_string());
    }
    if receipt.substituted != TrustState::NonContinuationWarning {
        return Err("a substituted key was re-pinned instead of warned".to_string());
    }
    if !receipt.session_was_rekeyed() {
        return Err(
            "ratchet-continued-across-identity-change: the session was not re-keyed".to_string(),
        );
    }

    Ok(format!(
        "verified-continuation + session-rekeyed + prekey-reverified: a pre-committed rotation of \
         {aid} verified as a continuation of the same identity; the Signal session was re-keyed \
         against the freshly-replayed key-state (the old ratchet was not continued across the \
         change) and the republished prekey was re-verified against the fresh current key (a \
         stale-signer bundle was rejected); a substituted key the prior state never pre-committed \
         to was warned, not re-pinned",
        aid = receipt.aid.as_str(),
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Mode::Version => {
            println!("murmur-relay {}", murmur_core::VERSION);
            ExitCode::SUCCESS
        }
        Mode::Serve => {
            // Each `serve` run drives every end-to-end leg the engine proves and
            // prints one marker line per proven property — the store-and-forward
            // delivery leg and the KERI→Signal prekey-bundle join. A reader greps
            // for its own marker; a leg that breaks fails the whole self-test
            // closed.
            let legs: [fn() -> Result<String, String>; 8] = [
                run_addressed,
                run_delivery,
                run_rooted,
                run_forward_secret,
                run_routing_only,
                run_relay_boundary,
                run_vetted,
                run_continuation,
            ];
            for leg in legs {
                match leg() {
                    Ok(line) => println!("murmur-relay {}: {line}", murmur_core::VERSION),
                    Err(why) => {
                        eprintln!("murmur-relay {}: {why}", murmur_core::VERSION);
                        return ExitCode::FAILURE;
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Mode::Usage => {
            eprintln!("usage: murmur-relay [serve|--version]");
            ExitCode::from(2)
        }
    }
}
