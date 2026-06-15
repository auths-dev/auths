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
    ContactDirectory, Endpoint, Identity, MailboxId, MailboxStore, Session, deliver_once,
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Mode::Version => {
            println!("murmur-relay {}", murmur_core::VERSION);
            ExitCode::SUCCESS
        }
        Mode::Serve => match run_delivery() {
            Ok(line) => {
                println!("murmur-relay {}: {line}", murmur_core::VERSION);
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("murmur-relay {}: {why}", murmur_core::VERSION);
                ExitCode::FAILURE
            }
        },
        Mode::Usage => {
            eprintln!("usage: murmur-relay [serve|--version]");
            ExitCode::from(2)
        }
    }
}
