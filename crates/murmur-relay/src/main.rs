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
//! This is a SKELETON. The binary stands up and reports its version and identity
//! so the apps, the FFI, and the probe harness can drive it, but the wire surface
//! (HTTPS / WebSocket / QUIC) and the queue are not built yet — `serve` exits
//! honestly with "feature absent" rather than pretending to accept traffic.

use std::process::ExitCode;

/// What the relay was asked to do.
enum Mode {
    /// Print the version and exit 0 — the liveness check the probe harness uses.
    Version,
    /// Stand up the store-and-forward wire. SKELETON: unbuilt.
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Mode::Version => {
            println!("murmur-relay {}", murmur_core::VERSION);
            ExitCode::SUCCESS
        }
        Mode::Serve => {
            // The wire (HTTPS/WS/QUIC) + the mailbox queue are not built yet.
            // Fail honestly so the harness reads "feature absent", never a fake
            // listening relay. murmur_core::relay::handle is the seam this will
            // drive once built; it returns NotBuilt today.
            eprintln!(
                "murmur-relay {}: store-and-forward wire not built yet \
                 (the mailbox queue + pull/subscribe surface is the slice's transport work)",
                murmur_core::VERSION
            );
            ExitCode::FAILURE
        }
        Mode::Usage => {
            eprintln!("usage: murmur-relay [serve|--version]");
            ExitCode::from(2)
        }
    }
}
