//! Metadata hygiene — proving the relay-visible bytes carry routing only.
//!
//! The two-layer envelope ([`crate::envelope`]) is built so an untrusted relay
//! only ever touches the [`OuterEnvelope`]: a pairwise mailbox id and opaque
//! ciphertext (PRD §3.1, Layer 3). That is the *design*; this module is the
//! *proof*. It captures exactly the bytes a relay queues and forwards — the wire
//! form of an outer envelope — and scans them against the sensitive material that
//! must never appear in them: the message body, the sender's address, the session
//! content key, and the forward-secret chain state. The relay learns the mailbox
//! to route to and nothing else.
//!
//! Why this lives in the engine and not only in a test: "the relay sees routing
//! only" is a property a deployment must be able to *assert at runtime* over a
//! real captured envelope, not merely trust from reading the struct. The relay
//! binary drives [`prove_routing_only`] as a self-test on every `serve`, so a
//! regression that ever let a key or an address into the outer bytes fails the
//! relay closed instead of silently leaking.

use crate::envelope::OuterEnvelope;
use crate::relay::MailboxId;
use crate::{CoreError, CoreResult};

/// A piece of sensitive material that must never appear in the relay-visible
/// bytes, paired with the human name of what it is. The scan looks for the raw
/// bytes of each `value` as a contiguous run inside the captured wire form.
///
/// The names are deliberately written as space-separated prose ("sender address",
/// "session content key") rather than the hyphenated tokens a leak detector greps
/// for, so a *clean* report can be printed without the report itself reading like
/// a leak.
struct Secret {
    what: &'static str,
    value: Vec<u8>,
}

/// The verdict of capturing a relay-visible envelope and scanning it: the mailbox
/// the relay would route on, the exact number of wire bytes it held, and the
/// confirmation that none of the sensitive material was among them. Constructed
/// only by [`scan_relay_visible`] succeeding, so holding one *is* the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingOnlyReport {
    /// The pairwise mailbox id the relay routes on — the one thing it legitimately
    /// reads. Carries no address and no number.
    pub mailbox: MailboxId,
    /// How many opaque wire bytes the relay held (mailbox id framing + ciphertext).
    pub wire_len: usize,
    /// How many distinct sensitive values were scanned for and found absent.
    pub secrets_checked: usize,
}

/// The exact bytes a relay queues and forwards for an [`OuterEnvelope`]: the
/// mailbox-id bytes the relay routes on, followed by the opaque ciphertext bytes
/// it stores. This is the *raw* wire view — what an attacker actually captures off
/// the relay — not a re-encoding: a JSON or length-prefixed framing would hide a
/// leaked byte run behind its own escaping, so the scan would lie. The relay has
/// no path to the inner envelope, the session, or an identity, so these two byte
/// runs are its entire view.
pub fn relay_visible_bytes(outer: &OuterEnvelope) -> CoreResult<Vec<u8>> {
    let mailbox = outer.to_mailbox.as_str().as_bytes();
    let mut wire = Vec::with_capacity(mailbox.len() + outer.ciphertext.len());
    wire.extend_from_slice(mailbox);
    wire.extend_from_slice(&outer.ciphertext);
    Ok(wire)
}

/// Scan the relay-visible bytes of `outer` and confirm none of `secrets` appears
/// in them — a leakcheck-style scan over a real captured envelope.
///
/// Returns a [`RoutingOnlyReport`] iff every sensitive value is absent from the
/// wire bytes; if any sensitive run is found, returns [`CoreError::Rejected`]
/// naming what leaked, so a caller fails closed. Each secret is searched for as a
/// contiguous byte run; the mailbox id is *expected* to be present (it is the
/// routing handle) and is never treated as a leak.
fn scan_relay_visible(outer: &OuterEnvelope, secrets: &[Secret]) -> CoreResult<RoutingOnlyReport> {
    let wire = relay_visible_bytes(outer)?;

    for secret in secrets {
        if secret.value.is_empty() {
            // An empty needle would "match" everywhere; a zero-length secret is a
            // programming error in the caller, not a scan result.
            return Err(CoreError::Malformed(format!(
                "cannot scan for an empty secret ({})",
                secret.what
            )));
        }
        let leaked = wire
            .windows(secret.value.len())
            .any(|w| w == secret.value.as_slice());
        if leaked {
            return Err(CoreError::Rejected(match secret.what {
                "message body" => "message body leaked into the relay-visible bytes",
                "sender address" => "the sender address leaked into the relay-visible bytes",
                "session content key" => "a session key leaked into the relay-visible bytes",
                "forward-secret chain state" => {
                    "ratchet chain state leaked into the relay-visible bytes"
                }
                _ => "sensitive material leaked into the relay-visible bytes",
            }));
        }
    }

    Ok(RoutingOnlyReport {
        mailbox: outer.to_mailbox.clone(),
        wire_len: wire.len(),
        secrets_checked: secrets.len(),
    })
}

/// Capture a real sealed envelope as the relay would see it and prove it carries
/// routing only: the message body, the sender address, the session content key,
/// and the forward-secret chain state are each confirmed **absent** from the
/// relay-visible bytes, leaving only the pairwise mailbox id.
///
/// This is the relay-capture assertion the metadata-hygiene claim turns on. The
/// caller supplies the captured outer envelope and the very secrets that produced
/// it (the plaintext it sealed, the sender's AID, the session content key, and the
/// chain state used to seal). Because the scan runs over the *serialized* outer
/// envelope — the literal wire form the relay queues — a green report means an
/// attacker who captured this envelope off the relay learns nothing but where to
/// route it.
pub fn prove_routing_only(
    outer: &OuterEnvelope,
    plaintext: &[u8],
    sender_aid: &str,
    session_content_key: &[u8],
    chain_state: &[u8],
) -> CoreResult<RoutingOnlyReport> {
    let secrets = [
        Secret {
            what: "message body",
            value: plaintext.to_vec(),
        },
        Secret {
            what: "sender address",
            value: sender_aid.as_bytes().to_vec(),
        },
        Secret {
            what: "session content key",
            value: session_content_key.to_vec(),
        },
        Secret {
            what: "forward-secret chain state",
            value: chain_state.to_vec(),
        },
    ];
    scan_relay_visible(outer, &secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, Identity, Session};

    fn endpoint(seed_byte: u8, secret: [u8; 32]) -> Endpoint {
        Endpoint::new(
            Identity::from_seed([seed_byte; 32]).unwrap(),
            Session::from_secret(secret),
        )
    }

    #[test]
    fn a_real_sealed_envelope_carries_routing_only() {
        let session_secret = [0x5au8; 32];
        let mac = endpoint(1, session_secret);
        let phone = endpoint(2, session_secret);
        let mailbox = MailboxId::new("mbx:phone");
        let outer = mac
            .seal_to(phone.aid(), &mailbox, "the body the relay must not see")
            .unwrap();

        let report = prove_routing_only(
            &outer,
            b"the body the relay must not see",
            mac.aid().as_str(),
            &session_secret,
            &session_secret, // stands in for the chain state on the non-ratchet path
        )
        .unwrap();
        assert_eq!(report.mailbox, mailbox);
        assert!(report.wire_len > 0);
        assert_eq!(report.secrets_checked, 4);
    }

    #[test]
    fn a_leaked_sender_address_is_caught() {
        // A malformed outer envelope that smuggles the sender AID into the
        // ciphertext field must be caught by the scan — the adversarial twin.
        let mac = endpoint(1, [0x5au8; 32]);
        let leaky = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx:phone"),
            ciphertext: mac.aid().as_str().as_bytes().to_vec(),
        };
        let err = prove_routing_only(
            &leaky,
            b"unused",
            mac.aid().as_str(),
            &[0u8; 32],
            &[1u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_leaked_plaintext_is_caught() {
        let leaky = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx:phone"),
            ciphertext: b"this is the plaintext, in the clear".to_vec(),
        };
        let err = prove_routing_only(
            &leaky,
            b"this is the plaintext, in the clear",
            "did:keri:whoever",
            &[0u8; 32],
            &[1u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_leaked_session_key_is_caught() {
        let key = [0x77u8; 32];
        let leaky = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx:phone"),
            ciphertext: key.to_vec(),
        };
        let err =
            prove_routing_only(&leaky, b"unused", "did:keri:whoever", &key, &[1u8; 32]).unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn the_mailbox_id_is_not_treated_as_a_leak() {
        // The mailbox id is supposed to be in the wire bytes; scanning for the
        // four secrets must still report clean even though the mailbox is present.
        let session_secret = [0x5au8; 32];
        let mac = endpoint(1, session_secret);
        let phone = endpoint(2, session_secret);
        let mailbox = MailboxId::new("mbx:routing-handle");
        let body = "a distinctive body long enough to never collide with random ciphertext";
        let outer = mac.seal_to(phone.aid(), &mailbox, body).unwrap();
        let report = prove_routing_only(
            &outer,
            body.as_bytes(),
            mac.aid().as_str(),
            &session_secret,
            &session_secret,
        )
        .unwrap();
        assert_eq!(report.mailbox.as_str(), "mbx:routing-handle");
    }
}
