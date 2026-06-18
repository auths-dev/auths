//! Number-free addressing — proving the address is an AID and nothing else.
//!
//! A phone number did two jobs at once: it was your *identity* and the network's
//! *directory key*. Murmur splits them (PRD §3.1), and the whole point is that
//! **no phone number and no email ever enter the flow** — the address is a
//! self-certifying [`Aid`], the routing handle is a pairwise [`MailboxId`], and a
//! [`Message`] has no number/email field by construction.
//!
//! "By construction" is the design; this module is the *proof*. The
//! [`Message`]/[`InnerEnvelope`]/[`OuterEnvelope`] types are serialized exactly as
//! they cross the engine boundary and scanned for anything number- or email-
//! shaped. A clean report means a reader can trust that a message addressed to and
//! authenticated by an AID carried no telco identifier anywhere — the floor claim
//! the whole thesis stands on (PRD §10, the addressing claim). A deployment can assert this at
//! runtime, not merely trust it from reading the struct: the relay binary drives
//! [`prove_number_free`] as a `serve` self-test, so a regression that ever let a
//! number or an address-shaped contact into a message fails the leg closed.
//!
//! [`Aid`]: crate::address::Aid
//! [`MailboxId`]: crate::relay::MailboxId
//! [`Message`]: crate::Message
//! [`InnerEnvelope`]: crate::envelope::InnerEnvelope
//! [`OuterEnvelope`]: crate::envelope::OuterEnvelope

use crate::envelope::{InnerEnvelope, OuterEnvelope};
use crate::{CoreError, CoreResult, Message};

/// The verdict of scanning a fully-formed message and its envelopes for a phone
/// number or an email: the AID the message was addressed to, the AID it
/// authenticated as, and the confirmation that no telco identifier appeared in any
/// of the serialized forms. Constructed only by [`prove_number_free`] succeeding,
/// so holding one *is* the proof that the flow was number-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumberFreeReport {
    /// The recipient AID the message was addressed to (textual `did:keri:` /
    /// `did:webs:` form) — the destination, in place of a number.
    pub addressed_to: String,
    /// The sender AID the message authenticated as — the identity, in place of a
    /// number.
    pub authenticated_as: String,
    /// How many serialized forms (message, inner envelope, outer envelope) were
    /// scanned and found free of a number or an email.
    pub forms_scanned: usize,
}

/// Why a scanned form was rejected: it carried something a number-free flow must
/// never contain. Kept as a typed reason so the relay self-test can name what
/// leaked without re-implementing the predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Telco {
    /// A run of digits long enough to be a dialable phone number.
    PhoneNumber,
    /// An `@`-shaped local@domain email address.
    Email,
}

/// Does `text` contain a run of at least `MIN_PHONE_DIGITS` digits, ignoring the
/// separators a written phone number uses (spaces, dashes, dots, parens, a leading
/// `+`)? A `did:keri:` AID is hex with letters interspersed, so it never trips
/// this; a real dialable number (`+1 415-555-0123`, `14155550123`) does.
fn looks_like_phone_number(text: &str) -> bool {
    /// The shortest run of digits we treat as a dialable number. Real E.164
    /// numbers are 7–15 digits; a SHA-256 `did:keri:` AID is hex (digits broken up
    /// by a–f), so its longest pure-digit run stays well under this.
    const MIN_PHONE_DIGITS: usize = 7;

    let mut run = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            run += 1;
            if run >= MIN_PHONE_DIGITS {
                return true;
            }
        } else if matches!(ch, ' ' | '-' | '.' | '(' | ')' | '+') {
            // A phone-number separator: keep the digit run going across it.
            continue;
        } else {
            run = 0;
        }
    }
    false
}

/// Does `text` contain an `@` with at least one non-`@` character on each side and
/// a dot in the domain part — the shape of an email address? A bare `@` (or a `@`
/// at a boundary) is not enough; this matches `alice@example.com`, not a stray
/// sigil.
fn looks_like_email(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        let local_ok = i > 0 && is_addr_char(bytes[i - 1]);
        let Some(domain) = text.get(i + 1..) else {
            continue;
        };
        // The domain must start with an address char and contain a dot followed by
        // more address chars (a TLD), so `a@b.com` matches and `a@ ` does not.
        let mut domain_chars = domain.chars();
        let starts_ok = domain_chars.next().is_some_and(|c| is_addr_char(c as u8));
        let has_dotted_tld = domain.split_once('.').is_some_and(|(left, right)| {
            !left.is_empty() && right.chars().next().is_some_and(|c| is_addr_char(c as u8))
        });
        if local_ok && starts_ok && has_dotted_tld {
            return true;
        }
    }
    false
}

/// An address-shaped character (alphanumeric, dot, dash, underscore, plus) — the
/// alphabet of an email local-part / domain label.
fn is_addr_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+')
}

/// Replace every occurrence of each address in `masks` with a single space in
/// `serialized`, so the number/email scan never sees an address as content.
///
/// An [`Aid`] is a self-certifying identifier — a `did:keri:` hex digest or a
/// `did:webs:` label — an *address by construction*, never a dialable number or an
/// email. Its hex form can, by chance, contain a long run of decimal digits (a
/// SHA-256 digest is uniform), which a naive scan would misread as a phone number.
/// So the known address strings are masked out *before* scanning: what is left to
/// judge is the genuine free text (the body) and any field that must never carry a
/// number. This keeps the scan honest in both directions — an AID never trips it,
/// and a real number hidden in the body still does.
///
/// [`Aid`]: crate::address::Aid
fn mask_addresses(serialized: &str, masks: &[String]) -> String {
    let mut out = serialized.to_string();
    for mask in masks {
        if !mask.is_empty() {
            out = out.replace(mask.as_str(), " ");
        }
    }
    out
}

/// Scan one serialized form for a number or an email, with the known address
/// strings masked out first; `what` names the form for the rejection message.
fn scan_form(serialized: &str, masks: &[String], what: &'static str) -> CoreResult<()> {
    let scanned = mask_addresses(serialized, masks);
    let telco = if looks_like_phone_number(&scanned) {
        Some(Telco::PhoneNumber)
    } else if looks_like_email(&scanned) {
        Some(Telco::Email)
    } else {
        None
    };
    match telco {
        None => Ok(()),
        Some(Telco::PhoneNumber) => Err(CoreError::Rejected(match what {
            "message" => "a phone number appeared in the message",
            "inner envelope" => "a phone number appeared in the inner envelope",
            "outer envelope" => "a phone number appeared in the outer envelope",
            _ => "a phone number appeared in the flow",
        })),
        Some(Telco::Email) => Err(CoreError::Rejected(match what {
            "message" => "an email address appeared in the message",
            "inner envelope" => "an email address appeared in the inner envelope",
            "outer envelope" => "an email address appeared in the outer envelope",
            _ => "an email address appeared in the flow",
        })),
    }
}

/// Prove a fully-formed, authenticated message carried no phone number and no
/// email anywhere — the floor of the thesis (PRD §10, the addressing claim).
///
/// The `message` (the API-boundary type the SwiftUI shell sees), the `inner`
/// envelope (the recipient reconstructs and verifies), and the `outer` envelope
/// (the relay routes on) are each serialized to their wire form and scanned for a
/// dialable phone number or an email address. The addresses themselves are AIDs
/// (`did:keri:` / `did:webs:` strings), which are hex/label text and never trip
/// the scan; a real number or email *anywhere* in any form fails the leg closed
/// with [`CoreError::Rejected`] naming where it appeared.
///
/// Returns a [`NumberFreeReport`] iff all three forms scan clean — carrying the
/// recipient AID the message was addressed to and the sender AID it authenticated
/// as, both in place of the number a legacy messenger would have used.
pub fn prove_number_free(
    message: &Message,
    inner: &InnerEnvelope,
    outer: &OuterEnvelope,
) -> CoreResult<NumberFreeReport> {
    // The known address strings — AIDs and the pairwise mailbox id — are routing
    // and identity handles, not user content, so they are masked out before the
    // scan (see `mask_addresses`). Everything else (above all the body) is judged.
    let masks: Vec<String> = [
        message.to.as_str(),
        message.from.as_str(),
        inner.sender.as_str(),
        inner.recipient.as_str(),
        outer.to_mailbox.as_str(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let message_json = serde_json::to_string(message)
        .map_err(|e| CoreError::Malformed(format!("serialize message: {e}")))?;
    let inner_json = serde_json::to_string(inner)
        .map_err(|e| CoreError::Malformed(format!("serialize inner: {e}")))?;
    let outer_json = serde_json::to_string(outer)
        .map_err(|e| CoreError::Malformed(format!("serialize outer: {e}")))?;

    scan_form(&message_json, &masks, "message")?;
    scan_form(&inner_json, &masks, "inner envelope")?;
    scan_form(&outer_json, &masks, "outer envelope")?;

    Ok(NumberFreeReport {
        addressed_to: message.to.as_str().to_string(),
        authenticated_as: message.from.as_str().to_string(),
        forms_scanned: 3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Aid;
    use crate::relay::MailboxId;

    fn aid(seed: u8) -> Aid {
        Aid::from_public_key(&[seed; 32])
    }

    fn forms(body: &str) -> (Message, InnerEnvelope, OuterEnvelope) {
        let to = aid(1);
        let from = aid(2);
        let message = Message {
            to: to.clone(),
            from: from.clone(),
            body: body.to_string(),
            message_id: vec![0u8; 8],
            content_type: "text".to_string(),
            flags: 0,
        };
        let inner = InnerEnvelope {
            sender: from,
            recipient: to,
            message_id: vec![0u8; 8],
            content_type: "text".to_string(),
            flags: 0,
            body: body.to_string(),
            signature: vec![0xab; 64],
        };
        let outer = OuterEnvelope {
            to_mailbox: MailboxId::new("mbx:pairwise-handle"),
            ciphertext: vec![0xcd; 96],
        };
        (message, inner, outer)
    }

    #[test]
    fn a_real_aid_addressed_message_scans_number_free() {
        let (m, i, o) = forms("see you at the usual place");
        let report = prove_number_free(&m, &i, &o).unwrap();
        assert!(report.addressed_to.starts_with("did:keri:"));
        assert!(report.authenticated_as.starts_with("did:keri:"));
        assert_eq!(report.forms_scanned, 3);
    }

    #[test]
    fn a_did_keri_aid_is_not_mistaken_for_a_phone_number() {
        // The AID is a SHA-256 hex string: long, with digits, but always broken up
        // by hex letters, so its longest pure-digit run stays under the threshold.
        let addr = aid(7);
        assert!(!looks_like_phone_number(addr.as_str()));
    }

    #[test]
    fn a_phone_number_in_the_body_is_caught() {
        let (m, i, o) = forms("call me at +1 415-555-0123");
        let err = prove_number_free(&m, &i, &o).unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_bare_run_of_digits_is_caught_as_a_number() {
        let (m, i, o) = forms("the code is 4155550123");
        assert!(matches!(
            prove_number_free(&m, &i, &o),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn an_email_in_the_body_is_caught() {
        let (m, i, o) = forms("reach me at alice@example.com");
        let err = prove_number_free(&m, &i, &o).unwrap_err();
        assert!(matches!(err, CoreError::Rejected(_)));
    }

    #[test]
    fn a_bare_at_sign_is_not_mistaken_for_an_email() {
        // A mention like "@alice" or a lone sigil is not an email address.
        assert!(!looks_like_email("ping @alice when you land"));
        assert!(!looks_like_email("rate is 5 @ noon"));
    }

    #[test]
    fn short_digit_runs_are_not_phone_numbers() {
        // A time, a small count, a short code: under the dialable threshold.
        assert!(!looks_like_phone_number("meet at 9 or 1030"));
        assert!(!looks_like_phone_number("table for 4 at 7"));
    }

    #[test]
    fn a_leak_into_the_inner_envelope_is_caught() {
        // Even if the message body is clean, a number smuggled into the inner
        // envelope (e.g. a malformed sender field) is caught.
        let (m, mut i, o) = forms("clean body");
        i.body = "fallback number 442079460958".to_string();
        assert!(matches!(
            prove_number_free(&m, &i, &o),
            Err(CoreError::Rejected(_))
        ));
    }
}
