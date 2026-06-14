//! The operator-vocabulary rule, in one place.
//!
//! A node operator stands a witness up, checks on it, registers it, reads its
//! logs — and must never need the protocol's vocabulary to do any of it. The
//! words a relying party's *verifier* speaks (key event logs, key-state
//! notices, self-addressing identifiers, the CESR wire, signing thresholds and
//! the rest) are correct and necessary *inside* the trust kernel; they are
//! friction in an operator's face. This module owns the line between the two so
//! it lives in exactly one place: the canonical list of terms an operator must
//! never see, and the scanner that finds one in a string.
//!
//! One source of truth (quality constitution §3): the standup surface, the
//! crate's own tests, and the conformance suite's vocabulary probe all check
//! against [`PROTOCOL_VOCABULARY`] here — none of them carries its own copy, so
//! none of them can drift from this list.

/// Protocol terms an operator must never encounter in the witness happy path.
///
/// These are the trust kernel's wire and ceremony vocabulary — exact and
/// load-bearing for a verifier, pure friction for an operator who only wants a
/// node that is up and vouchable. The list is the contract the operator-facing
/// surface is held to; it is matched whole-word and case-insensitively (see
/// [`scan_for_protocol_vocabulary`]), so an operator string that merely
/// *contains* these letters inside a larger benign word is not a leak.
///
/// Whole-word matching is why innocuous substrings are safe: `did:key:` and
/// `identity` carry "id"; "received" carries no listed term; the operator line
/// "this node is not running what it attests" carries none. A leak is a listed
/// term standing as its own word.
pub const PROTOCOL_VOCABULARY: &[&str] = &[
    // The event-log / key-state family.
    "keri",
    "kel",
    "kerl",
    "ksn",
    "icp",
    "rot",
    "ixn",
    "drt",
    // Self-addressing & credential wire.
    "said",
    "saider",
    "acdc",
    "tel",
    // The binary encoding.
    "cesr",
    "cigar",
    // Key-material jargon a relying party speaks, not an operator.
    "verkey",
    "prefix",
    "tholder",
    "diger",
    // The corroboration-policy term: an operator runs a node; "threshold" is the
    // verifier's M-of-N language, never standup's.
    "threshold",
    // Out-of-band introduction — discovery wire, not an operator concept.
    "oobi",
];

/// Find the first protocol term [`PROTOCOL_VOCABULARY`] that appears as a whole
/// word in `text`, case-insensitively. `None` means the text is operator-clean.
///
/// "Whole word" means flanked by non-alphanumeric boundaries (or string ends),
/// so a listed term embedded in a larger identifier — `prefixed`, `said` inside
/// `unsaid` — is not a false positive; only the bare term is a leak. The match
/// is case-insensitive because operators never see cased jargon either.
///
/// Args:
/// * `text`: any operator-facing string (a command's stdout/stderr line, a
///   rendered verdict, a help blurb).
pub fn scan_for_protocol_vocabulary(text: &str) -> Option<&'static str> {
    let lowered = text.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    for &term in PROTOCOL_VOCABULARY {
        let mut from = 0;
        while let Some(rel) = lowered[from..].find(term) {
            let start = from + rel;
            let end = start + term.len();
            let left_ok = start == 0 || !is_word_byte(bytes[start - 1]);
            let right_ok = end == bytes.len() || !is_word_byte(bytes[end]);
            if left_ok && right_ok {
                return Some(term);
            }
            from = start + 1;
        }
    }
    None
}

/// Whether a byte is part of a word (ASCII alphanumeric). Word boundaries are
/// anything else — whitespace, punctuation, string ends.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_operator_strings_carry_no_protocol_vocabulary() {
        // The exact lines the operator happy path prints today — every one must
        // pass the rule it is held to.
        let operator_lines = [
            "health: http://127.0.0.1:3333/health",
            "healthy: http://127.0.0.1:3333/health",
            "build verified: this node runs 0.1.3 (digest 7ce84d53b3b63323…), signed and matching",
            "witness node torn down",
            "opening signed registration for https://wit.example.org",
            "streaming logs for witness node at ./witness-data",
            "verified: this receipt was issued by did:key:z6Mkhr…",
            "node did not become healthy at http://127.0.0.1:3333/health within 540s — nothing left running",
            "this node is not running what it attests",
        ];
        for line in operator_lines {
            assert_eq!(
                scan_for_protocol_vocabulary(line),
                None,
                "operator line leaked protocol vocabulary: {line}"
            );
        }
    }

    #[test]
    fn a_leaked_term_is_found_whole_word_case_insensitively() {
        assert_eq!(
            scan_for_protocol_vocabulary("served the current KEL for this identity"),
            Some("kel")
        );
        assert_eq!(
            scan_for_protocol_vocabulary("quorum threshold met (2 of 3)"),
            Some("threshold")
        );
        assert_eq!(
            scan_for_protocol_vocabulary("verkey rotated"),
            Some("verkey")
        );
    }

    #[test]
    fn benign_substrings_are_not_false_positives() {
        // "prefix" is listed; "prefixed"/"prefixes" are operator-fine words that
        // merely contain it — whole-word matching must not flag them.
        assert_eq!(scan_for_protocol_vocabulary("the prefixed path"), None);
        // "id" / "did" appear all over operator output and are not listed; a
        // listed term inside a larger word ("unsaid") is not a bare leak.
        assert_eq!(scan_for_protocol_vocabulary("did:key:z6Mkhr… unsaid"), None);
        assert_eq!(scan_for_protocol_vocabulary("received and witnessed"), None);
    }

    #[test]
    fn the_denylist_is_nonempty_and_lowercase() {
        // The scanner lowercases input; the list it compares against must be
        // lowercase too, or a term could never match.
        assert!(!PROTOCOL_VOCABULARY.is_empty());
        for &term in PROTOCOL_VOCABULARY {
            assert_eq!(
                term,
                term.to_ascii_lowercase(),
                "denylist term not lowercase: {term}"
            );
            assert!(!term.is_empty());
        }
    }
}
