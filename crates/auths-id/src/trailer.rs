//! Git trailer parsing and formatting utilities.
//!
//! Git trailers are key-value pairs at the end of a commit message, separated
//! from the body by a blank line. This module handles:
//!
//! - Appending trailers to commit messages
//! - Parsing trailers (including RFC 822 folded lines)
//! - Extracting witness receipts from `Auths-Witness-Receipt` trailers

use auths_core::witness::SignedReceipt;

/// Re-export for backwards compatibility in this module's public API.
pub use auths_core::witness::Receipt;

/// The trailer key for witness receipts.
pub const WITNESS_RECEIPT_KEY: &str = "Auths-Witness-Receipt";

/// Maximum line length before folding (RFC 822 convention).
const FOLD_WIDTH: usize = 76;

// ── Formatting ──────────────────────────────────────────────────────────────

/// Appends a trailer to a commit message with RFC 822 folding for long values.
///
/// If the message doesn't already have a trailer block (blank line before trailers),
/// a blank line separator is inserted.
pub fn append_trailer(message: &str, key: &str, value: &str) -> String {
    let full_line = format!("{}: {}", key, value);
    let folded = fold_line(&full_line);

    let trimmed = message.trim_end();
    if trimmed.is_empty() {
        return folded;
    }

    // Check if last paragraph looks like trailers already
    if has_trailer_block(trimmed) {
        format!("{}\n{}", trimmed, folded)
    } else {
        format!("{}\n\n{}", trimmed, folded)
    }
}

/// Fold a single line at `FOLD_WIDTH` characters.
///
/// Continuation lines start with a single space (RFC 822 convention).
fn fold_line(line: &str) -> String {
    if line.len() <= FOLD_WIDTH {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len() + line.len() / FOLD_WIDTH);
    let mut remaining = line;

    while remaining.len() > FOLD_WIDTH {
        // Try to break at a space near the fold width, but never at position 0
        // (position 0 would mean remaining never advances — infinite loop).
        let break_at = remaining[..FOLD_WIDTH]
            .rfind(' ')
            .filter(|&pos| pos > 0)
            .unwrap_or(FOLD_WIDTH);

        result.push_str(&remaining[..break_at]);
        result.push('\n');
        remaining = &remaining[break_at..];

        // Continuation line: ensure it starts with a space
        if !remaining.starts_with(' ') {
            result.push(' ');
        }
    }
    result.push_str(remaining);
    result
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parses all trailers from a commit message.
///
/// Handles RFC 822 folded lines (continuation lines starting with whitespace).
/// Returns key-value pairs with folded values rejoined.
pub fn parse_trailers(message: &str) -> Vec<(String, String)> {
    let trailer_block = extract_trailer_block(message);
    if trailer_block.is_empty() {
        return vec![];
    }

    let unfolded = unfold_lines(trailer_block);
    let mut trailers = Vec::new();

    for line in unfolded.lines() {
        if let Some((key, value)) = parse_trailer_line(line) {
            trailers.push((key, value));
        }
    }

    trailers
}

/// Extracts and deserializes signed witness receipts from commit message trailers.
pub fn extract_witness_receipts(message: &str) -> Vec<SignedReceipt> {
    parse_trailers(message)
        .into_iter()
        .filter(|(key, _)| key == WITNESS_RECEIPT_KEY)
        .filter_map(|(_, value)| SignedReceipt::from_trailer_value(&value).ok())
        .collect()
}

// ── Internal Helpers ────────────────────────────────────────────────────────

/// Check if the last paragraph of a message looks like a trailer block.
fn has_trailer_block(message: &str) -> bool {
    let last_paragraph = match message.rfind("\n\n") {
        Some(pos) => &message[pos + 2..],
        None => message,
    };

    // A trailer block has at least one line matching "Key: Value"
    last_paragraph
        .lines()
        .any(|line| parse_trailer_line(line).is_some())
}

/// Extract the trailer block (last paragraph) from a commit message.
fn extract_trailer_block(message: &str) -> &str {
    let trimmed = message.trim_end();
    match trimmed.rfind("\n\n") {
        Some(pos) => &trimmed[pos + 2..],
        None => {
            // Single paragraph — only treat as trailers if every line is a trailer or continuation
            if trimmed.lines().all(|l| {
                l.starts_with(' ') || l.starts_with('\t') || parse_trailer_line(l).is_some()
            }) {
                trimmed
            } else {
                ""
            }
        }
    }
}

/// Unfold RFC 822 continuation lines.
///
/// Lines starting with whitespace are joined to the previous line.
fn unfold_lines(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation — append without newline
            result.push_str(line);
        } else {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(line);
        }
    }
    result
}

/// Parse a single trailer line into (key, value).
fn parse_trailer_line(line: &str) -> Option<(String, String)> {
    let colon_pos = line.find(':')?;
    let key = line[..colon_pos].trim();

    // Trailer keys must be non-empty, contain no spaces, and be alphanumeric + hyphens
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    if !key
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }

    let value = line[colon_pos + 1..].trim().to_string();
    Some((key.to_string(), value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::witness::RECEIPT_TYPE;
    use auths_keri::{KeriSequence, Prefix, Said, VersionString};

    fn sample_signed_receipt() -> SignedReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: RECEIPT_TYPE.into(),
            d: Said::new_unchecked("EEvent456".into()),
            i: Prefix::new_unchecked("did:key:z6MkWitness".into()),
            s: KeriSequence::new(5),
        };
        SignedReceipt {
            receipt,
            signature: vec![0xab; 64],
        }
    }

    #[test]
    fn append_trailer_to_empty_message() {
        let result = append_trailer("", "Signed-off-by", "Alice");
        assert_eq!(result, "Signed-off-by: Alice");
    }

    #[test]
    fn append_trailer_to_message_without_trailers() {
        let msg = "fix: resolve null pointer\n\nLong description here.";
        let result = append_trailer(msg, "Signed-off-by", "Alice");
        assert!(result.contains("\n\nSigned-off-by: Alice"));
    }

    #[test]
    fn append_trailer_to_existing_trailer_block() {
        let msg = "fix: bug\n\nSigned-off-by: Bob";
        let result = append_trailer(msg, "Reviewed-by", "Alice");
        assert!(result.ends_with("Reviewed-by: Alice"));
        // Should NOT have double blank line
        assert!(!result.contains("\n\n\n"));
    }

    #[test]
    fn fold_short_line_unchanged() {
        let line = "Key: short value";
        assert_eq!(fold_line(line), line);
    }

    #[test]
    fn fold_long_line() {
        let long_value = "x".repeat(100);
        let line = format!("Key: {}", long_value);
        let folded = fold_line(&line);
        // All lines should be <= FOLD_WIDTH (or close — continuation adds space)
        for (i, segment) in folded.lines().enumerate() {
            if i > 0 {
                assert!(
                    segment.starts_with(' '),
                    "continuation must start with space"
                );
            }
        }
    }

    #[test]
    fn parse_trailers_basic() {
        let msg = "fix: bug\n\nSigned-off-by: Alice\nReviewed-by: Bob";
        let trailers = parse_trailers(msg);
        assert_eq!(trailers.len(), 2);
        assert_eq!(
            trailers[0],
            ("Signed-off-by".to_string(), "Alice".to_string())
        );
        assert_eq!(trailers[1], ("Reviewed-by".to_string(), "Bob".to_string()));
    }

    #[test]
    fn parse_trailers_with_folding() {
        let msg = "fix: bug\n\nKey: start\n of-value";
        let trailers = parse_trailers(msg);
        assert_eq!(trailers.len(), 1);
        assert!(trailers[0].1.contains("start"));
        assert!(trailers[0].1.contains("of-value"));
    }

    #[test]
    fn parse_trailers_empty_message() {
        let trailers = parse_trailers("");
        assert!(trailers.is_empty());
    }

    #[test]
    fn parse_trailers_no_trailer_block() {
        let msg = "just a commit message\n\nwith a body paragraph";
        let trailers = parse_trailers(msg);
        // "with a body paragraph" doesn't have a colon-separated key
        assert!(trailers.is_empty());
    }

    #[test]
    fn extract_witness_receipts_roundtrip() {
        let signed = sample_signed_receipt();
        let trailer_value = signed.to_trailer_value().unwrap();
        let msg = append_trailer(
            "feat: add agent signing",
            WITNESS_RECEIPT_KEY,
            &trailer_value,
        );

        let receipts = extract_witness_receipts(&msg);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0], signed);
    }

    #[test]
    fn extract_multiple_witness_receipts() {
        let r1 = sample_signed_receipt();
        let mut r2 = sample_signed_receipt();
        r2.receipt.i = Prefix::new_unchecked("did:key:z6MkWitness2".into());
        r2.receipt.d = Said::new_unchecked("EEvent789".into());

        let mut msg = "feat: signed commit".to_string();
        msg = append_trailer(&msg, WITNESS_RECEIPT_KEY, &r1.to_trailer_value().unwrap());
        msg = append_trailer(&msg, WITNESS_RECEIPT_KEY, &r2.to_trailer_value().unwrap());

        let receipts = extract_witness_receipts(&msg);
        assert_eq!(receipts.len(), 2);
    }

    #[test]
    fn extract_witness_receipts_ignores_other_trailers() {
        let signed = sample_signed_receipt();
        let mut msg = "feat: stuff".to_string();
        msg = append_trailer(&msg, "Signed-off-by", "Alice");
        msg = append_trailer(
            &msg,
            WITNESS_RECEIPT_KEY,
            &signed.to_trailer_value().unwrap(),
        );
        msg = append_trailer(&msg, "Co-authored-by", "Bob");

        let receipts = extract_witness_receipts(&msg);
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn unfold_lines_basic() {
        let text = "Key: start\n of-value\n more";
        let result = unfold_lines(text);
        assert_eq!(result, "Key: start of-value more");
    }

    #[test]
    fn parse_trailer_line_valid() {
        assert_eq!(
            parse_trailer_line("Signed-off-by: Alice"),
            Some(("Signed-off-by".into(), "Alice".into()))
        );
    }

    #[test]
    fn parse_trailer_line_invalid() {
        assert!(parse_trailer_line("no colon here").is_none());
        assert!(parse_trailer_line("has space key: value").is_none());
        assert!(parse_trailer_line(": no key").is_none());
    }
}
