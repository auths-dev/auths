//! Product-facing rendering of identifiers for human-readable output.
//!
//! Identifiers are canonically `did:keri:<prefix>` (a W3C DID with a
//! self-addressing prefix). That canonical form is correct for `--json`, files,
//! bundles, trailers, and anything a machine consumes — it MUST never change.
//!
//! In **human-facing TEXT** output, however, the first-run surface should speak
//! the product's own vocabulary, not the underlying protocol's. This module maps
//! the canonical DID to a product handle (`auths:<prefix>`) for display only. The
//! prefix is preserved verbatim, so the handle is still unambiguous and a user
//! who needs the canonical form can recover it (or read `--json`).
//!
//! Use [`product_id`] anywhere a `did:keri:` would otherwise be printed to a
//! person; never use it where the value is parsed, stored, or transmitted.

/// The canonical DID method prefix carried by every identity string.
const DID_METHOD_PREFIX: &str = "did:keri:";

/// The product-facing scheme shown to people in place of the method prefix.
const PRODUCT_PREFIX: &str = "auths:";

/// Render an identifier in product-facing form for human TEXT output.
///
/// `did:keri:<prefix>` becomes `auths:<prefix>`. Any string that is not a
/// `did:keri:` identifier (already a product handle, an unexpected shape, etc.)
/// is returned unchanged, so this is always safe to wrap an arbitrary id in.
///
/// This is a DISPLAY transform only. It is never the inverse of any parser:
/// nothing in the codebase reads `auths:` back; the canonical `did:keri:` form
/// remains the single source of truth for `--json`, storage, and the wire.
///
/// Args:
/// * `did`: An identifier, canonically `did:keri:<prefix>`.
///
/// Usage:
/// ```ignore
/// let shown = product_id(&result.identity_did); // "auths:EPme…"
/// println!("  Identity: {shown}");
/// ```
pub fn product_id(did: &str) -> String {
    match did.strip_prefix(DID_METHOD_PREFIX) {
        Some(prefix) => format!("{PRODUCT_PREFIX}{prefix}"),
        None => did.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_canonical_did_to_product_handle() {
        assert_eq!(
            product_id("did:keri:EPmeUXn8Gbk_4u0ilbMnA46y6Q_5X1nRIpjPxCDmejml"),
            "auths:EPmeUXn8Gbk_4u0ilbMnA46y6Q_5X1nRIpjPxCDmejml"
        );
    }

    #[test]
    fn preserves_the_prefix_verbatim() {
        let prefix = "EBb6li302WtvHTrhg4FUmFuiWjrQEb-2mOD1TYrVd6ge";
        let shown = product_id(&format!("did:keri:{prefix}"));
        assert!(shown.ends_with(prefix), "prefix must be preserved exactly");
    }

    #[test]
    fn passes_through_non_did_strings_unchanged() {
        assert_eq!(
            product_id("auths:already-a-handle"),
            "auths:already-a-handle"
        );
        assert_eq!(product_id(""), "");
        assert_eq!(product_id("did:key:zDnaeh"), "did:key:zDnaeh");
    }

    #[test]
    fn display_form_carries_no_protocol_method_token() {
        // The product handle must not surface the DID method token to a person.
        let shown = product_id("did:keri:EPmeUXn8Gbk_4u0ilbMnA46y6Q");
        assert!(!shown.contains("did:keri:"));
        assert!(shown.starts_with("auths:"));
    }
}
