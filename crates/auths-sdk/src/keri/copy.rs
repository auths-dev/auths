//! Pinned user-facing copy for identity-related flows.
//!
//! Same strings are rendered by the CLI (`auths init`, `auths status`)
//! and by the iOS app (onboarding confirmation, duplicity banner). The
//! constants below are the single source of truth; Swift mirrors them
//! via `Copy/StaticCopy.swift` and a copy-parity test asserts the
//! action-block lines match byte-for-byte.

/// Message shown after `auths init` creates a device KEL but before any
/// shared identity exists. Substitutes the device-KEL prefix.
pub const AUTHS_INIT_SUCCESS_TEMPLATE: &str = "\
\u{2713} Created device KEL: did:keri:E{prefix}
  This identifies *this machine*, not your identity yet.
  Next: run `auths pair` on another device to bind them as controllers of a shared identity.
";

/// Warning rendered when the shared KEL has a diverging rotation at a
/// given sequence number. Substitutes the divergence `seq`.
pub const DUPLICITY_WARNING_TEMPLATE: &str = "\
\u{26A0} Your identity's key-event log has diverged.
   Two controllers signed incompatible rotations at sequence {seq}.
   To resolve, pick the device you trust and run:
     auths device remove <other-controller-did>
   This produces an authoritative rotation on that device's timeline.
";

/// Format the `auths init` success message with the given device-KEL prefix.
///
/// Args:
/// * `prefix`: The Blake3-SAID of the inception event, without the `did:keri:E` CESR code.
///
/// Usage:
/// ```
/// use auths_sdk::keri::copy::format_init_success;
/// let s = format_init_success("abc123");
/// assert!(s.contains("did:keri:Eabc123"));
/// ```
pub fn format_init_success(prefix: &str) -> String {
    AUTHS_INIT_SUCCESS_TEMPLATE.replace("{prefix}", prefix)
}

/// Format the duplicity warning for rendering via `auths status` or the iOS banner.
///
/// Args:
/// * `seq`: Sequence number at which the shared KEL diverged.
///
/// Usage:
/// ```
/// use auths_sdk::keri::copy::format_duplicity_warning;
/// let s = format_duplicity_warning(2);
/// assert!(s.contains("sequence 2"));
/// ```
pub fn format_duplicity_warning(seq: u64) -> String {
    DUPLICITY_WARNING_TEMPLATE.replace("{seq}", &seq.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_success_substitutes_prefix() {
        let out = format_init_success("abc");
        assert!(out.contains("did:keri:Eabc"));
        assert!(out.contains("This identifies *this machine*"));
    }

    #[test]
    fn init_success_is_stable_across_calls() {
        let a = format_init_success("xyz");
        let b = format_init_success("xyz");
        assert_eq!(a, b);
    }

    #[test]
    fn duplicity_warning_substitutes_seq() {
        let out = format_duplicity_warning(42);
        assert!(out.contains("sequence 42"));
        assert!(out.contains("auths device remove"));
    }

    #[test]
    fn duplicity_warning_action_block_is_byte_stable() {
        // The iOS banner re-flows prose for width, but the action
        // block (the three lines starting "To resolve...") must match
        // the Rust render byte-for-byte. Lock it.
        let out = format_duplicity_warning(7);
        assert!(out.contains(
            "   To resolve, pick the device you trust and run:\n\
             \x20    auths device remove <other-controller-did>"
        ));
    }
}
