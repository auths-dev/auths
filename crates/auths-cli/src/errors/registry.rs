//! Error code registry mapping `AUTHS-E{NNNN}` codes to explanation markdown.
//!
//! ## Range Allocation
//!
//! | Range   | Crate            | Layer |
//! |---------|------------------|-------|
//! | E0xxx   | Reserved/meta    | -     |
//! | E1xxx   | auths-crypto     | 0     |
//! | E2xxx   | auths-verifier   | 1     |
//! | E3xxx   | auths-core       | 2     |
//! | E4xxx   | auths-id         | 3     |
//! | E5xxx   | auths-sdk        | 3-4   |
//! | E6xxx   | auths-cli        | 6     |

macro_rules! error_registry {
    ($($code:literal => $path:literal),* $(,)?) => {
        /// Returns the explanation markdown for a given error code, or `None` if unknown.
        ///
        /// Args:
        /// * `code`: An error code string like `"AUTHS-E3001"`.
        ///
        /// Usage:
        /// ```ignore
        /// if let Some(text) = explain("AUTHS-E3001") {
        ///     println!("{text}");
        /// }
        /// ```
        pub fn explain(code: &str) -> Option<&'static str> {
            match code {
                $($code => Some(include_str!(concat!("../../../../docs/errors/", $path))),)*
                _ => None,
            }
        }

        /// Returns a sorted slice of all registered error codes.
        ///
        /// Usage:
        /// ```ignore
        /// for code in all_codes() {
        ///     println!("{code}");
        /// }
        /// ```
        pub fn all_codes() -> &'static [&'static str] {
            static CODES: &[&str] = &[$($code),*];
            CODES
        }
    };
}

// --- auths-verifier (E2xxx) ---
// --- auths-core (E3xxx) ---
// --- auths-sdk (E5xxx) ---
error_registry! {
    "AUTHS-E2001" => "AUTHS-E2001.md",
    "AUTHS-E2002" => "AUTHS-E2002.md",
    "AUTHS-E2003" => "AUTHS-E2003.md",
    "AUTHS-E2010" => "AUTHS-E2010.md",
    "AUTHS-E2016" => "AUTHS-E2016.md",
    "AUTHS-E3001" => "AUTHS-E3001.md",
    "AUTHS-E3002" => "AUTHS-E3002.md",
    "AUTHS-E3014" => "AUTHS-E3014.md",
    "AUTHS-E5001" => "AUTHS-E5001.md",
    "AUTHS-E5005" => "AUTHS-E5005.md",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_returns_content_for_known_code() {
        let text = explain("AUTHS-E3001");
        assert!(text.is_some());
        assert!(text.unwrap().contains("Key Not Found"));
    }

    #[test]
    fn explain_returns_none_for_unknown_code() {
        assert!(explain("AUTHS-E9999").is_none());
    }

    #[test]
    fn all_codes_is_sorted() {
        let codes = all_codes();
        assert!(!codes.is_empty());
        for window in codes.windows(2) {
            assert!(window[0] < window[1], "codes not sorted: {} >= {}", window[0], window[1]);
        }
    }

    #[test]
    fn all_codes_count_matches_registry() {
        assert_eq!(all_codes().len(), 10);
    }
}
