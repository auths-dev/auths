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

error_registry! {
    // --- auths-verifier (E2xxx) ---
    "AUTHS-E2001" => "AUTHS-E2001.md",
    "AUTHS-E2002" => "AUTHS-E2002.md",
    "AUTHS-E2003" => "AUTHS-E2003.md",
    "AUTHS-E2010" => "AUTHS-E2010.md",
    "AUTHS-E2016" => "AUTHS-E2016.md",
    // --- auths-core: AgentError (E30xx) ---
    "AUTHS-E3001" => "AUTHS-E3001.md",
    "AUTHS-E3002" => "AUTHS-E3002.md",
    "AUTHS-E3003" => "AUTHS-E3003.md",
    "AUTHS-E3004" => "AUTHS-E3004.md",
    "AUTHS-E3005" => "AUTHS-E3005.md",
    "AUTHS-E3006" => "AUTHS-E3006.md",
    "AUTHS-E3007" => "AUTHS-E3007.md",
    "AUTHS-E3008" => "AUTHS-E3008.md",
    "AUTHS-E3009" => "AUTHS-E3009.md",
    "AUTHS-E3010" => "AUTHS-E3010.md",
    "AUTHS-E3011" => "AUTHS-E3011.md",
    "AUTHS-E3012" => "AUTHS-E3012.md",
    "AUTHS-E3013" => "AUTHS-E3013.md",
    "AUTHS-E3014" => "AUTHS-E3014.md",
    "AUTHS-E3015" => "AUTHS-E3015.md",
    "AUTHS-E3016" => "AUTHS-E3016.md",
    "AUTHS-E3017" => "AUTHS-E3017.md",
    "AUTHS-E3018" => "AUTHS-E3018.md",
    "AUTHS-E3019" => "AUTHS-E3019.md",
    "AUTHS-E3020" => "AUTHS-E3020.md",
    "AUTHS-E3021" => "AUTHS-E3021.md",
    "AUTHS-E3022" => "AUTHS-E3022.md",
    "AUTHS-E3023" => "AUTHS-E3023.md",
    "AUTHS-E3024" => "AUTHS-E3024.md",
    // --- auths-core: TrustError (E31xx) ---
    "AUTHS-E3101" => "AUTHS-E3101.md",
    "AUTHS-E3102" => "AUTHS-E3102.md",
    "AUTHS-E3103" => "AUTHS-E3103.md",
    "AUTHS-E3104" => "AUTHS-E3104.md",
    "AUTHS-E3105" => "AUTHS-E3105.md",
    "AUTHS-E3106" => "AUTHS-E3106.md",
    "AUTHS-E3107" => "AUTHS-E3107.md",
    // --- auths-core: PairingError (E32xx) ---
    "AUTHS-E3201" => "AUTHS-E3201.md",
    "AUTHS-E3202" => "AUTHS-E3202.md",
    "AUTHS-E3203" => "AUTHS-E3203.md",
    "AUTHS-E3204" => "AUTHS-E3204.md",
    "AUTHS-E3205" => "AUTHS-E3205.md",
    "AUTHS-E3206" => "AUTHS-E3206.md",
    "AUTHS-E3207" => "AUTHS-E3207.md",
    // --- auths-core: CryptoError/ssh (E33xx) ---
    "AUTHS-E3301" => "AUTHS-E3301.md",
    "AUTHS-E3302" => "AUTHS-E3302.md",
    "AUTHS-E3303" => "AUTHS-E3303.md",
    "AUTHS-E3304" => "AUTHS-E3304.md",
    "AUTHS-E3305" => "AUTHS-E3305.md",
    // --- auths-core: WitnessError (E34xx) ---
    "AUTHS-E3401" => "AUTHS-E3401.md",
    "AUTHS-E3402" => "AUTHS-E3402.md",
    "AUTHS-E3403" => "AUTHS-E3403.md",
    "AUTHS-E3404" => "AUTHS-E3404.md",
    "AUTHS-E3405" => "AUTHS-E3405.md",
    "AUTHS-E3406" => "AUTHS-E3406.md",
    "AUTHS-E3407" => "AUTHS-E3407.md",
    "AUTHS-E3408" => "AUTHS-E3408.md",
    "AUTHS-E3409" => "AUTHS-E3409.md",
    // --- auths-core: StorageError (E35xx) ---
    "AUTHS-E3501" => "AUTHS-E3501.md",
    "AUTHS-E3502" => "AUTHS-E3502.md",
    "AUTHS-E3503" => "AUTHS-E3503.md",
    "AUTHS-E3504" => "AUTHS-E3504.md",
    "AUTHS-E3505" => "AUTHS-E3505.md",
    // --- auths-core: NetworkError (E36xx) ---
    "AUTHS-E3601" => "AUTHS-E3601.md",
    "AUTHS-E3602" => "AUTHS-E3602.md",
    "AUTHS-E3603" => "AUTHS-E3603.md",
    "AUTHS-E3604" => "AUTHS-E3604.md",
    "AUTHS-E3605" => "AUTHS-E3605.md",
    "AUTHS-E3606" => "AUTHS-E3606.md",
    // --- auths-core: ResolutionError (E37xx) ---
    "AUTHS-E3701" => "AUTHS-E3701.md",
    "AUTHS-E3702" => "AUTHS-E3702.md",
    "AUTHS-E3703" => "AUTHS-E3703.md",
    "AUTHS-E3704" => "AUTHS-E3704.md",
    // --- auths-core: PlatformError (E38xx) ---
    "AUTHS-E3801" => "AUTHS-E3801.md",
    "AUTHS-E3802" => "AUTHS-E3802.md",
    "AUTHS-E3803" => "AUTHS-E3803.md",
    "AUTHS-E3804" => "AUTHS-E3804.md",
    "AUTHS-E3805" => "AUTHS-E3805.md",
    "AUTHS-E3806" => "AUTHS-E3806.md",
    // --- auths-core: SshAgentError (E39xx) ---
    "AUTHS-E3901" => "AUTHS-E3901.md",
    "AUTHS-E3902" => "AUTHS-E3902.md",
    "AUTHS-E3903" => "AUTHS-E3903.md",
    // --- auths-core: ConfigStoreError (E395x) ---
    "AUTHS-E3951" => "AUTHS-E3951.md",
    "AUTHS-E3952" => "AUTHS-E3952.md",
    // --- auths-sdk (E5xxx) ---
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
        assert_eq!(all_codes().len(), 85);
    }
}
