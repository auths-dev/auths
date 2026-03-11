//! Error code registry — **generated** by `cargo xtask gen-error-docs`.
//!
//! Do not edit manually. Re-run the generator after changing any `AuthsErrorInfo` impl:
//! ```sh
//! cargo xtask gen-error-docs
//! ```
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

/// Returns the explanation markdown for a given error code, or `None` if unknown.
///
/// Args:
/// * `code`: An error code string like `"AUTHS-E3001"`.
pub fn explain(code: &str) -> Option<&'static str> {
    match code {
        // --- auths-crypto (CryptoError) ---
        "AUTHS-E1001" => Some(include_str!("../../../../docs/errors/AUTHS-E1001.md")),
        "AUTHS-E1002" => Some(include_str!("../../../../docs/errors/AUTHS-E1002.md")),
        "AUTHS-E1003" => Some(include_str!("../../../../docs/errors/AUTHS-E1003.md")),
        "AUTHS-E1004" => Some(include_str!("../../../../docs/errors/AUTHS-E1004.md")),
        "AUTHS-E1005" => Some(include_str!("../../../../docs/errors/AUTHS-E1005.md")),

        // --- auths-crypto (DidKeyError) ---
        "AUTHS-E1101" => Some(include_str!("../../../../docs/errors/AUTHS-E1101.md")),
        "AUTHS-E1102" => Some(include_str!("../../../../docs/errors/AUTHS-E1102.md")),
        "AUTHS-E1103" => Some(include_str!("../../../../docs/errors/AUTHS-E1103.md")),
        "AUTHS-E1104" => Some(include_str!("../../../../docs/errors/AUTHS-E1104.md")),

        // --- auths-crypto (KeriDecodeError) ---
        "AUTHS-E1201" => Some(include_str!("../../../../docs/errors/AUTHS-E1201.md")),
        "AUTHS-E1202" => Some(include_str!("../../../../docs/errors/AUTHS-E1202.md")),
        "AUTHS-E1203" => Some(include_str!("../../../../docs/errors/AUTHS-E1203.md")),
        "AUTHS-E1204" => Some(include_str!("../../../../docs/errors/AUTHS-E1204.md")),

        // --- auths-crypto (SshKeyError) ---
        "AUTHS-E1301" => Some(include_str!("../../../../docs/errors/AUTHS-E1301.md")),
        "AUTHS-E1302" => Some(include_str!("../../../../docs/errors/AUTHS-E1302.md")),

        // --- auths-verifier (AttestationError) ---
        "AUTHS-E2001" => Some(include_str!("../../../../docs/errors/AUTHS-E2001.md")),
        "AUTHS-E2002" => Some(include_str!("../../../../docs/errors/AUTHS-E2002.md")),
        "AUTHS-E2003" => Some(include_str!("../../../../docs/errors/AUTHS-E2003.md")),
        "AUTHS-E2004" => Some(include_str!("../../../../docs/errors/AUTHS-E2004.md")),
        "AUTHS-E2005" => Some(include_str!("../../../../docs/errors/AUTHS-E2005.md")),
        "AUTHS-E2006" => Some(include_str!("../../../../docs/errors/AUTHS-E2006.md")),
        "AUTHS-E2007" => Some(include_str!("../../../../docs/errors/AUTHS-E2007.md")),
        "AUTHS-E2008" => Some(include_str!("../../../../docs/errors/AUTHS-E2008.md")),
        "AUTHS-E2009" => Some(include_str!("../../../../docs/errors/AUTHS-E2009.md")),
        "AUTHS-E2010" => Some(include_str!("../../../../docs/errors/AUTHS-E2010.md")),
        "AUTHS-E2011" => Some(include_str!("../../../../docs/errors/AUTHS-E2011.md")),
        "AUTHS-E2012" => Some(include_str!("../../../../docs/errors/AUTHS-E2012.md")),
        "AUTHS-E2013" => Some(include_str!("../../../../docs/errors/AUTHS-E2013.md")),
        "AUTHS-E2014" => Some(include_str!("../../../../docs/errors/AUTHS-E2014.md")),
        "AUTHS-E2015" => Some(include_str!("../../../../docs/errors/AUTHS-E2015.md")),
        "AUTHS-E2016" => Some(include_str!("../../../../docs/errors/AUTHS-E2016.md")),
        "AUTHS-E2017" => Some(include_str!("../../../../docs/errors/AUTHS-E2017.md")),
        "AUTHS-E2018" => Some(include_str!("../../../../docs/errors/AUTHS-E2018.md")),

        // --- auths-verifier (CommitVerificationError) ---
        "AUTHS-E2101" => Some(include_str!("../../../../docs/errors/AUTHS-E2101.md")),
        "AUTHS-E2102" => Some(include_str!("../../../../docs/errors/AUTHS-E2102.md")),
        "AUTHS-E2103" => Some(include_str!("../../../../docs/errors/AUTHS-E2103.md")),
        "AUTHS-E2104" => Some(include_str!("../../../../docs/errors/AUTHS-E2104.md")),
        "AUTHS-E2105" => Some(include_str!("../../../../docs/errors/AUTHS-E2105.md")),
        "AUTHS-E2106" => Some(include_str!("../../../../docs/errors/AUTHS-E2106.md")),
        "AUTHS-E2107" => Some(include_str!("../../../../docs/errors/AUTHS-E2107.md")),
        "AUTHS-E2108" => Some(include_str!("../../../../docs/errors/AUTHS-E2108.md")),
        "AUTHS-E2109" => Some(include_str!("../../../../docs/errors/AUTHS-E2109.md")),

        // --- auths-core (AgentError) ---
        "AUTHS-E3001" => Some(include_str!("../../../../docs/errors/AUTHS-E3001.md")),
        "AUTHS-E3002" => Some(include_str!("../../../../docs/errors/AUTHS-E3002.md")),
        "AUTHS-E3003" => Some(include_str!("../../../../docs/errors/AUTHS-E3003.md")),
        "AUTHS-E3004" => Some(include_str!("../../../../docs/errors/AUTHS-E3004.md")),
        "AUTHS-E3005" => Some(include_str!("../../../../docs/errors/AUTHS-E3005.md")),
        "AUTHS-E3006" => Some(include_str!("../../../../docs/errors/AUTHS-E3006.md")),
        "AUTHS-E3007" => Some(include_str!("../../../../docs/errors/AUTHS-E3007.md")),
        "AUTHS-E3008" => Some(include_str!("../../../../docs/errors/AUTHS-E3008.md")),
        "AUTHS-E3009" => Some(include_str!("../../../../docs/errors/AUTHS-E3009.md")),
        "AUTHS-E3010" => Some(include_str!("../../../../docs/errors/AUTHS-E3010.md")),
        "AUTHS-E3011" => Some(include_str!("../../../../docs/errors/AUTHS-E3011.md")),
        "AUTHS-E3012" => Some(include_str!("../../../../docs/errors/AUTHS-E3012.md")),
        "AUTHS-E3013" => Some(include_str!("../../../../docs/errors/AUTHS-E3013.md")),
        "AUTHS-E3014" => Some(include_str!("../../../../docs/errors/AUTHS-E3014.md")),
        "AUTHS-E3015" => Some(include_str!("../../../../docs/errors/AUTHS-E3015.md")),
        "AUTHS-E3016" => Some(include_str!("../../../../docs/errors/AUTHS-E3016.md")),
        "AUTHS-E3017" => Some(include_str!("../../../../docs/errors/AUTHS-E3017.md")),
        "AUTHS-E3018" => Some(include_str!("../../../../docs/errors/AUTHS-E3018.md")),
        "AUTHS-E3019" => Some(include_str!("../../../../docs/errors/AUTHS-E3019.md")),
        "AUTHS-E3020" => Some(include_str!("../../../../docs/errors/AUTHS-E3020.md")),
        "AUTHS-E3021" => Some(include_str!("../../../../docs/errors/AUTHS-E3021.md")),
        "AUTHS-E3022" => Some(include_str!("../../../../docs/errors/AUTHS-E3022.md")),
        "AUTHS-E3023" => Some(include_str!("../../../../docs/errors/AUTHS-E3023.md")),
        "AUTHS-E3024" => Some(include_str!("../../../../docs/errors/AUTHS-E3024.md")),

        // --- auths-core (TrustError) ---
        "AUTHS-E3101" => Some(include_str!("../../../../docs/errors/AUTHS-E3101.md")),
        "AUTHS-E3102" => Some(include_str!("../../../../docs/errors/AUTHS-E3102.md")),
        "AUTHS-E3103" => Some(include_str!("../../../../docs/errors/AUTHS-E3103.md")),
        "AUTHS-E3104" => Some(include_str!("../../../../docs/errors/AUTHS-E3104.md")),
        "AUTHS-E3105" => Some(include_str!("../../../../docs/errors/AUTHS-E3105.md")),
        "AUTHS-E3106" => Some(include_str!("../../../../docs/errors/AUTHS-E3106.md")),
        "AUTHS-E3107" => Some(include_str!("../../../../docs/errors/AUTHS-E3107.md")),

        // --- auths-core (PairingError) ---
        "AUTHS-E3201" => Some(include_str!("../../../../docs/errors/AUTHS-E3201.md")),
        "AUTHS-E3202" => Some(include_str!("../../../../docs/errors/AUTHS-E3202.md")),
        "AUTHS-E3203" => Some(include_str!("../../../../docs/errors/AUTHS-E3203.md")),
        "AUTHS-E3204" => Some(include_str!("../../../../docs/errors/AUTHS-E3204.md")),
        "AUTHS-E3205" => Some(include_str!("../../../../docs/errors/AUTHS-E3205.md")),
        "AUTHS-E3206" => Some(include_str!("../../../../docs/errors/AUTHS-E3206.md")),
        "AUTHS-E3207" => Some(include_str!("../../../../docs/errors/AUTHS-E3207.md")),

        // --- auths-core (CryptoError) ---
        "AUTHS-E3301" => Some(include_str!("../../../../docs/errors/AUTHS-E3301.md")),
        "AUTHS-E3302" => Some(include_str!("../../../../docs/errors/AUTHS-E3302.md")),
        "AUTHS-E3303" => Some(include_str!("../../../../docs/errors/AUTHS-E3303.md")),
        "AUTHS-E3304" => Some(include_str!("../../../../docs/errors/AUTHS-E3304.md")),
        "AUTHS-E3305" => Some(include_str!("../../../../docs/errors/AUTHS-E3305.md")),

        // --- auths-core (WitnessError) ---
        "AUTHS-E3401" => Some(include_str!("../../../../docs/errors/AUTHS-E3401.md")),
        "AUTHS-E3402" => Some(include_str!("../../../../docs/errors/AUTHS-E3402.md")),
        "AUTHS-E3403" => Some(include_str!("../../../../docs/errors/AUTHS-E3403.md")),
        "AUTHS-E3404" => Some(include_str!("../../../../docs/errors/AUTHS-E3404.md")),
        "AUTHS-E3405" => Some(include_str!("../../../../docs/errors/AUTHS-E3405.md")),
        "AUTHS-E3406" => Some(include_str!("../../../../docs/errors/AUTHS-E3406.md")),
        "AUTHS-E3407" => Some(include_str!("../../../../docs/errors/AUTHS-E3407.md")),
        "AUTHS-E3408" => Some(include_str!("../../../../docs/errors/AUTHS-E3408.md")),
        "AUTHS-E3409" => Some(include_str!("../../../../docs/errors/AUTHS-E3409.md")),

        // --- auths-core (StorageError) ---
        "AUTHS-E3501" => Some(include_str!("../../../../docs/errors/AUTHS-E3501.md")),
        "AUTHS-E3502" => Some(include_str!("../../../../docs/errors/AUTHS-E3502.md")),
        "AUTHS-E3503" => Some(include_str!("../../../../docs/errors/AUTHS-E3503.md")),
        "AUTHS-E3504" => Some(include_str!("../../../../docs/errors/AUTHS-E3504.md")),
        "AUTHS-E3505" => Some(include_str!("../../../../docs/errors/AUTHS-E3505.md")),

        // --- auths-core (NetworkError) ---
        "AUTHS-E3601" => Some(include_str!("../../../../docs/errors/AUTHS-E3601.md")),
        "AUTHS-E3602" => Some(include_str!("../../../../docs/errors/AUTHS-E3602.md")),
        "AUTHS-E3603" => Some(include_str!("../../../../docs/errors/AUTHS-E3603.md")),
        "AUTHS-E3604" => Some(include_str!("../../../../docs/errors/AUTHS-E3604.md")),
        "AUTHS-E3605" => Some(include_str!("../../../../docs/errors/AUTHS-E3605.md")),
        "AUTHS-E3606" => Some(include_str!("../../../../docs/errors/AUTHS-E3606.md")),

        // --- auths-core (ResolutionError) ---
        "AUTHS-E3701" => Some(include_str!("../../../../docs/errors/AUTHS-E3701.md")),
        "AUTHS-E3702" => Some(include_str!("../../../../docs/errors/AUTHS-E3702.md")),
        "AUTHS-E3703" => Some(include_str!("../../../../docs/errors/AUTHS-E3703.md")),
        "AUTHS-E3704" => Some(include_str!("../../../../docs/errors/AUTHS-E3704.md")),

        // --- auths-core (PlatformError) ---
        "AUTHS-E3801" => Some(include_str!("../../../../docs/errors/AUTHS-E3801.md")),
        "AUTHS-E3802" => Some(include_str!("../../../../docs/errors/AUTHS-E3802.md")),
        "AUTHS-E3803" => Some(include_str!("../../../../docs/errors/AUTHS-E3803.md")),
        "AUTHS-E3804" => Some(include_str!("../../../../docs/errors/AUTHS-E3804.md")),
        "AUTHS-E3805" => Some(include_str!("../../../../docs/errors/AUTHS-E3805.md")),
        "AUTHS-E3806" => Some(include_str!("../../../../docs/errors/AUTHS-E3806.md")),

        // --- auths-core (SshAgentError) ---
        "AUTHS-E3901" => Some(include_str!("../../../../docs/errors/AUTHS-E3901.md")),
        "AUTHS-E3902" => Some(include_str!("../../../../docs/errors/AUTHS-E3902.md")),
        "AUTHS-E3903" => Some(include_str!("../../../../docs/errors/AUTHS-E3903.md")),

        // --- auths-core (ConfigStoreError) ---
        "AUTHS-E3951" => Some(include_str!("../../../../docs/errors/AUTHS-E3951.md")),
        "AUTHS-E3952" => Some(include_str!("../../../../docs/errors/AUTHS-E3952.md")),

        _ => None,
    }
}

/// Returns a sorted slice of all registered error codes.
pub fn all_codes() -> &'static [&'static str] {
    static CODES: &[&str] = &[
        "AUTHS-E1001",
        "AUTHS-E1002",
        "AUTHS-E1003",
        "AUTHS-E1004",
        "AUTHS-E1005",
        "AUTHS-E1101",
        "AUTHS-E1102",
        "AUTHS-E1103",
        "AUTHS-E1104",
        "AUTHS-E1201",
        "AUTHS-E1202",
        "AUTHS-E1203",
        "AUTHS-E1204",
        "AUTHS-E1301",
        "AUTHS-E1302",
        "AUTHS-E2001",
        "AUTHS-E2002",
        "AUTHS-E2003",
        "AUTHS-E2004",
        "AUTHS-E2005",
        "AUTHS-E2006",
        "AUTHS-E2007",
        "AUTHS-E2008",
        "AUTHS-E2009",
        "AUTHS-E2010",
        "AUTHS-E2011",
        "AUTHS-E2012",
        "AUTHS-E2013",
        "AUTHS-E2014",
        "AUTHS-E2015",
        "AUTHS-E2016",
        "AUTHS-E2017",
        "AUTHS-E2018",
        "AUTHS-E2101",
        "AUTHS-E2102",
        "AUTHS-E2103",
        "AUTHS-E2104",
        "AUTHS-E2105",
        "AUTHS-E2106",
        "AUTHS-E2107",
        "AUTHS-E2108",
        "AUTHS-E2109",
        "AUTHS-E3001",
        "AUTHS-E3002",
        "AUTHS-E3003",
        "AUTHS-E3004",
        "AUTHS-E3005",
        "AUTHS-E3006",
        "AUTHS-E3007",
        "AUTHS-E3008",
        "AUTHS-E3009",
        "AUTHS-E3010",
        "AUTHS-E3011",
        "AUTHS-E3012",
        "AUTHS-E3013",
        "AUTHS-E3014",
        "AUTHS-E3015",
        "AUTHS-E3016",
        "AUTHS-E3017",
        "AUTHS-E3018",
        "AUTHS-E3019",
        "AUTHS-E3020",
        "AUTHS-E3021",
        "AUTHS-E3022",
        "AUTHS-E3023",
        "AUTHS-E3024",
        "AUTHS-E3101",
        "AUTHS-E3102",
        "AUTHS-E3103",
        "AUTHS-E3104",
        "AUTHS-E3105",
        "AUTHS-E3106",
        "AUTHS-E3107",
        "AUTHS-E3201",
        "AUTHS-E3202",
        "AUTHS-E3203",
        "AUTHS-E3204",
        "AUTHS-E3205",
        "AUTHS-E3206",
        "AUTHS-E3207",
        "AUTHS-E3301",
        "AUTHS-E3302",
        "AUTHS-E3303",
        "AUTHS-E3304",
        "AUTHS-E3305",
        "AUTHS-E3401",
        "AUTHS-E3402",
        "AUTHS-E3403",
        "AUTHS-E3404",
        "AUTHS-E3405",
        "AUTHS-E3406",
        "AUTHS-E3407",
        "AUTHS-E3408",
        "AUTHS-E3409",
        "AUTHS-E3501",
        "AUTHS-E3502",
        "AUTHS-E3503",
        "AUTHS-E3504",
        "AUTHS-E3505",
        "AUTHS-E3601",
        "AUTHS-E3602",
        "AUTHS-E3603",
        "AUTHS-E3604",
        "AUTHS-E3605",
        "AUTHS-E3606",
        "AUTHS-E3701",
        "AUTHS-E3702",
        "AUTHS-E3703",
        "AUTHS-E3704",
        "AUTHS-E3801",
        "AUTHS-E3802",
        "AUTHS-E3803",
        "AUTHS-E3804",
        "AUTHS-E3805",
        "AUTHS-E3806",
        "AUTHS-E3901",
        "AUTHS-E3902",
        "AUTHS-E3903",
        "AUTHS-E3951",
        "AUTHS-E3952",
    ];
    CODES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_returns_content_for_known_code() {
        assert!(explain("AUTHS-E1001").is_some());
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
            assert!(
                window[0] < window[1],
                "codes not sorted: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn all_codes_count_matches_registry() {
        assert_eq!(all_codes().len(), 120);
    }
}
