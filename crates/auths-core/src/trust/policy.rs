//! Trust policy definitions for identity verification.

/// How the verifier decides to trust a root key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Accept on first use, pin for future. Interactive prompt on conflict.
    ///
    /// This is the default for interactive local development. When an unknown
    /// identity is encountered, the user is prompted to trust it. Once trusted,
    /// the identity is pinned for future verification.
    #[default]
    Tofu,

    /// Require an explicit pin, roots file, or --issuer-pk. No interactive prompts.
    ///
    /// This is the default for non-interactive environments (CI pipelines).
    /// Fails closed if the identity is unknown, ensuring CI never hangs waiting
    /// for interactive input.
    Explicit,
}

impl TrustPolicy {
    /// Parse a trust policy from a command-line flag value.
    ///
    /// # Examples
    ///
    /// ```
    /// use auths_core::trust::TrustPolicy;
    ///
    /// assert_eq!(TrustPolicy::from_str_flag("tofu"), Ok(TrustPolicy::Tofu));
    /// assert_eq!(TrustPolicy::from_str_flag("explicit"), Ok(TrustPolicy::Explicit));
    /// assert!(TrustPolicy::from_str_flag("invalid").is_err());
    /// ```
    pub fn from_str_flag(s: &str) -> Result<Self, String> {
        match s {
            "tofu" => Ok(Self::Tofu),
            "explicit" => Ok(Self::Explicit),
            other => Err(format!(
                "Unknown trust policy: '{}'. Valid values: tofu, explicit",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_flag_tofu() {
        assert_eq!(TrustPolicy::from_str_flag("tofu"), Ok(TrustPolicy::Tofu));
    }

    #[test]
    fn test_from_str_flag_explicit() {
        assert_eq!(
            TrustPolicy::from_str_flag("explicit"),
            Ok(TrustPolicy::Explicit)
        );
    }

    #[test]
    fn test_from_str_flag_invalid() {
        let result = TrustPolicy::from_str_flag("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown trust policy"));
    }

    #[test]
    fn test_default() {
        assert_eq!(TrustPolicy::default(), TrustPolicy::Tofu);
    }
}
