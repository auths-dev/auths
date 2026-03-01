//! Identity-level witness configuration.
//!
//! Declares which witnesses an identity uses, the quorum threshold,
//! and the degradation policy when witnesses are unreachable.

use serde::{Deserialize, Serialize};

/// Configuration for witness receipts on an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Witness server URLs (e.g. `["http://w1:3333", "http://w2:3333"]`).
    pub witness_urls: Vec<String>,
    /// Minimum receipts required (k-of-n threshold).
    pub threshold: usize,
    /// Per-witness timeout in milliseconds.
    pub timeout_ms: u64,
    /// Degradation policy when quorum is not met.
    pub policy: WitnessPolicy,
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            witness_urls: vec![],
            threshold: 0,
            timeout_ms: 5000,
            policy: WitnessPolicy::Enforce,
        }
    }
}

impl WitnessConfig {
    /// Returns `true` when witness collection should actually run.
    pub fn is_enabled(&self) -> bool {
        !self.witness_urls.is_empty() && self.threshold > 0 && self.policy != WitnessPolicy::Skip
    }
}

/// What to do when the witness quorum cannot be met.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum WitnessPolicy {
    /// Fail the operation if quorum is not met.
    #[default]
    Enforce,
    /// Log a warning but continue.
    Warn,
    /// Skip witness collection entirely.
    Skip,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let config = WitnessConfig::default();
        assert!(!config.is_enabled());
    }

    #[test]
    fn enabled_with_urls_and_threshold() {
        let config = WitnessConfig {
            witness_urls: vec!["http://w1:3333".into()],
            threshold: 1,
            timeout_ms: 5000,
            policy: WitnessPolicy::Enforce,
        };
        assert!(config.is_enabled());
    }

    #[test]
    fn skip_policy_disables() {
        let config = WitnessConfig {
            witness_urls: vec!["http://w1:3333".into()],
            threshold: 1,
            timeout_ms: 5000,
            policy: WitnessPolicy::Skip,
        };
        assert!(!config.is_enabled());
    }

    #[test]
    fn zero_threshold_disables() {
        let config = WitnessConfig {
            witness_urls: vec!["http://w1:3333".into()],
            threshold: 0,
            timeout_ms: 5000,
            policy: WitnessPolicy::Enforce,
        };
        assert!(!config.is_enabled());
    }
}
