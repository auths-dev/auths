//! Identity-level witness configuration.
//!
//! Declares which witnesses an identity uses, the quorum threshold,
//! and the degradation policy when witnesses are unreachable.

use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration for witness receipts on an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Schema version for forwards-compatible deserialization.
    #[serde(default = "default_version")]
    pub version: u8,
    /// Witness server URLs (e.g. `["http://w1:3333", "http://w2:3333"]`).
    pub witness_urls: Vec<Url>,
    /// Minimum receipts required (k-of-n threshold).
    pub threshold: usize,
    /// Per-witness timeout in milliseconds.
    pub timeout_ms: u64,
    /// Degradation policy when quorum is not met.
    pub policy: WitnessPolicy,
}

fn default_version() -> u8 {
    1
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            version: 1,
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
            witness_urls: vec!["http://w1:3333".parse().unwrap()],
            threshold: 1,
            timeout_ms: 5000,
            ..Default::default()
        };
        assert!(config.is_enabled());
    }

    #[test]
    fn skip_policy_disables() {
        let config = WitnessConfig {
            witness_urls: vec!["http://w1:3333".parse().unwrap()],
            threshold: 1,
            timeout_ms: 5000,
            policy: WitnessPolicy::Skip,
            ..Default::default()
        };
        assert!(!config.is_enabled());
    }

    #[test]
    fn zero_threshold_disables() {
        let config = WitnessConfig {
            witness_urls: vec!["http://w1:3333".parse().unwrap()],
            threshold: 0,
            timeout_ms: 5000,
            ..Default::default()
        };
        assert!(!config.is_enabled());
    }

    #[test]
    fn default_version_is_one() {
        assert_eq!(WitnessConfig::default().version, 1);
    }

    #[test]
    fn json_without_version_deserializes_to_v1() {
        let json = r#"{
            "witness_urls": [],
            "threshold": 0,
            "timeout_ms": 5000,
            "policy": "Enforce"
        }"#;
        let config: WitnessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.version, 1);
    }

    #[test]
    fn json_with_version_roundtrips() {
        let config = WitnessConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let roundtripped: WitnessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.version, 1);
    }
}
