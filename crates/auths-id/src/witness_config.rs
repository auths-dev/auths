//! Identity-level witness configuration.
//!
//! Declares which witnesses an identity uses, the quorum threshold,
//! and the degradation policy when witnesses are unreachable.
//!
//! A witness is identified by its **AID** (a curve-tagged CESR verkey prefix),
//! not merely a URL: the AID is what an identity designates in `b[]`, what KAWA
//! dedupes quorum by, and what a collected receipt's signature is verified
//! against. The URL is only where to reach it. Resolving a URL to its AID
//! (`GET /health`) happens at the infra/CLI boundary (it needs the HTTP client);
//! this layer owns the typed config + the pin/dedup logic.

use std::path::Path;

use auths_keri::Prefix;
use serde::{Deserialize, Serialize};
use url::Url;

/// Bundled witness configuration for anchor operations.
///
/// Replaces the error-prone `(Option<&WitnessConfig>, Option<&Path>)` pair.
/// With two separate Options, a caller can pass `Some(config)` with `None` for
/// `repo_path`, silently degrading `Enforce` to a no-op. This enum makes that
/// invalid state unrepresentable.
#[derive(Debug, Clone, Copy)]
pub enum WitnessParams<'a> {
    /// Witness receipting is active with a validated config and storage path.
    Enabled {
        config: &'a WitnessConfig,
        repo_path: &'a Path,
    },
    /// Witness receipting is explicitly disabled for this operation.
    Disabled,
}

/// A configured witness: where to reach it (`url`) and who it is (`aid`).
///
/// `aid` is the witness's curve-tagged CESR verkey prefix (parseable via
/// `KeriPublicKey::parse`) — the value designated in `b[]` and matched against
/// receipt signatures. It is resolved once (from the witness's `/health`) and
/// pinned, so later trust decisions never depend on re-resolving a URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessRef {
    /// Where to reach the witness server.
    pub url: Url,
    /// The witness's pinned AID (curve-tagged CESR verkey prefix).
    pub aid: Prefix,
}

/// Configuration for witness receipts on an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Schema version for forwards-compatible deserialization.
    #[serde(default = "default_version")]
    pub version: u8,
    /// Configured witnesses (pinned `(url, aid)` pairs).
    #[serde(default)]
    pub witnesses: Vec<WitnessRef>,
    /// Minimum receipts required (k-of-n threshold).
    pub threshold: usize,
    /// Per-witness timeout in milliseconds.
    pub timeout_ms: u64,
    /// Degradation policy when quorum is not met.
    pub policy: WitnessPolicy,
}

fn default_version() -> u8 {
    2
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            version: 2,
            witnesses: vec![],
            threshold: 0,
            timeout_ms: 5000,
            policy: WitnessPolicy::Enforce,
        }
    }
}

impl WitnessConfig {
    /// Returns `true` when witness collection should actually run.
    pub fn is_enabled(&self) -> bool {
        !self.witnesses.is_empty() && self.threshold > 0 && self.policy != WitnessPolicy::Skip
    }

    /// The configured witness URLs (where to reach each witness).
    pub fn urls(&self) -> impl Iterator<Item = &Url> {
        self.witnesses.iter().map(|w| &w.url)
    }

    /// The configured witness AIDs (the values designated in `b[]`).
    pub fn aids(&self) -> impl Iterator<Item = &Prefix> {
        self.witnesses.iter().map(|w| &w.aid)
    }

    /// Whether `aid` is one of the configured witnesses (for receipt provenance
    /// checks and KAWA membership).
    pub fn contains_aid(&self, aid: &Prefix) -> bool {
        self.witnesses.iter().any(|w| &w.aid == aid)
    }

    /// Pin a witness, deduped by AID. Returns `true` if newly added, `false` if
    /// an entry with the same AID was already present.
    pub fn pin(&mut self, witness: WitnessRef) -> bool {
        if self.witnesses.iter().any(|w| w.aid == witness.aid) {
            return false;
        }
        self.witnesses.push(witness);
        true
    }

    /// Remove the witness with the given URL. Returns `true` if one was removed.
    pub fn remove_url(&mut self, url: &Url) -> bool {
        let before = self.witnesses.len();
        self.witnesses.retain(|w| &w.url != url);
        self.witnesses.len() != before
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

    fn ref_for(url: &str, aid: &str) -> WitnessRef {
        WitnessRef {
            url: url.parse().unwrap(),
            aid: Prefix::new_unchecked(aid.to_string()),
        }
    }

    #[test]
    fn default_is_disabled() {
        let config = WitnessConfig::default();
        assert!(!config.is_enabled());
    }

    #[test]
    fn enabled_with_witnesses_and_threshold() {
        let config = WitnessConfig {
            witnesses: vec![ref_for(
                "http://w1:3333",
                "BWitnessOne00000000000000000000000000000000",
            )],
            threshold: 1,
            timeout_ms: 5000,
            ..Default::default()
        };
        assert!(config.is_enabled());
        assert_eq!(config.urls().count(), 1);
        assert!(config.contains_aid(&Prefix::new_unchecked(
            "BWitnessOne00000000000000000000000000000000".to_string()
        )));
    }

    #[test]
    fn skip_policy_disables() {
        let config = WitnessConfig {
            witnesses: vec![ref_for(
                "http://w1:3333",
                "BWitnessOne00000000000000000000000000000000",
            )],
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
            witnesses: vec![ref_for(
                "http://w1:3333",
                "BWitnessOne00000000000000000000000000000000",
            )],
            threshold: 0,
            timeout_ms: 5000,
            ..Default::default()
        };
        assert!(!config.is_enabled());
    }

    #[test]
    fn pin_dedupes_by_aid() {
        let mut config = WitnessConfig::default();
        assert!(config.pin(ref_for(
            "http://w1:3333",
            "BWitnessOne00000000000000000000000000000000"
        )));
        // Same AID, different URL → not added again.
        assert!(!config.pin(ref_for(
            "http://other:3333",
            "BWitnessOne00000000000000000000000000000000"
        )));
        assert_eq!(config.witnesses.len(), 1);
    }

    #[test]
    fn remove_url_drops_entry() {
        let mut config = WitnessConfig::default();
        config.pin(ref_for(
            "http://w1:3333",
            "BWitnessOne00000000000000000000000000000000",
        ));
        assert!(config.remove_url(&"http://w1:3333".parse().unwrap()));
        assert!(config.witnesses.is_empty());
        assert!(!config.remove_url(&"http://w1:3333".parse().unwrap()));
    }

    #[test]
    fn deserializes_v2_shape() {
        let json = serde_json::json!({
            "version": 2,
            "witnesses": [],
            "threshold": 0,
            "timeout_ms": 5000,
            "policy": "Enforce"
        });
        let config: WitnessConfig = serde_json::from_value(json).unwrap();
        assert!(!config.is_enabled());
    }
}
