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
use auths_keri::witness::independence::{
    Independence, IndependencePolicy, OperatorAttributes, WitnessOperatorInfo, spans_distinct,
};
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
    /// Operator-independence attributes for this witness ([`WitnessOperatorInfo`],
    /// shared with the CT trust root). Absent ⇒ this witness cannot contribute to
    /// proving quorum independence (fail closed, never "assume distinct").
    #[serde(default)]
    pub operator_info: Option<WitnessOperatorInfo>,
}

impl WitnessRef {
    /// Build the [`OperatorAttributes`] for this witness, keyed by its AID.
    ///
    /// Returns `None` when the witness has no pinned `operator_info` — the caller
    /// must treat that as "independence cannot be proven", not as a distinct
    /// operator.
    ///
    /// Args:
    /// * `self`: The pinned witness.
    ///
    /// Usage:
    /// ```ignore
    /// let attrs = witness_ref.operator_attributes();
    /// ```
    pub fn operator_attributes(&self) -> Option<OperatorAttributes> {
        self.operator_info
            .as_ref()
            .map(|info| info.to_attributes(self.aid.as_str()))
    }
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

    /// Whether the configured roster *could* form an independent quorum.
    ///
    /// A startup fail-fast check over the whole pinned set: if any witness lacks
    /// `operator_info`, independence cannot be proven (fail closed). This is the
    /// roster-capability check — NOT the security-decisive per-attestation check,
    /// which must run [`spans_distinct`] over the ACTUAL cosigning quorum.
    ///
    /// Args:
    /// * `policy`: The minimum-diversity thresholds to require.
    ///
    /// Usage:
    /// ```ignore
    /// let verdict = config.roster_independence(&IndependencePolicy::default());
    /// if !verdict.independent { /* refuse to start, or warn */ }
    /// ```
    pub fn roster_independence(&self, policy: &IndependencePolicy) -> Independence {
        let mut attesters = Vec::with_capacity(self.witnesses.len());
        for w in &self.witnesses {
            match w.operator_attributes() {
                Some(a) => attesters.push(a),
                None => {
                    return Independence::cannot_prove(format!(
                        "witness {} is missing operator/organization/jurisdiction/infrastructure attributes",
                        w.aid.as_str()
                    ));
                }
            }
        }
        spans_distinct(&attesters, policy)
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
    use auths_keri::witness::independence::{
        Infrastructure, Jurisdiction, OperatorId, Organization,
    };

    fn ref_for(url: &str, aid: &str) -> WitnessRef {
        WitnessRef {
            url: url.parse().unwrap(),
            aid: Prefix::new_unchecked(aid.to_string()),
            operator_info: None,
        }
    }

    fn tagged_ref(aid: &str, operator: &str, org: &str, jur: &str, infra: &str) -> WitnessRef {
        WitnessRef {
            url: "http://w:3333".parse().unwrap(),
            aid: Prefix::new_unchecked(aid.to_string()),
            operator_info: Some(WitnessOperatorInfo {
                operator: OperatorId::new(operator).unwrap(),
                organization: Organization::new(org).unwrap(),
                jurisdiction: Jurisdiction::new(jur).unwrap(),
                infrastructure: Infrastructure::new(infra).unwrap(),
            }),
        }
    }

    fn config_with(witnesses: Vec<WitnessRef>) -> WitnessConfig {
        WitnessConfig {
            witnesses,
            threshold: 2,
            ..Default::default()
        }
    }

    #[test]
    fn roster_independent_with_three_diverse_operators() {
        let config = config_with(vec![
            tagged_ref(
                "BW_A0000000000000000000000000000000000000000",
                "op-a",
                "org-a",
                "US",
                "aws/us-east-1",
            ),
            tagged_ref(
                "BW_B0000000000000000000000000000000000000000",
                "op-b",
                "org-b",
                "DE",
                "gcp/eu-west-1",
            ),
            tagged_ref(
                "BW_C0000000000000000000000000000000000000000",
                "op-c",
                "org-c",
                "JP",
                "azure/jp-east",
            ),
        ]);
        assert!(
            config
                .roster_independence(&IndependencePolicy::default())
                .independent
        );
    }

    #[test]
    fn roster_fails_closed_when_attributes_missing() {
        // One tagged, one untagged → cannot prove independence.
        let config = config_with(vec![
            tagged_ref(
                "BW_A0000000000000000000000000000000000000000",
                "op-a",
                "org-a",
                "US",
                "aws/us-east-1",
            ),
            ref_for(
                "http://w2:3333",
                "BW_B0000000000000000000000000000000000000000",
            ),
        ]);
        let verdict = config.roster_independence(&IndependencePolicy::default());
        assert!(!verdict.independent);
    }

    #[test]
    fn roster_same_org_is_not_independent() {
        let config = config_with(vec![
            tagged_ref(
                "BW_A0000000000000000000000000000000000000000",
                "op-a",
                "acme",
                "US",
                "aws/us-east-1",
            ),
            tagged_ref(
                "BW_B0000000000000000000000000000000000000000",
                "op-b",
                "acme",
                "DE",
                "gcp/eu-west-1",
            ),
            tagged_ref(
                "BW_C0000000000000000000000000000000000000000",
                "op-c",
                "acme",
                "JP",
                "azure/jp-east",
            ),
        ]);
        assert!(
            !config
                .roster_independence(&IndependencePolicy::default())
                .independent
        );
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
