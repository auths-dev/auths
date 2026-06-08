//! Typed, fail-closed witness-diversity policy (`data/witness_policy.json`).
//!
//! The pinned policy declares who may cosign checkpoints and the minimum
//! organization/jurisdiction/infrastructure diversity an honest quorum must span.
//! Per `docs/security/witness-diversity.md` §97, a passing verify with a missing
//! or placeholder policy is worse than a loud failure — so every fault here
//! (missing file, unparseable JSON, unknown schema version, or a placeholder
//! `pubkey_b64`) is a hard error, never a silent "no witnesses required".

use std::path::Path;

use auths_keri::witness::independence::{
    EquivocationDetection, HonestyCeiling, Independence, IndependencePolicy, Infrastructure,
    Jurisdiction, OperatorAttributes, OperatorId, Organization, WitnessOperatorInfo,
    honesty_ceiling, spans_distinct,
};
use serde::Deserialize;

/// The only witness-policy schema version this verifier understands.
const SUPPORTED_VERSION: u32 = 1;
/// Substring marking an unpinned placeholder key (e.g. `REPLACE_WITH_…`).
const PLACEHOLDER_MARKER: &str = "REPLACE_WITH";

/// Typed, fail-closed failure loading or validating a witness policy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessPolicyError {
    /// No policy file at the given path.
    #[error("witness policy not found at {path}")]
    NotFound {
        /// The path that does not exist.
        path: String,
    },
    /// The policy JSON could not be parsed.
    #[error("witness policy is unparseable: {0}")]
    Parse(String),
    /// The policy declared a schema version this verifier does not understand.
    #[error("unsupported witness policy version {found}; expected {expected}")]
    UnsupportedVersion {
        /// The version the file declared.
        found: u32,
        /// The version this verifier supports.
        expected: u32,
    },
    /// A witness entry carried an unpinned placeholder key.
    #[error("witness {name} has a placeholder pubkey; refusing to pin a placeholder")]
    PlaceholderKey {
        /// The offending witness name.
        name: String,
    },
    /// A witness entry had a missing/invalid attribute.
    #[error("witness {name} has an invalid attribute: {reason}")]
    InvalidEntry {
        /// The offending witness name.
        name: String,
        /// Why the entry was rejected.
        reason: String,
    },
    /// Filesystem error reading the policy.
    #[error("witness policy I/O at {path}: {source}")]
    Io {
        /// The path being read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Deserialize)]
struct WitnessPolicyDoc {
    version: u32,
    quorum: QuorumDoc,
    #[serde(default)]
    witnesses: Vec<WitnessEntryDoc>,
}

#[derive(Debug, Deserialize)]
struct QuorumDoc {
    #[serde(default)]
    min_witnesses: usize,
    #[serde(default)]
    min_organizations: usize,
    #[serde(default)]
    min_jurisdictions: usize,
    #[serde(default)]
    min_infra_zones: usize,
}

#[derive(Debug, Deserialize)]
struct WitnessEntryDoc {
    name: String,
    organization: String,
    jurisdiction: String,
    infrastructure: Option<String>,
    curve: Option<String>,
    pubkey_b64: String,
}

/// A validated witness entry: its operator-independence attributes and pinned key.
#[derive(Debug, Clone)]
pub struct WitnessPolicyEntry {
    /// Human-readable witness name (also used as the operator id).
    pub name: String,
    /// Operator-independence attributes (shared with the trust root).
    pub info: WitnessOperatorInfo,
    /// The pinned verkey, base64url (no pad).
    pub pubkey_b64: String,
    /// The verkey curve tag.
    pub curve: String,
}

/// A validated witness-diversity policy.
#[derive(Debug, Clone)]
pub struct WitnessPolicy {
    /// Minimum number of distinct witnesses required.
    pub min_witnesses: usize,
    /// Minimum org/jurisdiction/infra diversity an honest quorum must span.
    pub independence_policy: IndependencePolicy,
    /// The pinned, validated witness entries.
    pub entries: Vec<WitnessPolicyEntry>,
}

fn invalid(name: &str, reason: impl ToString) -> WitnessPolicyError {
    WitnessPolicyError::InvalidEntry {
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

/// The honest diversity ceiling for a witness-policy LOAD RESULT.
///
/// This is the single value every surface — the monitor's report, the compliance
/// evidence pack — renders, so none can over-claim third-party non-equivocation.
/// A missing, placeholder, or single-operator policy yields a `policy_met ==
/// false` ceiling labeled "single-operator — not yet independent"; only a roster
/// spanning the required organization/jurisdiction/infrastructure diversity
/// yields a met ceiling. Equivocation detection is reported as `Sampled` until
/// the gossip layer makes it non-repudiable.
///
/// This deliberately takes the fallible load result rather than a `WitnessPolicy`
/// so the "policy not established" case (the reality until an independent commons
/// is admitted) renders an honest single-operator verdict instead of being
/// unrepresentable.
///
/// Args:
/// * `result`: The outcome of [`WitnessPolicy::load`] / [`WitnessPolicy::from_json`].
///
/// Usage:
/// ```ignore
/// let ceiling = ceiling_for_policy_load(&WitnessPolicy::load(path));
/// if !ceiling.policy_met { /* render single-operator posture; never claim independence */ }
/// ```
pub fn ceiling_for_policy_load(
    result: &Result<WitnessPolicy, WitnessPolicyError>,
) -> HonestyCeiling {
    let independence = match result {
        Ok(policy) => policy.roster_independence(),
        Err(e) => Independence::cannot_prove(format!("witness policy not established: {e}")),
    };
    honesty_ceiling(&independence, EquivocationDetection::Sampled)
}

impl WitnessPolicy {
    /// Parse and validate a policy from JSON, failing closed.
    ///
    /// Args:
    /// * `json`: The policy document.
    ///
    /// Usage:
    /// ```ignore
    /// let policy = WitnessPolicy::from_json(include_str!("../data/witness_policy.json"))?;
    /// ```
    pub fn from_json(json: &str) -> Result<Self, WitnessPolicyError> {
        let doc: WitnessPolicyDoc =
            serde_json::from_str(json).map_err(|e| WitnessPolicyError::Parse(e.to_string()))?;
        if doc.version != SUPPORTED_VERSION {
            return Err(WitnessPolicyError::UnsupportedVersion {
                found: doc.version,
                expected: SUPPORTED_VERSION,
            });
        }

        let independence_policy = IndependencePolicy {
            min_organizations: doc.quorum.min_organizations,
            min_jurisdictions: doc.quorum.min_jurisdictions,
            min_infra_zones: doc.quorum.min_infra_zones,
        };

        let mut entries = Vec::with_capacity(doc.witnesses.len());
        for w in doc.witnesses {
            if w.pubkey_b64.contains(PLACEHOLDER_MARKER) || w.pubkey_b64.trim().is_empty() {
                return Err(WitnessPolicyError::PlaceholderKey { name: w.name });
            }
            let infrastructure = w
                .infrastructure
                .ok_or_else(|| invalid(&w.name, "missing infrastructure (ASN/cloud+region)"))?;
            let info = WitnessOperatorInfo {
                operator: OperatorId::new(w.name.clone()).map_err(|e| invalid(&w.name, e))?,
                organization: Organization::new(w.organization).map_err(|e| invalid(&w.name, e))?,
                jurisdiction: Jurisdiction::new(w.jurisdiction).map_err(|e| invalid(&w.name, e))?,
                infrastructure: Infrastructure::new(infrastructure)
                    .map_err(|e| invalid(&w.name, e))?,
            };
            entries.push(WitnessPolicyEntry {
                name: w.name,
                info,
                pubkey_b64: w.pubkey_b64,
                curve: w.curve.unwrap_or_else(|| "ed25519".to_string()),
            });
        }

        Ok(Self {
            min_witnesses: doc.quorum.min_witnesses,
            independence_policy,
            entries,
        })
    }

    /// Load and validate a policy from a file path, failing closed.
    ///
    /// Args:
    /// * `path`: Path to the policy JSON.
    ///
    /// Usage:
    /// ```ignore
    /// let policy = WitnessPolicy::load(Path::new("data/witness_policy.json"))?;
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: &Path) -> Result<Self, WitnessPolicyError> {
        let p = path.display().to_string();
        if !path.exists() {
            return Err(WitnessPolicyError::NotFound { path: p });
        }
        let json = std::fs::read_to_string(path)
            .map_err(|e| WitnessPolicyError::Io { path: p, source: e })?;
        Self::from_json(&json)
    }

    /// Whether the policy's own roster *could* form an independent quorum.
    ///
    /// A startup capability check over the pinned entries — NOT the per-checkpoint
    /// gate (which evaluates the actual cosigners). A 1-operator bootstrap policy
    /// renders as not-independent here, with a typed shortfall.
    ///
    /// Usage:
    /// ```ignore
    /// if !policy.roster_independence().independent { /* loud-fail / refuse */ }
    /// ```
    pub fn roster_independence(&self) -> Independence {
        let attrs: Vec<OperatorAttributes> = self
            .entries
            .iter()
            .map(|e| e.info.to_attributes(e.pubkey_b64.clone()))
            .collect();
        spans_distinct(&attrs, &self.independence_policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_json(name: &str, org: &str, jur: &str, infra: &str, pubkey: &str) -> String {
        format!(
            r#"{{"name":"{name}","organization":"{org}","jurisdiction":"{jur}","infrastructure":"{infra}","curve":"ed25519","pubkey_b64":"{pubkey}"}}"#
        )
    }

    fn policy_json(min_org: usize, min_jur: usize, min_infra: usize, entries: &[String]) -> String {
        format!(
            r#"{{"version":1,"quorum":{{"min_witnesses":3,"min_organizations":{min_org},"min_jurisdictions":{min_jur},"min_infra_zones":{min_infra}}},"witnesses":[{}]}}"#,
            entries.join(",")
        )
    }

    #[test]
    fn three_diverse_witnesses_pass() {
        let json = policy_json(
            3,
            2,
            2,
            &[
                entry_json("w-a", "org-a", "US", "aws/us-east-1", "AAAA"),
                entry_json("w-b", "org-b", "DE", "gcp/eu-west-1", "BBBB"),
                entry_json("w-c", "org-c", "JP", "azure/jp-east", "CCCC"),
            ],
        );
        let policy = WitnessPolicy::from_json(&json).unwrap();
        assert!(policy.roster_independence().independent);
    }

    #[test]
    fn one_org_fails_independence() {
        let json = policy_json(
            3,
            2,
            2,
            &[
                entry_json("w-a", "acme", "US", "aws/us-east-1", "AAAA"),
                entry_json("w-b", "acme", "DE", "gcp/eu-west-1", "BBBB"),
                entry_json("w-c", "acme", "JP", "azure/jp-east", "CCCC"),
            ],
        );
        let policy = WitnessPolicy::from_json(&json).unwrap();
        assert!(!policy.roster_independence().independent);
    }

    #[test]
    fn placeholder_key_fails_closed() {
        let json = policy_json(
            3,
            2,
            2,
            &[entry_json(
                "w-a",
                "org-a",
                "US",
                "aws/us-east-1",
                "REPLACE_WITH_PINNED_KEY",
            )],
        );
        assert!(matches!(
            WitnessPolicy::from_json(&json),
            Err(WitnessPolicyError::PlaceholderKey { .. })
        ));
    }

    #[test]
    fn unknown_version_fails_closed() {
        let json = r#"{"version":99,"quorum":{"min_organizations":3},"witnesses":[]}"#;
        assert!(matches!(
            WitnessPolicy::from_json(json),
            Err(WitnessPolicyError::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn unparseable_fails_closed() {
        assert!(matches!(
            WitnessPolicy::from_json("{ not json"),
            Err(WitnessPolicyError::Parse(_))
        ));
    }

    #[test]
    fn missing_infrastructure_is_rejected() {
        let json = r#"{"version":1,"quorum":{"min_organizations":3},"witnesses":[{"name":"w","organization":"o","jurisdiction":"US","curve":"ed25519","pubkey_b64":"AAAA"}]}"#;
        assert!(matches!(
            WitnessPolicy::from_json(json),
            Err(WitnessPolicyError::InvalidEntry { .. })
        ));
    }

    #[test]
    fn shipped_default_policy_fails_closed() {
        // The shipped bootstrap policy has a placeholder key and a single
        // operator — it MUST loud-fail rather than pass with a fake quorum.
        let shipped = include_str!("../data/witness_policy.json");
        let result = WitnessPolicy::from_json(shipped);
        assert!(
            result.is_err(),
            "shipped default policy must fail closed, got: {result:?}"
        );
    }

    #[test]
    fn ceiling_for_missing_policy_is_single_operator() {
        let result = Err(WitnessPolicyError::NotFound {
            path: "/nope".into(),
        });
        let ceiling = ceiling_for_policy_load(&result);
        assert!(!ceiling.policy_met);
        assert!(
            ceiling.label.contains("not yet independent"),
            "missing policy must not claim independence: {}",
            ceiling.label
        );
    }

    #[test]
    fn ceiling_for_shipped_placeholder_is_not_independent() {
        // Honesty surface: with the placeholder policy, the verdict must NOT
        // assert an independent commons.
        let result = WitnessPolicy::from_json(include_str!("../data/witness_policy.json"));
        let ceiling = ceiling_for_policy_load(&result);
        assert!(!ceiling.policy_met);
        assert!(ceiling.label.contains("not yet independent"));
    }

    #[test]
    fn ceiling_for_diverse_roster_is_met() {
        let json = policy_json(
            3,
            2,
            2,
            &[
                entry_json("w-a", "org-a", "US", "aws/us-east-1", "AAAA"),
                entry_json("w-b", "org-b", "DE", "gcp/eu-west-1", "BBBB"),
                entry_json("w-c", "org-c", "JP", "azure/jp-east", "CCCC"),
            ],
        );
        let ceiling = ceiling_for_policy_load(&WitnessPolicy::from_json(&json));
        assert!(ceiling.policy_met);
        assert!(ceiling.label.contains("independent"));
    }

    // --- Governance admission schema (W.4.2) ---
    //
    // The governance admission contract is a DIFFERENT artifact from the runtime
    // policy above; this test guards the schema/instance, not the runtime path.

    #[test]
    fn admission_policy_instance_matches_schema() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/governance/admission-policy.schema.json"
        ))
        .unwrap();
        let instance: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/governance/admission_policy.json"
        ))
        .unwrap();

        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        assert!(
            validator.is_valid(&instance),
            "shipped admission_policy.json must validate against the schema"
        );
    }

    #[test]
    fn admission_schema_rejects_invalid_instances() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/governance/admission-policy.schema.json"
        ))
        .unwrap();
        let instance: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/governance/admission_policy.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");

        // Operator missing the infrastructure axis → rejected.
        let mut missing_infra = instance.clone();
        missing_infra["operators"][0]
            .as_object_mut()
            .unwrap()
            .remove("infrastructure");
        assert!(
            !validator.is_valid(&missing_infra),
            "operator without an infrastructure axis must be rejected"
        );

        // Status outside the lifecycle enum → rejected.
        let mut bad_status = instance.clone();
        bad_status["operators"][0]["status"] = serde_json::json!("active");
        assert!(
            !validator.is_valid(&bad_status),
            "unknown lifecycle status must be rejected"
        );
    }
}
