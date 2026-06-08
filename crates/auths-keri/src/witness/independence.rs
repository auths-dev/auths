//! Typed operator-independence model for witness quorums.
//!
//! A quorum is only meaningful as a non-equivocation / censorship-resistance
//! guarantee if its members are genuinely independent. This module models the
//! three independence axes as fail-closed newtypes and provides ONE pure
//! predicate, [`spans_distinct`], that both the static roster-capability check and
//! the security-decisive per-attestation check reuse:
//!
//! 1. **Organization** — two witnesses run by the same org are not independent.
//! 2. **Jurisdiction** — all-in-one-jurisdiction is a single legal chokepoint.
//! 3. **Infrastructure** — three orgs all in one cloud region/ASN share a
//!    correlated-failure and single-censorship point; infra is first-class, as in
//!    Chrome CT / transparency.dev operator policies.
//!
//! Missing attributes mean "cannot prove independence" → fail closed, never
//! "assume distinct". A pubkey appearing under two operator labels is a Sybil and
//! counts once.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Failure constructing an independence newtype from untrusted input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndependenceError {
    /// A required attribute was empty/whitespace.
    #[error("{field} must not be empty")]
    Empty {
        /// Which attribute was empty.
        field: &'static str,
    },
}

macro_rules! validated_string_newtype {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Construct, rejecting empty/whitespace input (fail-closed).
            ///
            /// Args:
            /// * `value`: The attribute string.
            ///
            /// Usage:
            /// ```ignore
            #[doc = concat!("let v = ", stringify!($name), "::new(\"x\")?;")]
            /// ```
            pub fn new(value: impl Into<String>) -> Result<Self, IndependenceError> {
                let v = value.into();
                if v.trim().is_empty() {
                    return Err(IndependenceError::Empty { field: $field });
                }
                Ok(Self(v))
            }

            /// Borrow the inner string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IndependenceError;
            fn try_from(v: String) -> Result<Self, Self::Error> {
                Self::new(v)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
    };
}

validated_string_newtype!(
    OperatorId,
    "operator",
    "Stable identifier for a witness operator instance (the entity running it)."
);
validated_string_newtype!(
    Organization,
    "organization",
    "The organization/affiliation a witness operator belongs to. Two operators \
     sharing an organization are NOT independent."
);
validated_string_newtype!(
    Jurisdiction,
    "jurisdiction",
    "Legal/governance jurisdiction (e.g. an ISO 3166 country code or region tag)."
);
validated_string_newtype!(
    Infrastructure,
    "infrastructure",
    "Network/infrastructure zone — ASN or cloud-provider+region. Three distinct \
     orgs all in one zone are a correlated-failure and single-censorship point."
);

/// The independence attributes pinned alongside a witness key.
///
/// The key itself lives on the witness ref / trust-root entry; combine the two
/// via [`WitnessOperatorInfo::to_attributes`]. Shared by the KERI `WitnessRef` and
/// the CT `TrustRootWitness` so both sides describe operators identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessOperatorInfo {
    /// The operator running this witness.
    pub operator: OperatorId,
    /// The operator's organization/affiliation.
    pub organization: Organization,
    /// The operator's legal/governance jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// The operator's network/infrastructure zone (ASN or cloud+region).
    pub infrastructure: Infrastructure,
}

impl WitnessOperatorInfo {
    /// Combine these attributes with a witness key into [`OperatorAttributes`].
    ///
    /// Args:
    /// * `key`: The witness's curve-tagged verkey/AID (the Sybil-collapse key).
    ///
    /// Usage:
    /// ```ignore
    /// let attrs = info.to_attributes(witness.aid.as_str());
    /// ```
    pub fn to_attributes(&self, key: impl Into<String>) -> OperatorAttributes {
        OperatorAttributes {
            operator: self.operator.clone(),
            organization: self.organization.clone(),
            jurisdiction: self.jurisdiction.clone(),
            infrastructure: self.infrastructure.clone(),
            key: key.into(),
        }
    }
}

/// The independence-relevant attributes of one attester in a quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAttributes {
    /// The operator running this witness.
    pub operator: OperatorId,
    /// The operator's organization/affiliation.
    pub organization: Organization,
    /// The operator's jurisdiction.
    pub jurisdiction: Jurisdiction,
    /// The operator's infrastructure zone.
    pub infrastructure: Infrastructure,
    /// The attester's curve-tagged verkey/AID. Collapses Sybil duplicates: the
    /// same key under two operator labels counts once.
    pub key: String,
}

/// Minimum-diversity thresholds an independent quorum must clear.
///
/// Mirrors the diversity thresholds in `witness_policy.json` /
/// `docs/security/witness-diversity.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependencePolicy {
    /// Minimum distinct organizations (default 3).
    #[serde(default = "default_min_organizations")]
    pub min_organizations: usize,
    /// Minimum distinct jurisdictions (default 2).
    #[serde(default = "default_min_jurisdictions")]
    pub min_jurisdictions: usize,
    /// Minimum distinct infrastructure zones (default 2).
    #[serde(default = "default_min_infra_zones")]
    pub min_infra_zones: usize,
}

fn default_min_organizations() -> usize {
    3
}
fn default_min_jurisdictions() -> usize {
    2
}
fn default_min_infra_zones() -> usize {
    2
}

impl Default for IndependencePolicy {
    fn default() -> Self {
        Self {
            min_organizations: default_min_organizations(),
            min_jurisdictions: default_min_jurisdictions(),
            min_infra_zones: default_min_infra_zones(),
        }
    }
}

impl IndependencePolicy {
    /// The "no diversity required" policy (all thresholds zero).
    ///
    /// Use where a consumer pins no policy and must keep legacy behavior — as
    /// opposed to [`IndependencePolicy::default`], the strict 3/2/2 commons policy.
    ///
    /// Usage:
    /// ```ignore
    /// let policy = IndependencePolicy::unconstrained();
    /// ```
    pub fn unconstrained() -> Self {
        Self {
            min_organizations: 0,
            min_jurisdictions: 0,
            min_infra_zones: 0,
        }
    }
}

/// The verdict from evaluating a set of attesters against an [`IndependencePolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Independence {
    /// Whether the attesters clear every threshold.
    pub independent: bool,
    /// Distinct operators after Sybil collapse.
    pub distinct_operators: usize,
    /// Distinct organizations after Sybil collapse.
    pub distinct_organizations: usize,
    /// Distinct jurisdictions after Sybil collapse.
    pub distinct_jurisdictions: usize,
    /// Distinct infrastructure zones after Sybil collapse.
    pub distinct_infra_zones: usize,
    /// Human-readable shortfalls (empty iff independent) — for status surfaces.
    pub shortfalls: Vec<String>,
}

impl Independence {
    /// A fail-closed verdict for when independence cannot even be evaluated
    /// (e.g. an attester is missing required attributes).
    ///
    /// Args:
    /// * `reason`: Why independence could not be proven.
    ///
    /// Usage:
    /// ```ignore
    /// return Independence::cannot_prove("a witness is missing its jurisdiction");
    /// ```
    pub fn cannot_prove(reason: impl Into<String>) -> Self {
        Self {
            independent: false,
            distinct_operators: 0,
            distinct_organizations: 0,
            distinct_jurisdictions: 0,
            distinct_infra_zones: 0,
            shortfalls: vec![reason.into()],
        }
    }
}

/// Evaluate whether a set of attesters spans distinct operators across enough
/// organizations, jurisdictions, and infrastructure zones to be independent.
///
/// Sybil collapse runs first: attesters sharing a `key` count once, so relabeling
/// one key under several operators cannot inflate diversity.
///
/// Args:
/// * `attesters`: The attesters to evaluate — for the security-decisive check,
///   the ACTUAL cosigning quorum (the receipts/cosignatures present), not the
///   configured roster.
/// * `policy`: The minimum-diversity thresholds.
///
/// Usage:
/// ```ignore
/// let verdict = spans_distinct(&cosigners, &IndependencePolicy::default());
/// if !verdict.independent { /* a single-operator quorum is visibly not independence */ }
/// ```
pub fn spans_distinct(
    attesters: &[OperatorAttributes],
    policy: &IndependencePolicy,
) -> Independence {
    // Sybil collapse: the same key counts once, regardless of operator label.
    let mut seen_keys = HashSet::new();
    let unique: Vec<&OperatorAttributes> = attesters
        .iter()
        .filter(|a| seen_keys.insert(a.key.as_str()))
        .collect();

    let operators: HashSet<&str> = unique.iter().map(|a| a.operator.as_str()).collect();
    let organizations: HashSet<&str> = unique.iter().map(|a| a.organization.as_str()).collect();
    let jurisdictions: HashSet<&str> = unique.iter().map(|a| a.jurisdiction.as_str()).collect();
    let infra_zones: HashSet<&str> = unique.iter().map(|a| a.infrastructure.as_str()).collect();

    let mut shortfalls = Vec::new();
    if organizations.len() < policy.min_organizations {
        shortfalls.push(format!(
            "organizations: {} < required {}",
            organizations.len(),
            policy.min_organizations
        ));
    }
    if jurisdictions.len() < policy.min_jurisdictions {
        shortfalls.push(format!(
            "jurisdictions: {} < required {}",
            jurisdictions.len(),
            policy.min_jurisdictions
        ));
    }
    if infra_zones.len() < policy.min_infra_zones {
        shortfalls.push(format!(
            "infrastructure zones: {} < required {}",
            infra_zones.len(),
            policy.min_infra_zones
        ));
    }

    Independence {
        independent: shortfalls.is_empty(),
        distinct_operators: operators.len(),
        distinct_organizations: organizations.len(),
        distinct_jurisdictions: jurisdictions.len(),
        distinct_infra_zones: infra_zones.len(),
        shortfalls,
    }
}

/// Whether cross-operator equivocation detection is merely sampled or
/// non-repudiable. Until the gossip layer (W.3) lands, detection is `Sampled` —
/// a surface must say so rather than imply a guarantee it cannot make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationDetection {
    /// Best-effort monitoring; a hidden split-view may go undetected.
    Sampled,
    /// Cross-operator detection with non-repudiable evidence is live.
    NonRepudiable,
}

/// The honest current truth about a witness set, rendered identically by every
/// surface — CLI `witness` status, verify output, and the cross-repo badge (via
/// the serialized form). Computing it in ONE place means no surface can forget
/// the ceiling or re-derive met/failing differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HonestyCeiling {
    /// Distinct operators (after Sybil collapse).
    pub distinct_operators: usize,
    /// Distinct organizations.
    pub distinct_organizations: usize,
    /// Distinct jurisdictions.
    pub distinct_jurisdictions: usize,
    /// Distinct infrastructure zones.
    pub distinct_infra_zones: usize,
    /// Whether the diversity policy is met.
    pub policy_met: bool,
    /// Whether equivocation detection is sampled or non-repudiable.
    pub equivocation: EquivocationDetection,
    /// Why the policy is unmet (empty iff `policy_met`).
    pub shortfalls: Vec<String>,
    /// One-line human-readable ceiling label — the canonical honest summary.
    pub label: String,
}

/// Compute the [`HonestyCeiling`] from an [`Independence`] verdict and the current
/// equivocation-detection capability.
///
/// This is the single source of truth for honest witness-status text: every
/// surface renders the returned value rather than re-deriving met/failing.
///
/// Args:
/// * `independence`: The verdict from [`spans_distinct`] over the relevant set.
/// * `equivocation`: Whether split-view detection is sampled or non-repudiable.
///
/// Usage:
/// ```ignore
/// let ceiling = honesty_ceiling(&spans_distinct(&attrs, &policy), EquivocationDetection::Sampled);
/// println!("{}", ceiling.label);
/// ```
pub fn honesty_ceiling(
    independence: &Independence,
    equivocation: EquivocationDetection,
) -> HonestyCeiling {
    let equivocation_phrase = match equivocation {
        EquivocationDetection::Sampled => "equivocation sampled, not yet non-repudiable",
        EquivocationDetection::NonRepudiable => "equivocation detection non-repudiable",
    };

    let label = if independence.independent {
        format!(
            "witnessed by {} operators across {} orgs / {} jurisdictions / {} infra zones (independent; {})",
            independence.distinct_operators,
            independence.distinct_organizations,
            independence.distinct_jurisdictions,
            independence.distinct_infra_zones,
            equivocation_phrase,
        )
    } else {
        let posture = if independence.distinct_operators <= 1 {
            "single-operator — not yet independent"
        } else {
            "not yet independent"
        };
        format!(
            "witnessed by {} operators ({}: {}); {}",
            independence.distinct_operators,
            posture,
            independence.shortfalls.join(", "),
            equivocation_phrase,
        )
    };

    HonestyCeiling {
        distinct_operators: independence.distinct_operators,
        distinct_organizations: independence.distinct_organizations,
        distinct_jurisdictions: independence.distinct_jurisdictions,
        distinct_infra_zones: independence.distinct_infra_zones,
        policy_met: independence.independent,
        equivocation,
        shortfalls: independence.shortfalls.clone(),
        label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attester(
        operator: &str,
        org: &str,
        jur: &str,
        infra: &str,
        key: &str,
    ) -> OperatorAttributes {
        OperatorAttributes {
            operator: OperatorId::new(operator).unwrap(),
            organization: Organization::new(org).unwrap(),
            jurisdiction: Jurisdiction::new(jur).unwrap(),
            infrastructure: Infrastructure::new(infra).unwrap(),
            key: key.to_string(),
        }
    }

    fn diverse_three() -> Vec<OperatorAttributes> {
        vec![
            attester("op-a", "org-a", "US", "aws/us-east-1", "K_AAA"),
            attester("op-b", "org-b", "DE", "gcp/eu-west-1", "K_BBB"),
            attester("op-c", "org-c", "JP", "azure/jp-east", "K_CCC"),
        ]
    }

    #[test]
    fn three_distinct_orgs_jurisdictions_infra_is_independent() {
        let verdict = spans_distinct(&diverse_three(), &IndependencePolicy::default());
        assert!(verdict.independent, "shortfalls: {:?}", verdict.shortfalls);
        assert_eq!(verdict.distinct_organizations, 3);
        assert_eq!(verdict.distinct_jurisdictions, 3);
        assert_eq!(verdict.distinct_infra_zones, 3);
    }

    #[test]
    fn three_same_organization_is_not_independent() {
        let attesters = vec![
            attester("op-a", "acme", "US", "aws/us-east-1", "K_AAA"),
            attester("op-b", "acme", "DE", "gcp/eu-west-1", "K_BBB"),
            attester("op-c", "acme", "JP", "azure/jp-east", "K_CCC"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        assert!(!verdict.independent);
        assert_eq!(verdict.distinct_organizations, 1);
    }

    #[test]
    fn three_orgs_one_jurisdiction_fails() {
        let attesters = vec![
            attester("op-a", "org-a", "US", "aws/us-east-1", "K_AAA"),
            attester("op-b", "org-b", "US", "gcp/us-west-1", "K_BBB"),
            attester("op-c", "org-c", "US", "azure/us-central", "K_CCC"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        assert!(!verdict.independent);
        assert_eq!(verdict.distinct_jurisdictions, 1);
    }

    #[test]
    fn three_orgs_two_jurisdictions_one_infra_fails() {
        let attesters = vec![
            attester("op-a", "org-a", "US", "aws/us-east-1", "K_AAA"),
            attester("op-b", "org-b", "DE", "aws/us-east-1", "K_BBB"),
            attester("op-c", "org-c", "JP", "aws/us-east-1", "K_CCC"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        assert!(!verdict.independent);
        assert_eq!(verdict.distinct_infra_zones, 1);
    }

    #[test]
    fn single_operator_quorum_fails_closed() {
        let attesters = vec![
            attester("solo", "solo-org", "US", "aws/us-east-1", "K_AAA"),
            attester("solo", "solo-org", "US", "aws/us-east-1", "K_BBB"),
            attester("solo", "solo-org", "US", "aws/us-east-1", "K_CCC"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        assert!(!verdict.independent);
        assert_eq!(verdict.distinct_operators, 1);
    }

    #[test]
    fn honesty_ceiling_independent_is_met_and_sampled() {
        let verdict = spans_distinct(&diverse_three(), &IndependencePolicy::default());
        let ceiling = honesty_ceiling(&verdict, EquivocationDetection::Sampled);
        assert!(ceiling.policy_met);
        assert!(ceiling.label.contains("independent"));
        assert!(ceiling.label.contains("sampled"));
    }

    #[test]
    fn honesty_ceiling_single_operator_is_failing() {
        let attesters = vec![
            attester("solo", "solo-org", "US", "aws/us-east-1", "K_A"),
            attester("solo", "solo-org", "US", "aws/us-east-1", "K_B"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        let ceiling = honesty_ceiling(&verdict, EquivocationDetection::Sampled);
        assert!(!ceiling.policy_met);
        assert!(ceiling.label.contains("single-operator"));
        assert!(ceiling.label.contains("not yet independent"));
    }

    #[test]
    fn honesty_ceiling_round_trips() {
        let verdict = spans_distinct(&diverse_three(), &IndependencePolicy::default());
        let ceiling = honesty_ceiling(&verdict, EquivocationDetection::NonRepudiable);
        let json = serde_json::to_string(&ceiling).unwrap();
        let back: HonestyCeiling = serde_json::from_str(&json).unwrap();
        assert_eq!(ceiling, back);
    }

    #[test]
    fn honesty_ceiling_label_changes_with_config() {
        let diverse = honesty_ceiling(
            &spans_distinct(&diverse_three(), &IndependencePolicy::default()),
            EquivocationDetection::Sampled,
        );
        let same_org = vec![
            attester("op-a", "acme", "US", "aws/us-east-1", "K_A"),
            attester("op-b", "acme", "DE", "gcp/eu-west-1", "K_B"),
            attester("op-c", "acme", "JP", "azure/jp-east", "K_C"),
        ];
        let failing = honesty_ceiling(
            &spans_distinct(&same_org, &IndependencePolicy::default()),
            EquivocationDetection::Sampled,
        );
        assert_ne!(diverse.label, failing.label);
        assert!(diverse.policy_met && !failing.policy_met);
    }

    #[test]
    fn quorum_not_roster_two_same_org_cosigners_fail() {
        // The roster spans 3 orgs, but the ACTUAL cosigning quorum is two
        // attesters from the same org → not independent.
        let actual_cosigners = vec![
            attester("op-a", "org-a", "US", "aws/us-east-1", "K_AAA"),
            attester("op-a2", "org-a", "DE", "gcp/eu-west-1", "K_AAA2"),
        ];
        let verdict = spans_distinct(&actual_cosigners, &IndependencePolicy::default());
        assert!(!verdict.independent);
        assert_eq!(verdict.distinct_organizations, 1);
    }

    #[test]
    fn duplicate_key_under_two_labels_counts_once() {
        // Same key relabeled as two operators/orgs must not inflate diversity.
        let attesters = vec![
            attester("op-a", "org-a", "US", "aws/us-east-1", "K_SHARED"),
            attester("op-b", "org-b", "DE", "gcp/eu-west-1", "K_SHARED"),
            attester("op-c", "org-c", "JP", "azure/jp-east", "K_CCC"),
        ];
        let verdict = spans_distinct(&attesters, &IndependencePolicy::default());
        // K_SHARED collapses to one → only 2 distinct orgs, not 3.
        assert_eq!(verdict.distinct_organizations, 2);
        assert!(!verdict.independent);
    }

    #[test]
    fn cannot_prove_is_fail_closed() {
        let verdict = Independence::cannot_prove("missing jurisdiction");
        assert!(!verdict.independent);
        assert_eq!(verdict.shortfalls.len(), 1);
    }

    #[test]
    fn newtypes_reject_empty_input() {
        assert_eq!(
            OperatorId::new("  "),
            Err(IndependenceError::Empty { field: "operator" })
        );
        assert!(Organization::new("").is_err());
    }

    #[test]
    fn newtype_deserialize_is_fail_closed() {
        // Empty string must be rejected at deserialize, not silently accepted.
        assert!(serde_json::from_str::<Organization>("\"\"").is_err());
        let ok: Organization = serde_json::from_str("\"acme\"").unwrap();
        assert_eq!(ok.as_str(), "acme");
    }
}
