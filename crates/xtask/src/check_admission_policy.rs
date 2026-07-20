//! CI enforcement of the Witness Commons admission policy (W.4.3).
//!
//! Prose + schema without an enforcer is aspirational. This check validates the
//! ratified admission policy fail-closed: the instance must validate against
//! `admission-policy.schema.json`, every operator must carry the three
//! independence axes, an SLA must be declared, and no two operators may share a
//! legal entity (a witness that adds no organizational diversity is rejected).
//!
//! The validator (`validate_admission`) is pure and unit-tested independently of
//! CI; `run` is the CI entrypoint that loads the shipped files.

use std::path::Path;

use auths_keri::witness::independence::{
    Infrastructure, Jurisdiction, OperatorAttributes, OperatorId, Organization,
};
use serde::Deserialize;

/// A typed admission-policy violation (the CI failure reason).
#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The instance does not validate against the schema.
    SchemaInvalid,
    /// The instance JSON could not be parsed.
    Parse(String),
    /// An operator entry was structurally invalid.
    InvalidOperator { name: String, reason: String },
    /// No SLA was declared.
    MissingSla,
    /// A proposed operator shares a legal entity with an existing one and adds no
    /// organizational diversity.
    NoDiversityAdded { duplicate_org: String },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaInvalid => {
                write!(
                    f,
                    "admission policy does not validate against admission-policy.schema.json"
                )
            }
            Self::Parse(e) => write!(f, "admission policy is unparseable: {e}"),
            Self::InvalidOperator { name, reason } => {
                write!(f, "operator {name} is invalid: {reason}")
            }
            Self::MissingSla => write!(f, "admission policy declares no SLA"),
            Self::NoDiversityAdded { duplicate_org } => write!(
                f,
                "operator with legal entity {duplicate_org:?} adds no organizational diversity (already present)"
            ),
        }
    }
}

#[derive(Deserialize)]
struct AdmissionDoc {
    sla: Option<serde_json::Value>,
    #[serde(default)]
    operators: Vec<OperatorDoc>,
}

#[derive(Deserialize)]
struct OperatorDoc {
    name: String,
    legal_entity: String,
    jurisdiction: String,
    infrastructure: InfrastructureDoc,
}

#[derive(Deserialize)]
struct InfrastructureDoc {
    asn_or_cloud: String,
    region: String,
}

/// Validate an admission-policy instance against its schema and the independence
/// rules. Pure (no I/O); fail-closed with a typed reason.
///
/// Args:
/// * `schema_json`: The `admission-policy.schema.json` contents.
/// * `instance_json`: The proposed `admission_policy.json` contents.
///
/// Usage:
/// ```ignore
/// validate_admission(schema, instance)?;
/// ```
pub fn validate_admission(schema_json: &str, instance_json: &str) -> Result<(), AdmissionError> {
    let schema: serde_json::Value =
        serde_json::from_str(schema_json).map_err(|e| AdmissionError::Parse(e.to_string()))?;
    let instance: serde_json::Value =
        serde_json::from_str(instance_json).map_err(|e| AdmissionError::Parse(e.to_string()))?;

    let validator =
        jsonschema::validator_for(&schema).map_err(|_| AdmissionError::SchemaInvalid)?;
    if !validator.is_valid(&instance) {
        return Err(AdmissionError::SchemaInvalid);
    }

    let doc: AdmissionDoc =
        serde_json::from_value(instance).map_err(|e| AdmissionError::Parse(e.to_string()))?;

    if doc.sla.is_none() {
        return Err(AdmissionError::MissingSla);
    }

    // Build the W.2.1 attributes (validates each axis is non-empty), then enforce
    // distinct legal entities — a duplicate org adds no organizational diversity.
    let mut seen_orgs = std::collections::HashSet::new();
    for op in &doc.operators {
        let _attrs = operator_attributes(op)?;
        if !seen_orgs.insert(op.legal_entity.clone()) {
            return Err(AdmissionError::NoDiversityAdded {
                duplicate_org: op.legal_entity.clone(),
            });
        }
    }

    Ok(())
}

/// Build the independence attributes for one operator, validating each axis.
fn operator_attributes(op: &OperatorDoc) -> Result<OperatorAttributes, AdmissionError> {
    let invalid = |reason: String| AdmissionError::InvalidOperator {
        name: op.name.clone(),
        reason,
    };
    Ok(OperatorAttributes {
        operator: OperatorId::new(op.name.clone()).map_err(|e| invalid(e.to_string()))?,
        organization: Organization::new(op.legal_entity.clone())
            .map_err(|e| invalid(e.to_string()))?,
        jurisdiction: Jurisdiction::new(op.jurisdiction.clone())
            .map_err(|e| invalid(e.to_string()))?,
        infrastructure: Infrastructure::new(format!(
            "{}/{}",
            op.infrastructure.asn_or_cloud, op.infrastructure.region
        ))
        .map_err(|e| invalid(e.to_string()))?,
        key: op.name.clone(),
    })
}

/// CI entrypoint: validate the shipped admission policy, failing the build on any
/// violation.
///
/// Args:
/// * `workspace_root`: Repository root.
///
/// Usage:
/// ```ignore
/// check_admission_policy::run(workspace_root())?;
/// ```
pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let gov = workspace_root.join("docs/governance");
    let schema = std::fs::read_to_string(gov.join("admission-policy.schema.json"))?;
    let instance = std::fs::read_to_string(gov.join("admission_policy.json"))?;

    validate_admission(&schema, &instance)
        .map_err(|e| anyhow::anyhow!("admission policy check failed: {e}"))?;

    println!("admission policy OK: schema-valid, distinct legal entities, SLA declared");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = include_str!("../../../docs/governance/admission-policy.schema.json");
    const INSTANCE: &str = include_str!("../../../docs/governance/admission_policy.json");

    #[test]
    fn shipped_admission_policy_passes() {
        assert!(validate_admission(SCHEMA, INSTANCE).is_ok());
    }

    #[test]
    fn schema_invalid_entry_fails() {
        // Operator missing the required infrastructure axis.
        let bad = r#"{"version":1,"independence_requirements":{"min_organizations":3,"min_jurisdictions":2,"min_infrastructure_zones":2},"sla":{"min_availability":0.99,"window_days":90},"lifecycle_states":["usable"],"rotation":{"signed_rotation_notice_required":true,"retire_notice_days":30},"operators":[{"name":"w","legal_entity":"X","jurisdiction":"US","key_custody":{"method":"kms"},"status":"usable"}]}"#;
        assert_eq!(
            validate_admission(SCHEMA, bad),
            Err(AdmissionError::SchemaInvalid)
        );
    }

    #[test]
    fn duplicate_org_adds_no_diversity_and_fails() {
        // Two operators sharing a legal entity → no organizational diversity.
        let dup = r#"{"version":1,"independence_requirements":{"min_organizations":3,"min_jurisdictions":2,"min_infrastructure_zones":2},"sla":{"min_availability":0.99,"window_days":90},"lifecycle_states":["usable"],"rotation":{"signed_rotation_notice_required":true,"retire_notice_days":30},"operators":[{"name":"w1","legal_entity":"Acme","jurisdiction":"US","infrastructure":{"asn_or_cloud":"aws","region":"us-east-1"},"key_custody":{"method":"kms"},"status":"usable"},{"name":"w2","legal_entity":"Acme","jurisdiction":"DE","infrastructure":{"asn_or_cloud":"gcp","region":"eu-west-1"},"key_custody":{"method":"kms"},"status":"usable"}]}"#;
        assert_eq!(
            validate_admission(SCHEMA, dup),
            Err(AdmissionError::NoDiversityAdded {
                duplicate_org: "Acme".to_string()
            })
        );
    }

    #[test]
    fn distinct_orgs_pass() {
        let ok = r#"{"version":1,"independence_requirements":{"min_organizations":3,"min_jurisdictions":2,"min_infrastructure_zones":2},"sla":{"min_availability":0.99,"window_days":90},"lifecycle_states":["usable"],"rotation":{"signed_rotation_notice_required":true,"retire_notice_days":30},"operators":[{"name":"w1","legal_entity":"Acme","jurisdiction":"US","infrastructure":{"asn_or_cloud":"aws","region":"us-east-1"},"key_custody":{"method":"kms"},"status":"usable"},{"name":"w2","legal_entity":"Globex","jurisdiction":"DE","infrastructure":{"asn_or_cloud":"gcp","region":"eu-west-1"},"key_custody":{"method":"kms"},"status":"usable"}]}"#;
        assert!(validate_admission(SCHEMA, ok).is_ok());
    }
}
