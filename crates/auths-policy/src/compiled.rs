//! Compiled policy expression — validated, canonical, ready to evaluate.
//!
//! This is what `evaluate` actually runs against. Every string has been validated
//! and canonicalized. Constructed only via [`compile`](crate::compile::compile).

use serde::{Deserialize, Serialize};

use crate::types::{AssuranceLevel, CanonicalCapability, CanonicalDid, ValidatedGlob};

/// Compiled policy expression — validated, canonical, ready to evaluate.
///
/// Constructed only via [`compile`](crate::compile::compile). Cannot be built directly.
/// All string fields have been parsed into canonical typed forms.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CompiledExpr {
    /// Always allow.
    True,
    /// Always deny.
    False,
    /// All children must evaluate to Allow.
    And(Vec<CompiledExpr>),
    /// At least one child must evaluate to Allow.
    Or(Vec<CompiledExpr>),
    /// Invert the child's outcome.
    Not(Box<CompiledExpr>),

    /// Subject must have this capability.
    HasCapability(CanonicalCapability),
    /// Subject must have all listed capabilities.
    HasAllCapabilities(Vec<CanonicalCapability>),
    /// Subject must have at least one of the listed capabilities.
    HasAnyCapability(Vec<CanonicalCapability>),

    /// Issuer DID must match exactly.
    IssuerIs(CanonicalDid),
    /// Issuer DID must be in the set.
    IssuerIn(Vec<CanonicalDid>),
    /// Subject DID must match exactly.
    SubjectIs(CanonicalDid),
    /// Attestation must be delegated by this DID.
    DelegatedBy(CanonicalDid),

    /// Attestation must not be revoked.
    NotRevoked,
    /// Attestation must not be expired.
    NotExpired,
    /// Attestation must have at least this many seconds remaining.
    ExpiresAfter(i64),
    /// Attestation must have been issued within this many seconds.
    IssuedWithin(i64),

    /// Subject's role must match exactly.
    RoleIs(String),
    /// Subject's role must be in the set.
    RoleIn(Vec<String>),

    /// Repository must match exactly.
    RepoIs(String),
    /// Repository must be in the set.
    RepoIn(Vec<String>),
    /// Git ref must match the glob pattern.
    RefMatches(ValidatedGlob),
    /// All paths must match at least one of the glob patterns.
    PathAllowed(Vec<ValidatedGlob>),
    /// Environment must match exactly.
    EnvIs(String),
    /// Environment must be in the set.
    EnvIn(Vec<String>),

    /// Workload issuer DID must match exactly.
    WorkloadIssuerIs(CanonicalDid),
    /// Workload claim must equal the expected value.
    WorkloadClaimEquals {
        /// Claim key.
        key: String,
        /// Expected value.
        value: String,
    },

    /// Signer must be an AI agent.
    IsAgent,
    /// Signer must be a human.
    IsHuman,
    /// Signer must be a workload (CI/CD).
    IsWorkload,

    /// Delegation chain depth must not exceed this value.
    MaxChainDepth(u32),

    /// Match a flat string attribute.
    AttrEquals {
        /// Attribute key.
        key: String,
        /// Expected value.
        value: String,
    },
    /// Attribute must be one of the values.
    AttrIn {
        /// Attribute key.
        key: String,
        /// Allowed values.
        values: Vec<String>,
    },

    /// Assurance level must be at least this level (uses `Ord` comparison).
    MinAssurance(AssuranceLevel),
    /// Assurance level must match exactly.
    AssuranceLevelIs(AssuranceLevel),

    /// Approval gate: if inner evaluates to Allow, return RequiresApproval.
    ApprovalGate {
        /// The compiled inner expression.
        inner: Box<CompiledExpr>,
        /// Validated DIDs of allowed approvers.
        approvers: Vec<CanonicalDid>,
        /// Approval request TTL in seconds.
        ttl_seconds: u64,
        /// Approval scope controlling hash binding.
        scope: ApprovalScope,
    },
}

/// Controls which EvalContext fields are included in the approval request hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Hash: issuer + subject + capabilities (approve the agent for the action).
    #[default]
    Identity,
    /// Hash: issuer + subject + capabilities + repo + environment.
    Scoped,
    /// Hash: all context fields (approve the exact request).
    Full,
}

/// A compiled policy — validated, immutable, ready for repeated evaluation.
///
/// Stores the compiled expression plus metadata for audit/pinning.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    expr: CompiledExpr,
    source_hash: [u8; 32],
}

impl CompiledPolicy {
    /// Create a new compiled policy (internal use only).
    ///
    /// This is `pub(crate)` to ensure policies can only be created via `compile()`.
    pub(crate) fn new(expr: CompiledExpr, source_hash: [u8; 32]) -> Self {
        Self { expr, source_hash }
    }

    /// Returns the compiled expression.
    pub fn expr(&self) -> &CompiledExpr {
        &self.expr
    }

    /// Blake3 hash of the original `Expr` JSON used to compile this policy.
    /// Included in decision evidence for audit pinning.
    pub fn source_hash(&self) -> &[u8; 32] {
        &self.source_hash
    }

    /// Return a human-readable summary of the policy's requirements.
    pub fn describe(&self) -> String {
        describe_expr(&self.expr, 0)
    }
}

fn describe_expr(expr: &CompiledExpr, depth: usize) -> String {
    let indent = "  ".repeat(depth);
    match expr {
        CompiledExpr::True => format!("{indent}always allow"),
        CompiledExpr::False => format!("{indent}always deny"),
        CompiledExpr::And(children) => {
            let parts: Vec<String> = children
                .iter()
                .map(|c| describe_expr(c, depth + 1))
                .collect();
            format!("{indent}ALL of:\n{}", parts.join("\n"))
        }
        CompiledExpr::Or(children) => {
            let parts: Vec<String> = children
                .iter()
                .map(|c| describe_expr(c, depth + 1))
                .collect();
            format!("{indent}ANY of:\n{}", parts.join("\n"))
        }
        CompiledExpr::Not(inner) => format!("{indent}NOT:\n{}", describe_expr(inner, depth + 1)),
        CompiledExpr::HasCapability(c) => format!("{indent}require capability: {c}"),
        CompiledExpr::HasAllCapabilities(caps) => {
            let names: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
            format!("{indent}require all capabilities: [{}]", names.join(", "))
        }
        CompiledExpr::HasAnyCapability(caps) => {
            let names: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
            format!("{indent}require any capability: [{}]", names.join(", "))
        }
        CompiledExpr::IssuerIs(d) => format!("{indent}issuer must be: {d}"),
        CompiledExpr::IssuerIn(ds) => {
            let names: Vec<String> = ds.iter().map(|d| d.to_string()).collect();
            format!("{indent}issuer in: [{}]", names.join(", "))
        }
        CompiledExpr::SubjectIs(d) => format!("{indent}subject must be: {d}"),
        CompiledExpr::DelegatedBy(d) => format!("{indent}delegated by: {d}"),
        CompiledExpr::NotRevoked => format!("{indent}not revoked"),
        CompiledExpr::NotExpired => format!("{indent}not expired"),
        CompiledExpr::ExpiresAfter(s) => format!("{indent}expires after {s}s"),
        CompiledExpr::IssuedWithin(s) => format!("{indent}issued within {s}s"),
        CompiledExpr::RoleIs(r) => format!("{indent}role must be: {r}"),
        CompiledExpr::RoleIn(rs) => format!("{indent}role in: [{}]", rs.join(", ")),
        CompiledExpr::RepoIs(r) => format!("{indent}repo must be: {r}"),
        CompiledExpr::RepoIn(rs) => format!("{indent}repo in: [{}]", rs.join(", ")),
        CompiledExpr::RefMatches(g) => format!("{indent}ref matches: {g}"),
        CompiledExpr::PathAllowed(gs) => {
            let names: Vec<String> = gs.iter().map(|g| g.to_string()).collect();
            format!("{indent}paths allowed: [{}]", names.join(", "))
        }
        CompiledExpr::EnvIs(e) => format!("{indent}env must be: {e}"),
        CompiledExpr::EnvIn(es) => format!("{indent}env in: [{}]", es.join(", ")),
        CompiledExpr::WorkloadIssuerIs(d) => format!("{indent}workload issuer: {d}"),
        CompiledExpr::WorkloadClaimEquals { key, value } => {
            format!("{indent}workload claim {key} = {value}")
        }
        CompiledExpr::IsAgent => format!("{indent}signer is agent"),
        CompiledExpr::IsHuman => format!("{indent}signer is human"),
        CompiledExpr::IsWorkload => format!("{indent}signer is workload"),
        CompiledExpr::MaxChainDepth(d) => format!("{indent}max chain depth: {d}"),
        CompiledExpr::AttrEquals { key, value } => format!("{indent}attr {key} = {value}"),
        CompiledExpr::AttrIn { key, values } => {
            format!("{indent}attr {key} in: [{}]", values.join(", "))
        }
        CompiledExpr::MinAssurance(level) => {
            format!("{indent}min assurance: {}", level.label())
        }
        CompiledExpr::AssuranceLevelIs(level) => {
            format!("{indent}assurance must be: {}", level.label())
        }
        CompiledExpr::ApprovalGate {
            approvers,
            ttl_seconds,
            ..
        } => {
            let names: Vec<String> = approvers.iter().map(|d| d.to_string()).collect();
            format!(
                "{indent}requires approval from [{}] (TTL: {ttl_seconds}s)",
                names.join(", ")
            )
        }
    }
}

impl PartialEq for CompiledPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.expr == other.expr && self.source_hash == other.source_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CanonicalCapability, CanonicalDid, ValidatedGlob};

    #[test]
    fn compiled_expr_true() {
        let expr = CompiledExpr::True;
        assert!(matches!(expr, CompiledExpr::True));
    }

    #[test]
    fn compiled_expr_and() {
        let expr = CompiledExpr::And(vec![CompiledExpr::True, CompiledExpr::False]);
        match expr {
            CompiledExpr::And(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compiled_expr_has_capability() {
        let cap = CanonicalCapability::parse("sign_commit").unwrap();
        let expr = CompiledExpr::HasCapability(cap.clone());
        match expr {
            CompiledExpr::HasCapability(c) => assert_eq!(c, cap),
            _ => panic!("expected HasCapability"),
        }
    }

    #[test]
    fn compiled_expr_issuer_is() {
        let did = CanonicalDid::parse("did:keri:EOrg123").unwrap();
        let expr = CompiledExpr::IssuerIs(did.clone());
        match expr {
            CompiledExpr::IssuerIs(d) => assert_eq!(d, did),
            _ => panic!("expected IssuerIs"),
        }
    }

    #[test]
    fn compiled_expr_ref_matches() {
        let glob = ValidatedGlob::parse("refs/heads/*").unwrap();
        let expr = CompiledExpr::RefMatches(glob.clone());
        match expr {
            CompiledExpr::RefMatches(g) => assert_eq!(g, glob),
            _ => panic!("expected RefMatches"),
        }
    }

    #[test]
    fn compiled_policy_accessors() {
        let expr = CompiledExpr::True;
        let hash = [42u8; 32];
        let policy = CompiledPolicy::new(expr.clone(), hash);

        assert_eq!(*policy.expr(), expr);
        assert_eq!(*policy.source_hash(), hash);
    }

    #[test]
    fn compiled_policy_equality() {
        let expr1 = CompiledExpr::True;
        let expr2 = CompiledExpr::True;
        let hash = [42u8; 32];

        let policy1 = CompiledPolicy::new(expr1, hash);
        let policy2 = CompiledPolicy::new(expr2, hash);

        assert_eq!(policy1, policy2);
    }

    #[test]
    fn compiled_policy_inequality_different_hash() {
        let expr = CompiledExpr::True;
        let hash1 = [42u8; 32];
        let hash2 = [43u8; 32];

        let policy1 = CompiledPolicy::new(expr.clone(), hash1);
        let policy2 = CompiledPolicy::new(expr, hash2);

        assert_ne!(policy1, policy2);
    }
}
