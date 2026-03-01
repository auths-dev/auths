//! Compiled policy expression — validated, canonical, ready to evaluate.
//!
//! This is what `evaluate` actually runs against. Every string has been validated
//! and canonicalized. Constructed only via [`compile`](crate::compile::compile).

use crate::types::{CanonicalCapability, CanonicalDid, ValidatedGlob};

/// Compiled policy expression — validated, canonical, ready to evaluate.
///
/// Constructed only via [`compile`](crate::compile::compile). Cannot be built directly.
/// All string fields have been parsed into canonical typed forms.
#[derive(Debug, Clone, PartialEq)]
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
