//! Serializable policy expression AST.
//!
//! This is the **wire format**. All identifiers are strings.
//! Must be compiled to [`CompiledPolicy`](crate::compiled::CompiledPolicy) before evaluation.
//! Compilation validates and canonicalizes all string fields.
//!
//! # Intentional Limitations
//!
//! - No closures, no function pointers, no IO
//! - No `Value` type for open-ended JSON queries — scope predicates are first-class
//! - Recursion bounded at compile time via depth check

use serde::{Deserialize, Serialize};

/// Serializable policy expression.
///
/// This is the **wire format** stored in JSON/TOML files. All identifiers are strings.
/// Must be compiled to [`CompiledPolicy`](crate::compiled::CompiledPolicy) before evaluation.
/// Compilation validates and canonicalizes all string fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "args")]
#[non_exhaustive]
pub enum Expr {
    // ── Combinators ──────────────────────────────────────────────────
    /// Always allow.
    True,
    /// Always deny.
    False,
    /// All children must evaluate to Allow.
    And(Vec<Expr>),
    /// At least one child must evaluate to Allow.
    Or(Vec<Expr>),
    /// Invert the child's outcome.
    Not(Box<Expr>),

    // ── Capability ───────────────────────────────────────────────────
    /// Subject must have this capability.
    HasCapability(String),
    /// Subject must have all listed capabilities.
    HasAllCapabilities(Vec<String>),
    /// Subject must have at least one of the listed capabilities.
    HasAnyCapability(Vec<String>),

    // ── Identity ─────────────────────────────────────────────────────
    /// Issuer DID must match exactly.
    IssuerIs(String),
    /// Issuer DID must be in the set.
    IssuerIn(Vec<String>),
    /// Subject DID must match exactly.
    SubjectIs(String),
    /// Attestation must be delegated by this DID.
    DelegatedBy(String),

    // ── Lifecycle ────────────────────────────────────────────────────
    /// Attestation must not be revoked.
    NotRevoked,
    /// Attestation must not be expired.
    NotExpired,
    /// Attestation must have at least this many seconds remaining.
    ExpiresAfter(i64),
    /// Attestation must have been issued within this many seconds.
    IssuedWithin(i64),

    // ── Role ─────────────────────────────────────────────────────────
    /// Subject's role must match exactly.
    RoleIs(String),
    /// Subject's role must be in the set.
    RoleIn(Vec<String>),

    // ── Scope (typed, first-class) ───────────────────────────────────
    /// Repository must match exactly.
    RepoIs(String),
    /// Repository must be in the set.
    RepoIn(Vec<String>),
    /// Git ref must match the glob pattern.
    RefMatches(String),
    /// All paths must match at least one of the glob patterns.
    PathAllowed(Vec<String>),
    /// Environment must match exactly.
    EnvIs(String),
    /// Environment must be in the set.
    EnvIn(Vec<String>),

    // ── Workload Claims ──────────────────────────────────────────────
    /// Workload issuer DID must match exactly.
    WorkloadIssuerIs(String),
    /// Workload claim must equal the expected value.
    WorkloadClaimEquals {
        /// Claim key (alphanumeric + underscore only).
        key: String,
        /// Expected value.
        value: String,
    },

    // ── Signer Type ──────────────────────────────────────────────────
    /// Signer must be an AI agent.
    IsAgent,
    /// Signer must be a human.
    IsHuman,
    /// Signer must be a workload (CI/CD).
    IsWorkload,

    // ── Chain ────────────────────────────────────────────────────────
    /// Delegation chain depth must not exceed this value.
    MaxChainDepth(u32),

    // ── Escape Hatch (constrained) ───────────────────────────────────
    /// Match a flat string attribute. Keys must be alphanumeric+underscore,
    /// max 64 chars. No dot-paths. No nested JSON. No `Value` type.
    AttrEquals {
        /// Attribute key (alphanumeric + underscore only).
        key: String,
        /// Expected value.
        value: String,
    },
    /// Attribute must be one of the values.
    AttrIn {
        /// Attribute key (alphanumeric + underscore only).
        key: String,
        /// Allowed values.
        values: Vec<String>,
    },

    // ── Assurance Level ────────────────────────────────────────────
    /// Assurance level must be at least this level (uses `Ord` comparison).
    MinAssurance(String),
    /// Assurance level must match exactly.
    AssuranceLevelIs(String),

    // ── Approval Gate ─────────────────────────────────────────────
    /// Approval gate: if inner evaluates to Allow, return RequiresApproval instead.
    /// Transparent to Deny/Indeterminate — those pass through unchanged.
    ApprovalGate {
        /// The inner expression to evaluate.
        inner: Box<Expr>,
        /// DIDs of allowed approvers (validated at compile time).
        approvers: Vec<String>,
        /// Approval request TTL in seconds (default 300 = 5 minutes).
        ttl_seconds: u64,
        /// Approval scope: "identity" (default), "scoped", or "full".
        scope: Option<String>,
    },
}

impl Expr {
    /// Create an And expression from multiple conditions.
    pub fn and(conditions: impl IntoIterator<Item = Expr>) -> Self {
        Expr::And(conditions.into_iter().collect())
    }

    /// Create an Or expression from multiple conditions.
    pub fn or(conditions: impl IntoIterator<Item = Expr>) -> Self {
        Expr::Or(conditions.into_iter().collect())
    }

    /// Create a Not expression (negation).
    pub fn negate(expr: Expr) -> Self {
        Expr::Not(Box::new(expr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_true() {
        let expr = Expr::True;
        let json = serde_json::to_string(&expr).unwrap();
        assert_eq!(json, r#"{"op":"True"}"#);
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_has_capability() {
        let expr = Expr::HasCapability("sign_commit".into());
        let json = serde_json::to_string(&expr).unwrap();
        assert!(json.contains(r#""op":"HasCapability""#));
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_and() {
        let expr = Expr::And(vec![Expr::NotRevoked, Expr::NotExpired]);
        let json = serde_json::to_string(&expr).unwrap();
        assert!(json.contains(r#""op":"And""#));
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_not() {
        let expr = Expr::Not(Box::new(Expr::HasCapability("admin".into())));
        let json = serde_json::to_string(&expr).unwrap();
        assert!(json.contains(r#""op":"Not""#));
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_issuer_in() {
        let expr = Expr::IssuerIn(vec!["did:keri:E1".into(), "did:keri:E2".into()]);
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_ref_matches() {
        let expr = Expr::RefMatches("refs/heads/*".into());
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_workload_claim_equals() {
        let expr = Expr::WorkloadClaimEquals {
            key: "repo".into(),
            value: "my-org/my-repo".into(),
        };
        let json = serde_json::to_string(&expr).unwrap();
        assert!(json.contains("WorkloadClaimEquals"));
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_attr_equals() {
        let expr = Expr::AttrEquals {
            key: "team".into(),
            value: "platform".into(),
        };
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_attr_in() {
        let expr = Expr::AttrIn {
            key: "team".into(),
            values: vec!["platform".into(), "security".into()],
        };
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn serde_complex_nested() {
        let expr = Expr::And(vec![
            Expr::NotRevoked,
            Expr::NotExpired,
            Expr::Or(vec![
                Expr::HasCapability("admin".into()),
                Expr::And(vec![
                    Expr::HasCapability("write".into()),
                    Expr::RepoIs("my-org/my-repo".into()),
                ]),
            ]),
        ]);
        let json = serde_json::to_string(&expr).unwrap();
        let parsed: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, expr);
    }

    #[test]
    fn helper_and() {
        let expr = Expr::and([Expr::True, Expr::False]);
        match expr {
            Expr::And(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn helper_or() {
        let expr = Expr::or([Expr::True, Expr::False]);
        match expr {
            Expr::Or(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn helper_negate() {
        let expr = Expr::negate(Expr::True);
        match expr {
            Expr::Not(inner) => assert_eq!(*inner, Expr::True),
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn serde_all_variants() {
        // Test that all variants can be serialized and deserialized
        let variants = vec![
            Expr::True,
            Expr::False,
            Expr::And(vec![]),
            Expr::Or(vec![]),
            Expr::Not(Box::new(Expr::True)),
            Expr::HasCapability("cap".into()),
            Expr::HasAllCapabilities(vec!["a".into(), "b".into()]),
            Expr::HasAnyCapability(vec!["a".into(), "b".into()]),
            Expr::IssuerIs("did:keri:E1".into()),
            Expr::IssuerIn(vec!["did:keri:E1".into()]),
            Expr::SubjectIs("did:keri:E1".into()),
            Expr::DelegatedBy("did:keri:E1".into()),
            Expr::NotRevoked,
            Expr::NotExpired,
            Expr::ExpiresAfter(3600),
            Expr::IssuedWithin(86400),
            Expr::RoleIs("admin".into()),
            Expr::RoleIn(vec!["admin".into(), "user".into()]),
            Expr::RepoIs("org/repo".into()),
            Expr::RepoIn(vec!["org/repo".into()]),
            Expr::RefMatches("refs/heads/*".into()),
            Expr::PathAllowed(vec!["src/**".into()]),
            Expr::EnvIs("production".into()),
            Expr::EnvIn(vec!["staging".into(), "production".into()]),
            Expr::WorkloadIssuerIs("did:keri:E1".into()),
            Expr::WorkloadClaimEquals {
                key: "k".into(),
                value: "v".into(),
            },
            Expr::IsAgent,
            Expr::IsHuman,
            Expr::IsWorkload,
            Expr::MaxChainDepth(3),
            Expr::AttrEquals {
                key: "k".into(),
                value: "v".into(),
            },
            Expr::AttrIn {
                key: "k".into(),
                values: vec!["v1".into(), "v2".into()],
            },
            Expr::MinAssurance("authenticated".into()),
            Expr::AssuranceLevelIs("sovereign".into()),
            Expr::ApprovalGate {
                inner: Box::new(Expr::HasCapability("deploy".into())),
                approvers: vec!["did:keri:EHuman123".into()],
                ttl_seconds: 300,
                scope: Some("identity".into()),
            },
        ];

        for expr in variants {
            let json = serde_json::to_string(&expr).unwrap();
            let parsed: Expr = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expr, "roundtrip failed for {:?}", expr);
        }
    }
}
