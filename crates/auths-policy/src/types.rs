//! Canonical types for policy expressions.
//!
//! Every string that crosses the policy boundary gets validated and canonicalised
//! at compile time. These types ensure that invalid data cannot reach the evaluator.

use std::fmt;

use serde::{Deserialize, Serialize};

// CanonicalDid lives in auths-verifier (Layer 1) so all DID types are co-located.
pub use auths_verifier::types::CanonicalDid;

/// Re-export DidParseError from auths-verifier for backwards compatibility.
pub type DidParseError = auths_verifier::DidParseError;

/// A validated capability identifier.
///
/// Enforces the same rules as `Capability::validate_custom`:
/// alphanumeric + colon/hyphen/underscore, max 64 chars. Stored in canonical
/// lowercase form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CanonicalCapability(String);

/// Error returned when parsing a capability fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityParseError(pub String);

impl std::fmt::Display for CapabilityParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CapabilityParseError {}

impl CanonicalCapability {
    /// Parse and validate a capability string into canonical form.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability:
    /// - Is empty or exceeds 64 characters
    /// - Contains characters other than alphanumeric, colon, hyphen, or underscore
    pub fn parse(raw: &str) -> Result<Self, CapabilityParseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return Err(CapabilityParseError(format!(
                "capability must be 1-64 chars, got {}",
                trimmed.len()
            )));
        }
        if !trimmed
            .chars()
            .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
        {
            return Err(CapabilityParseError(format!(
                "invalid chars in capability: '{}'",
                trimmed
            )));
        }
        // Canonical: lowercase
        Ok(Self(trimmed.to_lowercase()))
    }

    /// Returns the canonical capability as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CanonicalCapability {
    type Error = CapabilityParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<CanonicalCapability> for String {
    fn from(c: CanonicalCapability) -> Self {
        c.0
    }
}

impl fmt::Display for CanonicalCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The type of entity that produced a signature.
///
/// Used to distinguish human, AI agent, and workload (CI/CD) signers
/// in policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignerType {
    /// A human user.
    Human,
    /// An autonomous AI agent.
    Agent,
    /// A CI/CD workload or service identity.
    Workload,
}

/// A validated glob pattern for path/ref matching.
///
/// Restricted to:
/// - ASCII printable characters only
/// - Max 256 chars
/// - Wildcards: `*` (single segment), `**` (multi-segment)
/// - No `..` path traversal
/// - Segments separated by `/`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedGlob(String);

/// Error returned when parsing a glob pattern fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobParseError(pub String);

impl std::fmt::Display for GlobParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for GlobParseError {}

impl ValidatedGlob {
    /// Parse and validate a glob pattern into canonical form.
    ///
    /// # Errors
    ///
    /// Returns an error if the glob:
    /// - Is empty or exceeds 256 characters
    /// - Contains non-ASCII or control characters
    /// - Contains path traversal (`..`)
    pub fn parse(raw: &str) -> Result<Self, GlobParseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 256 {
            return Err(GlobParseError(format!(
                "glob must be 1-256 chars, got {}",
                trimmed.len()
            )));
        }
        if !trimmed.chars().all(|c| c.is_ascii() && !c.is_control()) {
            return Err(GlobParseError(
                "glob contains non-ASCII or control chars".into(),
            ));
        }
        if trimmed.contains("..") {
            return Err(GlobParseError("glob contains path traversal (..)".into()));
        }
        // Normalise consecutive slashes
        let normalised: String = trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        Ok(Self(normalised))
    }

    /// Returns the normalised glob pattern as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ValidatedGlob {
    type Error = GlobParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<ValidatedGlob> for String {
    fn from(g: ValidatedGlob) -> Self {
        g.0
    }
}

impl fmt::Display for ValidatedGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Evaluates quorum requirements across multiple signers.
///
/// This operates at a higher level than `Expr` (which evaluates a single
/// `EvalContext`). A `QuorumPolicy` aggregates the results of per-signer
/// policy evaluations and enforces typed signer count thresholds.
///
/// Usage:
/// ```ignore
/// let quorum = QuorumPolicy {
///     required_humans: 1,
///     required_agents: 1,
///     required_total: 2,
///     base_expression: Expr::And(vec![Expr::NotRevoked, Expr::NotExpired]),
/// };
/// let approved = quorum.evaluate(&contexts, |expr, ctx| evaluator(expr, ctx));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Minimum number of human signers required.
    pub required_humans: u32,
    /// Minimum number of agent signers required.
    pub required_agents: u32,
    /// Minimum total signers required (human + agent + workload).
    pub required_total: u32,
    /// Each signer must also pass this expression.
    pub base_expression: crate::expr::Expr,
}

impl QuorumPolicy {
    /// Evaluate the quorum against a set of signer contexts.
    ///
    /// Args:
    /// * `contexts`: The evaluation contexts for each signer.
    /// * `eval_fn`: A function that evaluates the base expression against a context.
    ///   Returns `true` if the signer passes the base policy.
    pub fn evaluate<F>(&self, contexts: &[crate::context::EvalContext], eval_fn: F) -> bool
    where
        F: Fn(&crate::expr::Expr, &crate::context::EvalContext) -> bool,
    {
        let mut human_count: u32 = 0;
        let mut agent_count: u32 = 0;
        let mut total_count: u32 = 0;

        for ctx in contexts {
            if eval_fn(&self.base_expression, ctx) {
                total_count += 1;
                match ctx.signer_type {
                    Some(SignerType::Human) => human_count += 1,
                    Some(SignerType::Agent) => agent_count += 1,
                    Some(SignerType::Workload) | None => {}
                }
            }
        }

        human_count >= self.required_humans
            && agent_count >= self.required_agents
            && total_count >= self.required_total
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    mod canonical_did {
        use super::*;

        #[test]
        fn parses_valid_did() {
            let did = CanonicalDid::parse("did:keri:EOrg123").unwrap();
            assert_eq!(did.as_str(), "did:keri:EOrg123");
        }

        #[test]
        fn lowercases_method() {
            let did = CanonicalDid::parse("did:KERI:EOrg123").unwrap();
            assert_eq!(did.as_str(), "did:keri:EOrg123");
        }

        #[test]
        fn preserves_id_case() {
            let did = CanonicalDid::parse("did:key:zABC123XYZ").unwrap();
            assert_eq!(did.as_str(), "did:key:zABC123XYZ");
        }

        #[test]
        fn trims_whitespace() {
            let did = CanonicalDid::parse("  did:keri:EOrg123  ").unwrap();
            assert_eq!(did.as_str(), "did:keri:EOrg123");
        }

        #[test]
        fn rejects_empty() {
            assert!(CanonicalDid::parse("").is_err());
            assert!(CanonicalDid::parse("   ").is_err());
        }

        #[test]
        fn rejects_missing_parts() {
            assert!(CanonicalDid::parse("did").is_err());
            assert!(CanonicalDid::parse("did:keri").is_err());
            assert!(CanonicalDid::parse("did::id").is_err());
            assert!(CanonicalDid::parse("did:keri:").is_err());
        }

        #[test]
        fn rejects_wrong_prefix() {
            assert!(CanonicalDid::parse("uri:keri:id").is_err());
        }

        #[test]
        fn rejects_control_chars() {
            assert!(CanonicalDid::parse("did:keri:id\x00").is_err());
            assert!(CanonicalDid::parse("did:keri:id\n").is_err());
        }

        #[test]
        fn serde_roundtrip() {
            let did = CanonicalDid::parse("did:keri:EOrg123").unwrap();
            let json = serde_json::to_string(&did).unwrap();
            let parsed: CanonicalDid = serde_json::from_str(&json).unwrap();
            assert_eq!(did, parsed);
        }
    }

    mod canonical_capability {
        use super::*;

        #[test]
        fn parses_valid_capability() {
            let cap = CanonicalCapability::parse("sign_commit").unwrap();
            assert_eq!(cap.as_str(), "sign_commit");
        }

        #[test]
        fn lowercases() {
            let cap = CanonicalCapability::parse("Sign_Commit").unwrap();
            assert_eq!(cap.as_str(), "sign_commit");
        }

        #[test]
        fn allows_colons_and_hyphens() {
            let cap = CanonicalCapability::parse("repo:read-write").unwrap();
            assert_eq!(cap.as_str(), "repo:read-write");
        }

        #[test]
        fn trims_whitespace() {
            let cap = CanonicalCapability::parse("  sign_commit  ").unwrap();
            assert_eq!(cap.as_str(), "sign_commit");
        }

        #[test]
        fn rejects_empty() {
            assert!(CanonicalCapability::parse("").is_err());
        }

        #[test]
        fn rejects_too_long() {
            let long = "a".repeat(65);
            assert!(CanonicalCapability::parse(&long).is_err());
        }

        #[test]
        fn accepts_max_length() {
            let max = "a".repeat(64);
            assert!(CanonicalCapability::parse(&max).is_ok());
        }

        #[test]
        fn rejects_invalid_chars() {
            assert!(CanonicalCapability::parse("sign commit").is_err()); // space
            assert!(CanonicalCapability::parse("sign.commit").is_err()); // dot
            assert!(CanonicalCapability::parse("sign/commit").is_err()); // slash
        }

        #[test]
        fn serde_roundtrip() {
            let cap = CanonicalCapability::parse("sign_commit").unwrap();
            let json = serde_json::to_string(&cap).unwrap();
            let parsed: CanonicalCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, parsed);
        }
    }

    mod validated_glob {
        use super::*;

        #[test]
        fn parses_simple_path() {
            let glob = ValidatedGlob::parse("refs/heads/main").unwrap();
            assert_eq!(glob.as_str(), "refs/heads/main");
        }

        #[test]
        fn parses_wildcards() {
            let glob = ValidatedGlob::parse("refs/heads/*").unwrap();
            assert_eq!(glob.as_str(), "refs/heads/*");

            let glob = ValidatedGlob::parse("refs/**/main").unwrap();
            assert_eq!(glob.as_str(), "refs/**/main");
        }

        #[test]
        fn normalises_consecutive_slashes() {
            let glob = ValidatedGlob::parse("refs//heads///main").unwrap();
            assert_eq!(glob.as_str(), "refs/heads/main");
        }

        #[test]
        fn strips_leading_trailing_slashes() {
            let glob = ValidatedGlob::parse("/refs/heads/main/").unwrap();
            assert_eq!(glob.as_str(), "refs/heads/main");
        }

        #[test]
        fn trims_whitespace() {
            let glob = ValidatedGlob::parse("  refs/heads/main  ").unwrap();
            assert_eq!(glob.as_str(), "refs/heads/main");
        }

        #[test]
        fn rejects_empty() {
            assert!(ValidatedGlob::parse("").is_err());
        }

        #[test]
        fn rejects_too_long() {
            let long = "a/".repeat(129); // 258 chars
            assert!(ValidatedGlob::parse(&long).is_err());
        }

        #[test]
        fn rejects_path_traversal() {
            assert!(ValidatedGlob::parse("refs/../secrets").is_err());
            assert!(ValidatedGlob::parse("..").is_err());
            assert!(ValidatedGlob::parse("foo/..").is_err());
        }

        #[test]
        fn rejects_non_ascii() {
            assert!(ValidatedGlob::parse("refs/héads/main").is_err());
        }

        #[test]
        fn rejects_control_chars() {
            assert!(ValidatedGlob::parse("refs/heads/main\x00").is_err());
        }

        #[test]
        fn serde_roundtrip() {
            let glob = ValidatedGlob::parse("refs/heads/*").unwrap();
            let json = serde_json::to_string(&glob).unwrap();
            let parsed: ValidatedGlob = serde_json::from_str(&json).unwrap();
            assert_eq!(glob, parsed);
        }
    }

    mod signer_type {
        use super::*;

        #[test]
        fn serde_roundtrip() {
            for st in [SignerType::Human, SignerType::Agent, SignerType::Workload] {
                let json = serde_json::to_string(&st).unwrap();
                let parsed: SignerType = serde_json::from_str(&json).unwrap();
                assert_eq!(st, parsed);
            }
        }

        #[test]
        fn equality() {
            assert_eq!(SignerType::Human, SignerType::Human);
            assert_ne!(SignerType::Human, SignerType::Agent);
            assert_ne!(SignerType::Agent, SignerType::Workload);
        }
    }

    mod quorum_policy {
        use super::*;
        use crate::context::EvalContext;
        use crate::expr::Expr;
        use chrono::Utc;

        fn did(s: &str) -> CanonicalDid {
            CanonicalDid::parse(s).unwrap()
        }

        fn make_ctx(signer_type: SignerType) -> EvalContext {
            EvalContext::new(Utc::now(), did("did:keri:issuer"), did("did:keri:subject"))
                .signer_type(signer_type)
        }

        fn always_pass(_expr: &Expr, _ctx: &EvalContext) -> bool {
            true
        }

        fn always_fail(_expr: &Expr, _ctx: &EvalContext) -> bool {
            false
        }

        #[test]
        fn quorum_met_with_mixed_signers() {
            let quorum = QuorumPolicy {
                required_humans: 1,
                required_agents: 1,
                required_total: 2,
                base_expression: Expr::True,
            };
            let contexts = vec![make_ctx(SignerType::Human), make_ctx(SignerType::Agent)];
            assert!(quorum.evaluate(&contexts, always_pass));
        }

        #[test]
        fn quorum_not_met_missing_human() {
            let quorum = QuorumPolicy {
                required_humans: 1,
                required_agents: 1,
                required_total: 2,
                base_expression: Expr::True,
            };
            let contexts = vec![make_ctx(SignerType::Agent), make_ctx(SignerType::Agent)];
            assert!(!quorum.evaluate(&contexts, always_pass));
        }

        #[test]
        fn quorum_not_met_base_expression_fails() {
            let quorum = QuorumPolicy {
                required_humans: 1,
                required_agents: 0,
                required_total: 1,
                base_expression: Expr::True,
            };
            let contexts = vec![make_ctx(SignerType::Human)];
            assert!(!quorum.evaluate(&contexts, always_fail));
        }

        #[test]
        fn quorum_empty_contexts() {
            let quorum = QuorumPolicy {
                required_humans: 0,
                required_agents: 0,
                required_total: 0,
                base_expression: Expr::True,
            };
            assert!(quorum.evaluate(&[], always_pass));
        }

        #[test]
        fn quorum_total_threshold() {
            let quorum = QuorumPolicy {
                required_humans: 0,
                required_agents: 0,
                required_total: 3,
                base_expression: Expr::True,
            };
            let contexts = vec![make_ctx(SignerType::Human), make_ctx(SignerType::Agent)];
            assert!(!quorum.evaluate(&contexts, always_pass));

            let contexts = vec![
                make_ctx(SignerType::Human),
                make_ctx(SignerType::Agent),
                make_ctx(SignerType::Workload),
            ];
            assert!(quorum.evaluate(&contexts, always_pass));
        }

        #[test]
        fn serde_roundtrip() {
            let quorum = QuorumPolicy {
                required_humans: 1,
                required_agents: 1,
                required_total: 2,
                base_expression: Expr::And(vec![Expr::NotRevoked, Expr::NotExpired]),
            };
            let json = serde_json::to_string(&quorum).unwrap();
            let parsed: QuorumPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(quorum, parsed);
        }
    }
}
