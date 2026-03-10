//! Fluent builder for constructing compiled policies.
//!
//! The `PolicyBuilder` provides an ergonomic API for constructing policies
//! in code. It accumulates conditions and compiles them into a `CompiledPolicy`.

use crate::compile::{CompileError, compile};
use crate::compiled::CompiledPolicy;
use crate::expr::Expr;

/// Fluent builder that produces a `CompiledPolicy`.
///
/// Panics on `build()` if any field is invalid. For fallible
/// construction, use `try_build()`.
///
/// # Example
///
/// ```
/// use auths_policy::builder::PolicyBuilder;
///
/// let policy = PolicyBuilder::new()
///     .not_revoked()
///     .not_expired()
///     .require_capability("sign_commit")
///     .require_issuer("did:keri:EOrg123")
///     .build();
/// ```
pub struct PolicyBuilder {
    conditions: Vec<Expr>,
}

impl PolicyBuilder {
    /// Create a new empty policy builder.
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
        }
    }

    /// Reconstruct a `PolicyBuilder` from a JSON policy expression.
    ///
    /// Enables round-tripping saved policy JSON back to a builder for
    /// modification or recompilation.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        let expr: Expr = serde_json::from_str(json_str)?;
        let conditions = match expr {
            Expr::And(children) => children,
            single => vec![single],
        };
        Ok(Self { conditions })
    }

    /// Require a specific capability.
    pub fn require_capability(mut self, cap: impl Into<String>) -> Self {
        self.conditions.push(Expr::HasCapability(cap.into()));
        self
    }

    /// Require all of the specified capabilities.
    pub fn require_all_capabilities(
        mut self,
        caps: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.conditions.push(Expr::HasAllCapabilities(
            caps.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Require at least one of the specified capabilities.
    pub fn require_any_capability(
        mut self,
        caps: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.conditions.push(Expr::HasAnyCapability(
            caps.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Require a specific issuer DID.
    pub fn require_issuer(mut self, did: impl Into<String>) -> Self {
        self.conditions.push(Expr::IssuerIs(did.into()));
        self
    }

    /// Require the issuer to be one of the specified DIDs.
    pub fn require_issuer_in(mut self, dids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.conditions
            .push(Expr::IssuerIn(dids.into_iter().map(Into::into).collect()));
        self
    }

    /// Require a specific subject DID.
    pub fn require_subject(mut self, did: impl Into<String>) -> Self {
        self.conditions.push(Expr::SubjectIs(did.into()));
        self
    }

    /// Require delegation from a specific DID.
    pub fn require_delegated_by(mut self, did: impl Into<String>) -> Self {
        self.conditions.push(Expr::DelegatedBy(did.into()));
        self
    }

    /// Require that the attestation is not revoked.
    pub fn not_revoked(mut self) -> Self {
        self.conditions.push(Expr::NotRevoked);
        self
    }

    /// Require that the attestation is not expired.
    pub fn not_expired(mut self) -> Self {
        self.conditions.push(Expr::NotExpired);
        self
    }

    /// Require the attestation to have at least this many seconds remaining.
    pub fn expires_after_seconds(mut self, s: i64) -> Self {
        self.conditions.push(Expr::ExpiresAfter(s));
        self
    }

    /// Require the attestation to have been issued within this many seconds.
    pub fn issued_within_seconds(mut self, s: i64) -> Self {
        self.conditions.push(Expr::IssuedWithin(s));
        self
    }

    /// Require a specific role.
    pub fn require_role(mut self, role: impl Into<String>) -> Self {
        self.conditions.push(Expr::RoleIs(role.into()));
        self
    }

    /// Require the role to be one of the specified values.
    pub fn require_role_in(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.conditions
            .push(Expr::RoleIn(roles.into_iter().map(Into::into).collect()));
        self
    }

    /// Require a specific repository.
    pub fn repo_is(mut self, repo: impl Into<String>) -> Self {
        self.conditions.push(Expr::RepoIs(repo.into()));
        self
    }

    /// Require the repository to be one of the specified values.
    pub fn repo_in(mut self, repos: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.conditions
            .push(Expr::RepoIn(repos.into_iter().map(Into::into).collect()));
        self
    }

    /// Require the git ref to match a glob pattern.
    pub fn ref_matches(mut self, pattern: impl Into<String>) -> Self {
        self.conditions.push(Expr::RefMatches(pattern.into()));
        self
    }

    /// Require all paths to match at least one of the glob patterns.
    pub fn path_allowed(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.conditions.push(Expr::PathAllowed(
            patterns.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Require a specific environment.
    pub fn env_is(mut self, env: impl Into<String>) -> Self {
        self.conditions.push(Expr::EnvIs(env.into()));
        self
    }

    /// Require the environment to be one of the specified values.
    pub fn env_in(mut self, envs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.conditions
            .push(Expr::EnvIn(envs.into_iter().map(Into::into).collect()));
        self
    }

    /// Require a specific workload issuer.
    pub fn workload_issuer_is(mut self, did: impl Into<String>) -> Self {
        self.conditions.push(Expr::WorkloadIssuerIs(did.into()));
        self
    }

    /// Require a workload claim to have a specific value.
    pub fn workload_claim_equals(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.conditions.push(Expr::WorkloadClaimEquals {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    /// Require the signer to be a human.
    pub fn require_human(mut self) -> Self {
        self.conditions.push(Expr::IsHuman);
        self
    }

    /// Require the signer to be an AI agent.
    pub fn require_agent(mut self) -> Self {
        self.conditions.push(Expr::IsAgent);
        self
    }

    /// Require the signer to be a workload (CI/CD).
    pub fn require_workload(mut self) -> Self {
        self.conditions.push(Expr::IsWorkload);
        self
    }

    /// Require the delegation chain depth to not exceed this value.
    pub fn max_chain_depth(mut self, max: u32) -> Self {
        self.conditions.push(Expr::MaxChainDepth(max));
        self
    }

    /// Require an attribute to have a specific value.
    pub fn attr_equals(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.conditions.push(Expr::AttrEquals {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    /// Require an attribute to be one of the specified values.
    pub fn attr_in(mut self, key: impl Into<String>, values: Vec<String>) -> Self {
        self.conditions.push(Expr::AttrIn {
            key: key.into(),
            values,
        });
        self
    }

    /// Add a raw expression as a condition.
    pub fn condition(mut self, expr: Expr) -> Self {
        self.conditions.push(expr);
        self
    }

    /// Try to build the policy, returning errors if validation fails.
    pub fn try_build(self) -> Result<CompiledPolicy, Vec<CompileError>> {
        let expr = match self.conditions.len() {
            0 => Expr::True,
            // INVARIANT: len()==1 guarantees next() returns Some
            #[allow(clippy::unwrap_used)]
            1 => self.conditions.into_iter().next().unwrap(),
            _ => Expr::And(self.conditions),
        };
        compile(&expr)
    }

    /// Build the policy, panicking if validation fails.
    ///
    /// # Panics
    ///
    /// Panics if any condition contains invalid data (e.g., malformed DID).
    #[allow(clippy::expect_used)]
    pub fn build(self) -> CompiledPolicy {
        self.try_build().expect("PolicyBuilder: invalid policy")
    }
}

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiled::CompiledExpr;

    #[test]
    fn empty_builder_produces_true() {
        let policy = PolicyBuilder::new().build();
        assert!(matches!(policy.expr(), CompiledExpr::True));
    }

    #[test]
    fn single_condition_not_wrapped_in_and() {
        let policy = PolicyBuilder::new().not_revoked().build();
        assert!(matches!(policy.expr(), CompiledExpr::NotRevoked));
    }

    #[test]
    fn multiple_conditions_wrapped_in_and() {
        let policy = PolicyBuilder::new().not_revoked().not_expired().build();
        assert!(matches!(policy.expr(), CompiledExpr::And(_)));
    }

    #[test]
    fn require_capability() {
        let policy = PolicyBuilder::new()
            .require_capability("sign_commit")
            .build();
        match policy.expr() {
            CompiledExpr::HasCapability(cap) => {
                assert_eq!(cap.as_str(), "sign_commit");
            }
            _ => panic!("expected HasCapability"),
        }
    }

    #[test]
    fn require_all_capabilities() {
        let policy = PolicyBuilder::new()
            .require_all_capabilities(["sign_commit", "push"])
            .build();
        match policy.expr() {
            CompiledExpr::HasAllCapabilities(caps) => {
                assert_eq!(caps.len(), 2);
            }
            _ => panic!("expected HasAllCapabilities"),
        }
    }

    #[test]
    fn require_any_capability() {
        let policy = PolicyBuilder::new()
            .require_any_capability(["sign_commit", "push"])
            .build();
        match policy.expr() {
            CompiledExpr::HasAnyCapability(caps) => {
                assert_eq!(caps.len(), 2);
            }
            _ => panic!("expected HasAnyCapability"),
        }
    }

    #[test]
    fn require_issuer() {
        let policy = PolicyBuilder::new()
            .require_issuer("did:keri:EOrg123")
            .build();
        match policy.expr() {
            CompiledExpr::IssuerIs(did) => {
                assert_eq!(did.as_str(), "did:keri:EOrg123");
            }
            _ => panic!("expected IssuerIs"),
        }
    }

    #[test]
    fn require_issuer_in() {
        let policy = PolicyBuilder::new()
            .require_issuer_in(["did:keri:EOrg123", "did:keri:EOrg456"])
            .build();
        match policy.expr() {
            CompiledExpr::IssuerIn(dids) => {
                assert_eq!(dids.len(), 2);
            }
            _ => panic!("expected IssuerIn"),
        }
    }

    #[test]
    fn require_subject() {
        let policy = PolicyBuilder::new()
            .require_subject("did:keri:EUser123")
            .build();
        match policy.expr() {
            CompiledExpr::SubjectIs(did) => {
                assert_eq!(did.as_str(), "did:keri:EUser123");
            }
            _ => panic!("expected SubjectIs"),
        }
    }

    #[test]
    fn require_delegated_by() {
        let policy = PolicyBuilder::new()
            .require_delegated_by("did:keri:EDelegate")
            .build();
        match policy.expr() {
            CompiledExpr::DelegatedBy(did) => {
                assert_eq!(did.as_str(), "did:keri:EDelegate");
            }
            _ => panic!("expected DelegatedBy"),
        }
    }

    #[test]
    fn lifecycle_conditions() {
        let policy = PolicyBuilder::new()
            .not_revoked()
            .not_expired()
            .expires_after_seconds(3600)
            .issued_within_seconds(86400)
            .build();
        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 4);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn role_conditions() {
        let policy = PolicyBuilder::new().require_role("admin").build();
        match policy.expr() {
            CompiledExpr::RoleIs(role) => {
                assert_eq!(role, "admin");
            }
            _ => panic!("expected RoleIs"),
        }
    }

    #[test]
    fn role_in_conditions() {
        let policy = PolicyBuilder::new()
            .require_role_in(["admin", "maintainer"])
            .build();
        match policy.expr() {
            CompiledExpr::RoleIn(roles) => {
                assert_eq!(roles.len(), 2);
            }
            _ => panic!("expected RoleIn"),
        }
    }

    #[test]
    fn repo_conditions() {
        let policy = PolicyBuilder::new().repo_is("org/repo").build();
        match policy.expr() {
            CompiledExpr::RepoIs(repo) => {
                assert_eq!(repo, "org/repo");
            }
            _ => panic!("expected RepoIs"),
        }
    }

    #[test]
    fn repo_in_conditions() {
        let policy = PolicyBuilder::new()
            .repo_in(["org/repo1", "org/repo2"])
            .build();
        match policy.expr() {
            CompiledExpr::RepoIn(repos) => {
                assert_eq!(repos.len(), 2);
            }
            _ => panic!("expected RepoIn"),
        }
    }

    #[test]
    fn ref_matches_condition() {
        let policy = PolicyBuilder::new().ref_matches("refs/heads/*").build();
        match policy.expr() {
            CompiledExpr::RefMatches(glob) => {
                assert_eq!(glob.as_str(), "refs/heads/*");
            }
            _ => panic!("expected RefMatches"),
        }
    }

    #[test]
    fn path_allowed_condition() {
        let policy = PolicyBuilder::new()
            .path_allowed(["src/**", "docs/**"])
            .build();
        match policy.expr() {
            CompiledExpr::PathAllowed(patterns) => {
                assert_eq!(patterns.len(), 2);
            }
            _ => panic!("expected PathAllowed"),
        }
    }

    #[test]
    fn env_conditions() {
        let policy = PolicyBuilder::new().env_is("production").build();
        match policy.expr() {
            CompiledExpr::EnvIs(env) => {
                assert_eq!(env, "production");
            }
            _ => panic!("expected EnvIs"),
        }
    }

    #[test]
    fn env_in_conditions() {
        let policy = PolicyBuilder::new()
            .env_in(["staging", "production"])
            .build();
        match policy.expr() {
            CompiledExpr::EnvIn(envs) => {
                assert_eq!(envs.len(), 2);
            }
            _ => panic!("expected EnvIn"),
        }
    }

    #[test]
    fn workload_conditions() {
        let policy = PolicyBuilder::new()
            .workload_issuer_is("did:keri:EWorkload")
            .workload_claim_equals("aud", "my-service")
            .build();
        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn max_chain_depth_condition() {
        let policy = PolicyBuilder::new().max_chain_depth(3).build();
        match policy.expr() {
            CompiledExpr::MaxChainDepth(max) => {
                assert_eq!(*max, 3);
            }
            _ => panic!("expected MaxChainDepth"),
        }
    }

    #[test]
    fn attr_conditions() {
        let policy = PolicyBuilder::new()
            .attr_equals("team", "platform")
            .attr_in("tier", vec!["gold".into(), "platinum".into()])
            .build();
        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn raw_condition() {
        let policy = PolicyBuilder::new()
            .condition(Expr::True)
            .condition(Expr::False)
            .build();
        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn try_build_returns_errors_for_invalid_did() {
        let result = PolicyBuilder::new()
            .require_issuer("not-a-valid-did")
            .try_build();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
    }

    #[test]
    fn try_build_returns_errors_for_invalid_capability() {
        let result = PolicyBuilder::new()
            .require_capability("invalid capability with spaces")
            .try_build();
        assert!(result.is_err());
    }

    #[test]
    fn try_build_returns_errors_for_invalid_glob() {
        let result = PolicyBuilder::new()
            .ref_matches("refs/../escape")
            .try_build();
        assert!(result.is_err());
    }

    #[test]
    fn complex_policy() {
        let policy = PolicyBuilder::new()
            .not_revoked()
            .not_expired()
            .require_capability("sign_commit")
            .require_issuer("did:keri:EOrg123")
            .require_role_in(["maintainer", "admin"])
            .ref_matches("refs/heads/*")
            .max_chain_depth(2)
            .build();

        match policy.expr() {
            CompiledExpr::And(children) => {
                assert_eq!(children.len(), 7);
            }
            _ => panic!("expected And with 7 children"),
        }
    }

    #[test]
    fn default_is_new() {
        let builder1 = PolicyBuilder::new();
        let builder2 = PolicyBuilder::default();
        // Both should produce True for empty policy
        assert_eq!(builder1.build(), builder2.build());
    }
}
