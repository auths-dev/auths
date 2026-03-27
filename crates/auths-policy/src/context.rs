//! Typed evaluation context.
//!
//! The context is a typed struct with first-class scope fields. No JSON dot-paths.
//! Constructed by an **adapter** in `auths-id`, not by the policy crate directly.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::approval::ApprovalAttestation;
use crate::types::{AssuranceLevel, CanonicalCapability, CanonicalDid, SignerType};

/// Typed evaluation context.
///
/// Constructed by an **adapter** in `auths-id`, not by the policy crate directly.
/// This keeps `auths-policy` decoupled from `auths-verifier`'s data model.
///
/// # Scope Fields
///
/// Scope fields (`repo`, `git_ref`, `paths`, `environment`) are `Option`.
/// When a predicate references a scope field that is `None`, evaluation
/// returns `Indeterminate` in forensic mode or `Deny` in strict mode.
#[derive(Debug, Clone)]
pub struct EvalContext {
    // ── Time ─────────────────────────────────────────────────────────
    /// Current time for expiry/freshness checks.
    pub now: DateTime<Utc>,

    // ── Signer Type ───────────────────────────────────────────────────
    /// The type of entity that produced this signature (human, agent, workload).
    pub signer_type: Option<SignerType>,

    // ── Assurance Level ─────────────────────────────────────────────
    /// Cryptographic assurance level of the platform identity claim.
    pub assurance_level: Option<AssuranceLevel>,

    // ── Attestation Identity ─────────────────────────────────────────
    /// The DID of the attestation issuer.
    pub issuer: CanonicalDid,
    /// The DID of the attestation subject.
    pub subject: CanonicalDid,
    /// Whether the attestation has been revoked.
    pub revoked: bool,
    /// When the attestation expires (if set).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the attestation was issued (if set).
    pub timestamp: Option<DateTime<Utc>>,

    // ── Capabilities & Role ──────────────────────────────────────────
    /// Capabilities granted by the attestation.
    pub capabilities: Vec<CanonicalCapability>,
    /// Role assigned to the subject (if any).
    pub role: Option<String>,

    // ── Delegation ───────────────────────────────────────────────────
    /// The DID that delegated this attestation (if delegated).
    pub delegated_by: Option<CanonicalDid>,
    /// Depth in the delegation chain (0 = root attestation).
    pub chain_depth: u32,

    // ── Scope (typed, first-class) ───────────────────────────────────
    /// Repository identifier (e.g., "org/repo").
    pub repo: Option<String>,
    /// Git ref (e.g., "refs/heads/main").
    pub git_ref: Option<String>,
    /// Paths being accessed.
    pub paths: Vec<String>,
    /// Environment (e.g., "production", "staging").
    pub environment: Option<String>,

    // ── Workload Claims ──────────────────────────────────────────────
    /// Workload identity issuer (e.g., for OIDC tokens).
    pub workload_issuer: Option<CanonicalDid>,
    /// Workload claims from the token.
    pub workload_claims: HashMap<String, String>,

    // ── Escape Hatch (flat string attrs) ─────────────────────────────
    /// Custom attributes for extension points.
    pub attrs: HashMap<String, String>,

    // ── Approval Attestations ────────────────────────────────────────
    /// Submitted approval attestations for ApprovalGate checking.
    pub approvals: Vec<ApprovalAttestation>,

    // ── Audit Metadata ────────────────────────────────────────────────
    /// Opaque gateway metadata (source IP, request ID) for audit logging.
    /// Not used in policy evaluation — carried through for audit trail.
    pub audit_metadata: HashMap<String, Value>,
}

impl EvalContext {
    /// Create a new evaluation context with required fields.
    ///
    /// Optional fields are initialized to their default values.
    pub fn new(now: DateTime<Utc>, issuer: CanonicalDid, subject: CanonicalDid) -> Self {
        Self {
            now,
            signer_type: None,
            assurance_level: None,
            issuer,
            subject,
            revoked: false,
            expires_at: None,
            timestamp: None,
            capabilities: Vec::new(),
            role: None,
            delegated_by: None,
            chain_depth: 0,
            repo: None,
            git_ref: None,
            paths: Vec::new(),
            environment: None,
            workload_issuer: None,
            workload_claims: HashMap::new(),
            attrs: HashMap::new(),
            approvals: Vec::new(),
            audit_metadata: HashMap::new(),
        }
    }

    /// Create a new evaluation context from string DIDs.
    ///
    /// Returns an error if either DID fails to parse.
    ///
    /// # Errors
    ///
    /// Returns the DID parse error if issuer or subject is invalid.
    pub fn try_from_strings(
        now: DateTime<Utc>,
        issuer: &str,
        subject: &str,
    ) -> Result<Self, crate::types::DidParseError> {
        let issuer = CanonicalDid::parse(issuer)?;
        let subject = CanonicalDid::parse(subject)?;
        Ok(Self::new(now, issuer, subject))
    }

    /// Set the signer type.
    pub fn signer_type(mut self, signer_type: SignerType) -> Self {
        self.signer_type = Some(signer_type);
        self
    }

    /// Set the assurance level.
    pub fn assurance_level(mut self, level: AssuranceLevel) -> Self {
        self.assurance_level = Some(level);
        self
    }

    /// Set whether the attestation is revoked.
    pub fn revoked(mut self, revoked: bool) -> Self {
        self.revoked = revoked;
        self
    }

    /// Set the expiry time.
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set the issuance timestamp.
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Add a capability.
    pub fn capability(mut self, cap: CanonicalCapability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Add multiple capabilities.
    pub fn capabilities(mut self, caps: impl IntoIterator<Item = CanonicalCapability>) -> Self {
        self.capabilities.extend(caps);
        self
    }

    /// Set the role.
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Set the delegator.
    pub fn delegated_by(mut self, delegator: CanonicalDid) -> Self {
        self.delegated_by = Some(delegator);
        self
    }

    /// Set the chain depth.
    pub fn chain_depth(mut self, depth: u32) -> Self {
        self.chain_depth = depth;
        self
    }

    /// Set the repository.
    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    /// Set the git ref.
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_ref = Some(git_ref.into());
        self
    }

    /// Add paths being accessed.
    pub fn paths(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.paths.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Set the environment.
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.environment = Some(env.into());
        self
    }

    /// Set the workload issuer.
    pub fn workload_issuer(mut self, issuer: CanonicalDid) -> Self {
        self.workload_issuer = Some(issuer);
        self
    }

    /// Add a workload claim.
    pub fn workload_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.workload_claims.insert(key.into(), value.into());
        self
    }

    /// Add a custom attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Add an approval attestation.
    pub fn approval(mut self, attestation: ApprovalAttestation) -> Self {
        self.approvals.push(attestation);
        self
    }

    /// Add an audit metadata entry.
    pub fn audit_meta(mut self, key: impl Into<String>, value: Value) -> Self {
        self.audit_metadata.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    fn did(s: &str) -> CanonicalDid {
        CanonicalDid::parse(s).unwrap()
    }

    fn cap(s: &str) -> CanonicalCapability {
        CanonicalCapability::parse(s).unwrap()
    }

    #[test]
    fn new_context() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"));

        assert_eq!(ctx.issuer.as_str(), "did:keri:issuer");
        assert_eq!(ctx.subject.as_str(), "did:keri:subject");
        assert!(!ctx.revoked);
        assert!(ctx.expires_at.is_none());
        assert!(ctx.capabilities.is_empty());
    }

    #[test]
    fn builder_chain() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .revoked(false)
            .capability(cap("sign_commit"))
            .role("admin")
            .repo("org/repo")
            .git_ref("refs/heads/main")
            .environment("production")
            .chain_depth(1);

        assert_eq!(ctx.capabilities.len(), 1);
        assert_eq!(ctx.role, Some("admin".to_string()));
        assert_eq!(ctx.repo, Some("org/repo".to_string()));
        assert_eq!(ctx.git_ref, Some("refs/heads/main".to_string()));
        assert_eq!(ctx.environment, Some("production".to_string()));
        assert_eq!(ctx.chain_depth, 1);
    }

    #[test]
    fn multiple_capabilities() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .capabilities([cap("read"), cap("write")]);

        assert_eq!(ctx.capabilities.len(), 2);
    }

    #[test]
    fn paths() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .paths(["src/lib.rs", "src/main.rs"]);

        assert_eq!(ctx.paths.len(), 2);
        assert_eq!(ctx.paths[0], "src/lib.rs");
    }

    #[test]
    fn workload_claims() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .workload_claim("repo", "org/repo")
            .workload_claim("actor", "user");

        assert_eq!(
            ctx.workload_claims.get("repo"),
            Some(&"org/repo".to_string())
        );
        assert_eq!(ctx.workload_claims.get("actor"), Some(&"user".to_string()));
    }

    #[test]
    fn attrs() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .attr("custom_key", "custom_value");

        assert_eq!(
            ctx.attrs.get("custom_key"),
            Some(&"custom_value".to_string())
        );
    }

    #[test]
    fn delegated_by() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .delegated_by(did("did:keri:delegator"));

        assert_eq!(
            ctx.delegated_by.as_ref().map(|d| d.as_str()),
            Some("did:keri:delegator")
        );
    }
}
