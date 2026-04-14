//! Approval attestation types and request hash computation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::compiled::ApprovalScope;
use crate::context::EvalContext;
use crate::types::{CanonicalCapability, CanonicalDid};

/// A submitted approval attestation, checked during ApprovalGate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalAttestation {
    /// Unique nonce for single-use enforcement (UUID v4).
    pub jti: String,
    /// DID of the human who approved.
    pub approver_did: CanonicalDid,
    /// Scoped hash of the original request.
    pub request_hash: auths_verifier::Hash256,
    /// Approval expiry.
    pub expires_at: DateTime<Utc>,
    /// Capabilities that were approved.
    pub approved_capabilities: Vec<CanonicalCapability>,
}

/// Compute the approval request hash for an EvalContext at the given scope.
///
/// Args:
/// * `ctx`: The evaluation context to hash.
/// * `scope`: Controls which fields are included in the hash.
///
/// Usage:
/// ```ignore
/// let hash = compute_request_hash(&ctx, ApprovalScope::Identity);
/// ```
pub fn compute_request_hash(ctx: &EvalContext, scope: ApprovalScope) -> auths_verifier::Hash256 {
    let hash_input = match scope {
        ApprovalScope::Identity => {
            let mut caps: Vec<&str> = ctx.capabilities.iter().map(|c| c.as_str()).collect();
            caps.sort();
            serde_json::json!({
                "capabilities": caps,
                "issuer": ctx.issuer.as_str(),
                "subject": ctx.subject.as_str(),
            })
        }
        ApprovalScope::Scoped => {
            let mut caps: Vec<&str> = ctx.capabilities.iter().map(|c| c.as_str()).collect();
            caps.sort();
            serde_json::json!({
                "capabilities": caps,
                "environment": ctx.environment,
                "issuer": ctx.issuer.as_str(),
                "repo": ctx.repo,
                "subject": ctx.subject.as_str(),
            })
        }
        ApprovalScope::Full => {
            let mut caps: Vec<&str> = ctx.capabilities.iter().map(|c| c.as_str()).collect();
            caps.sort();
            let mut attrs: Vec<(&str, &str)> = ctx
                .attrs
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            attrs.sort();
            let mut workload_claims: Vec<(&str, &str)> = ctx
                .workload_claims
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            workload_claims.sort();
            serde_json::json!({
                "attrs": attrs,
                "capabilities": caps,
                "chain_depth": ctx.chain_depth,
                "delegated_by": ctx.delegated_by.as_ref().map(|d| d.as_str()),
                "environment": ctx.environment,
                "git_ref": ctx.git_ref,
                "issuer": ctx.issuer.as_str(),
                "paths": ctx.paths,
                "repo": ctx.repo,
                "revoked": ctx.revoked,
                "role": ctx.role,
                "subject": ctx.subject.as_str(),
                "workload_claims": workload_claims,
                "workload_issuer": ctx.workload_issuer.as_ref().map(|d| d.as_str()),
            })
        }
    };

    // json-canon style: serde_json::to_string produces deterministic output for our
    // constructed Values (sorted keys via json! macro). For strict RFC 8785 compliance
    // in production, swap to json-canon crate. SHA-256 the canonical bytes.
    let canonical = serde_json::to_string(&hash_input).unwrap_or_default();
    let hash = blake3::hash(canonical.as_bytes());
    auths_verifier::Hash256::new(*hash.as_bytes())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::types::CanonicalDid;
    use chrono::Utc;

    fn did(s: &str) -> CanonicalDid {
        CanonicalDid::parse(s).unwrap()
    }

    #[test]
    fn hash_determinism() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"));
        let hash1 = compute_request_hash(&ctx, ApprovalScope::Identity);
        let hash2 = compute_request_hash(&ctx, ApprovalScope::Identity);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_scope_differentiation() {
        let now = Utc::now();
        let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .repo("org/repo")
            .environment("production");
        let identity_hash = compute_request_hash(&ctx, ApprovalScope::Identity);
        let scoped_hash = compute_request_hash(&ctx, ApprovalScope::Scoped);
        let full_hash = compute_request_hash(&ctx, ApprovalScope::Full);
        assert_ne!(identity_hash, scoped_hash);
        assert_ne!(scoped_hash, full_hash);
        assert_ne!(identity_hash, full_hash);
    }

    #[test]
    fn identity_scope_ignores_repo() {
        let now = Utc::now();
        let ctx1 = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .repo("org/repo-a");
        let ctx2 = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .repo("org/repo-b");
        assert_eq!(
            compute_request_hash(&ctx1, ApprovalScope::Identity),
            compute_request_hash(&ctx2, ApprovalScope::Identity),
        );
    }

    #[test]
    fn scoped_scope_includes_repo() {
        let now = Utc::now();
        let ctx1 = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .repo("org/repo-a");
        let ctx2 = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
            .repo("org/repo-b");
        assert_ne!(
            compute_request_hash(&ctx1, ApprovalScope::Scoped),
            compute_request_hash(&ctx2, ApprovalScope::Scoped),
        );
    }
}
