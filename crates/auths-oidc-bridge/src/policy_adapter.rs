//! Adapter that converts OIDC bridge claims into policy evaluation contexts.
//!
//! This module bridges the gap between the OIDC bridge's `OidcClaims` and
//! the policy engine's `EvalContext`, enabling workload authorization policies
//! to gate token exchange.

use auths_policy::{CanonicalCapability, CanonicalDid, EvalContext, SignerType};
use chrono::{DateTime, Utc};

use crate::error::BridgeError;
use crate::token::OidcClaims;

/// Converts verified OIDC claims into a policy evaluation context.
///
/// Args:
/// * `claims`: The OIDC claims built from the attestation chain.
/// * `now`: Current wall-clock time (injected, never call `Utc::now()`).
///
/// Usage:
/// ```ignore
/// let ctx = build_eval_context_from_oidc(&claims, now)?;
/// let decision = auths_policy::evaluate_strict(&policy, &ctx);
/// ```
pub fn build_eval_context_from_oidc(
    claims: &OidcClaims,
    now: DateTime<Utc>,
) -> Result<EvalContext, BridgeError> {
    let issuer_did = keri_prefix_to_did(&claims.keri_prefix);
    let issuer = CanonicalDid::parse(&issuer_did).map_err(|e| {
        BridgeError::InvalidRequest(format!("invalid keri_prefix DID '{}': {e}", issuer_did))
    })?;

    let subject = CanonicalDid::parse(&claims.sub).map_err(|e| {
        BridgeError::InvalidRequest(format!("invalid subject DID '{}': {e}", claims.sub))
    })?;

    let mut ctx = EvalContext::new(now, issuer.clone(), subject)
        .signer_type(SignerType::Workload)
        .workload_issuer(issuer);

    for cap_str in &claims.capabilities {
        if let Ok(cap) = CanonicalCapability::parse(cap_str) {
            ctx = ctx.capability(cap);
        }
    }

    if let Some(ref repo) = claims.github_repository {
        ctx = ctx.repo(repo);
    }

    if let Some(ref actor) = claims.github_actor {
        ctx = ctx.workload_claim("github_actor", actor.as_str());
    }

    if let Some(ref provider) = claims.target_provider {
        ctx = ctx.attr("provider", provider.as_str());
    }

    Ok(ctx)
}

fn keri_prefix_to_did(prefix: &str) -> String {
    if prefix.starts_with("did:") {
        prefix.to_string()
    } else {
        format!("did:keri:{prefix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(
        keri_prefix: &str,
        sub: &str,
        capabilities: Vec<&str>,
        github_repo: Option<&str>,
        github_actor: Option<&str>,
        target_provider: Option<&str>,
    ) -> OidcClaims {
        OidcClaims {
            iss: "https://bridge.example.com".to_string(),
            sub: sub.to_string(),
            aud: "https://sts.amazonaws.com".to_string(),
            exp: 9_999_999_999,
            iat: 1_700_000_000,
            jti: "test-jti".to_string(),
            keri_prefix: keri_prefix.to_string(),
            target_provider: target_provider.map(String::from),
            capabilities: capabilities.into_iter().map(String::from).collect(),
            witness_quorum: None,
            github_actor: github_actor.map(String::from),
            github_repository: github_repo.map(String::from),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    #[test]
    fn happy_path_all_fields() {
        let claims = make_claims(
            "EOrg123abc",
            "did:keri:EOrg123abc",
            vec!["sign:commit", "deploy:staging"],
            Some("myorg/myrepo"),
            Some("octocat"),
            Some("aws"),
        );

        let ctx = build_eval_context_from_oidc(&claims, now()).expect("should succeed");

        assert_eq!(ctx.issuer.as_str(), "did:keri:EOrg123abc");
        assert_eq!(ctx.subject.as_str(), "did:keri:EOrg123abc");
        assert_eq!(ctx.signer_type, Some(SignerType::Workload));
        assert_eq!(ctx.capabilities.len(), 2);
        assert_eq!(ctx.repo, Some("myorg/myrepo".to_string()));
        assert_eq!(
            ctx.workload_claims.get("github_actor"),
            Some(&"octocat".to_string())
        );
        assert_eq!(ctx.attrs.get("provider"), Some(&"aws".to_string()));
        assert!(ctx.workload_issuer.is_some());
        assert_eq!(
            ctx.workload_issuer.as_ref().unwrap().as_str(),
            "did:keri:EOrg123abc"
        );
    }

    #[test]
    fn missing_optional_fields() {
        let claims = make_claims(
            "EOrg123abc",
            "did:keri:EOrg123abc",
            vec!["sign:commit"],
            None,
            None,
            None,
        );

        let ctx = build_eval_context_from_oidc(&claims, now()).expect("should succeed");

        assert!(ctx.repo.is_none());
        assert!(ctx.workload_claims.is_empty());
        assert!(ctx.attrs.is_empty());
    }

    #[test]
    fn invalid_keri_prefix_returns_error() {
        let claims = make_claims("", "did:keri:EOrg123abc", vec![], None, None, None);
        let result = build_eval_context_from_oidc(&claims, now());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid keri_prefix"));
    }

    #[test]
    fn empty_capabilities() {
        let claims = make_claims(
            "EOrg123abc",
            "did:keri:EOrg123abc",
            vec![],
            None,
            None,
            None,
        );
        let ctx = build_eval_context_from_oidc(&claims, now()).expect("should succeed");
        assert!(ctx.capabilities.is_empty());
    }

    #[test]
    fn unparseable_capability_skipped() {
        let claims = make_claims(
            "EOrg123abc",
            "did:keri:EOrg123abc",
            vec!["sign:commit", "", "deploy:staging"],
            None,
            None,
            None,
        );

        let ctx = build_eval_context_from_oidc(&claims, now()).expect("should succeed");
        assert_eq!(ctx.capabilities.len(), 2);
    }
}
