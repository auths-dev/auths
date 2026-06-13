//! OIDC-subject policy — the org's side of the keyless CI exchange.
//!
//! An org that wants keyless CI signing never hands a key to the runner.
//! Instead it states, ahead of time, WHICH workload identity it trusts to
//! sign: the OIDC issuer, the repository, and (optionally) the exact
//! workflow. At verify time the verifier JOINS the artifact's signed
//! [`OidcBinding`](crate::core::OidcBinding) — the claims the signer
//! validated against the issuer's JWKS while the token was live — against
//! that policy. The org key is never reachable from CI; the policy is the
//! delegation.
//!
//! Parse, don't validate: [`OidcSubjectPolicy::parse`] is the only
//! constructor, so a policy in hand is always well-formed (non-empty issuer
//! and repository). The join is fail-closed: a missing binding, missing
//! claim, or any mismatch is an error, never a pass.

use serde::{Deserialize, Serialize};

use crate::core::OidcBinding;

/// The OIDC workload identity an org trusts to sign its artifacts.
///
/// Wire form (JSON):
/// ```json
/// {
///   "issuer": "https://token.actions.githubusercontent.com",
///   "repository": "acme/widget",
///   "workflow_ref": "acme/widget/.github/workflows/release.yml"
/// }
/// ```
///
/// `workflow_ref` may pin the exact ref (`...release.yml@refs/tags/v1.0`) or
/// just the workflow path (no `@`), which then matches any ref of that file.
/// Omitting it trusts every workflow in the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSubjectPolicy {
    /// The OIDC issuer the org trusts (exact match).
    issuer: String,
    /// The repository whose workloads may sign (exact match).
    repository: String,
    /// Optional workflow pin — exact `path@ref`, or `path` to allow any ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow_ref: Option<String>,
}

/// Why a policy failed to parse or a binding failed to join.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcPolicyError {
    /// The policy JSON did not parse or had empty required fields.
    #[error("invalid OIDC policy: {0}")]
    InvalidPolicy(String),
    /// The attestation carries no OIDC binding to join.
    #[error("attestation carries no OIDC binding — signer presented no verified OIDC identity")]
    MissingBinding,
    /// The binding lacks a claim the policy constrains.
    #[error("OIDC binding lacks the '{0}' claim the policy requires")]
    MissingClaim(&'static str),
    /// A claim did not match the policy.
    #[error("OIDC {claim} mismatch: policy trusts '{expected}', binding presented '{got}'")]
    Mismatch {
        /// Which claim mismatched.
        claim: &'static str,
        /// What the policy trusts.
        expected: String,
        /// What the binding presented.
        got: String,
    },
}

/// Proof that a binding satisfied a policy — only [`OidcSubjectPolicy::join`]
/// constructs it, so holding one means the join passed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OidcPolicyJoin {
    /// The issuer both sides agreed on.
    pub issuer: String,
    /// The repository both sides agreed on.
    pub repository: String,
    /// The workflow_ref the binding presented (when the policy pinned one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,
    /// The token subject, for audit display.
    pub subject: String,
}

impl OidcSubjectPolicy {
    /// Parse a policy from its JSON wire form. The only constructor.
    pub fn parse(json: &str) -> Result<Self, OidcPolicyError> {
        let policy: Self = serde_json::from_str(json)
            .map_err(|e| OidcPolicyError::InvalidPolicy(e.to_string()))?;
        if policy.issuer.trim().is_empty() {
            return Err(OidcPolicyError::InvalidPolicy("issuer is empty".into()));
        }
        if policy.repository.trim().is_empty() {
            return Err(OidcPolicyError::InvalidPolicy("repository is empty".into()));
        }
        if let Some(wf) = &policy.workflow_ref
            && wf.trim().is_empty()
        {
            return Err(OidcPolicyError::InvalidPolicy(
                "workflow_ref is empty".into(),
            ));
        }
        Ok(policy)
    }

    /// The issuer this policy trusts.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The repository this policy trusts.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// JOIN a signed OIDC binding against this policy, fail-closed.
    ///
    /// Checks, in order: issuer (exact), repository (exact, from the
    /// platform-normalized claims), and — when the policy pins one —
    /// workflow_ref (exact `path@ref`, or path-only when the policy value
    /// carries no `@`).
    ///
    /// Args:
    /// * `binding`: The signature-covered OIDC binding from a verified
    ///   attestation. Callers must only pass bindings from attestations whose
    ///   signatures verified — the join trusts the claims, not the envelope.
    pub fn join(&self, binding: &OidcBinding) -> Result<OidcPolicyJoin, OidcPolicyError> {
        if binding.issuer != self.issuer {
            return Err(OidcPolicyError::Mismatch {
                claim: "issuer",
                expected: self.issuer.clone(),
                got: binding.issuer.clone(),
            });
        }

        let claims = binding
            .normalized_claims
            .as_ref()
            .ok_or(OidcPolicyError::MissingClaim("repository"))?;

        let repository = claims
            .get("repository")
            .and_then(|v| v.as_str())
            .ok_or(OidcPolicyError::MissingClaim("repository"))?;
        if repository != self.repository {
            return Err(OidcPolicyError::Mismatch {
                claim: "repository",
                expected: self.repository.clone(),
                got: repository.to_string(),
            });
        }

        let mut joined_workflow_ref = None;
        if let Some(pinned) = &self.workflow_ref {
            let presented = claims
                .get("workflow_ref")
                .and_then(|v| v.as_str())
                .ok_or(OidcPolicyError::MissingClaim("workflow_ref"))?;
            let presented_path = presented.split('@').next().unwrap_or(presented);
            let matches = if pinned.contains('@') {
                presented == pinned
            } else {
                presented_path == pinned
            };
            if !matches {
                return Err(OidcPolicyError::Mismatch {
                    claim: "workflow_ref",
                    expected: pinned.clone(),
                    got: presented.to_string(),
                });
            }
            joined_workflow_ref = Some(presented.to_string());
        }

        Ok(OidcPolicyJoin {
            issuer: self.issuer.clone(),
            repository: self.repository.clone(),
            workflow_ref: joined_workflow_ref,
            subject: binding.subject.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GH_ISSUER: &str = "https://token.actions.githubusercontent.com";

    fn binding(claims: serde_json::Value) -> OidcBinding {
        let map = match claims {
            serde_json::Value::Object(m) => m,
            _ => panic!("claims must be an object"),
        };
        OidcBinding {
            issuer: GH_ISSUER.to_string(),
            subject: "repo:acme/widget:ref:refs/tags/v1.0".to_string(),
            audience: "https://github.com/acme".to_string(),
            token_exp: 4_102_444_800,
            platform: Some("github".to_string()),
            jti: Some("jti-1".to_string()),
            normalized_claims: Some(map),
        }
    }

    fn policy(workflow_ref: Option<&str>) -> OidcSubjectPolicy {
        let mut v = serde_json::json!({
            "issuer": GH_ISSUER,
            "repository": "acme/widget",
        });
        if let Some(wf) = workflow_ref {
            v["workflow_ref"] = serde_json::Value::String(wf.to_string());
        }
        OidcSubjectPolicy::parse(&v.to_string()).expect("valid policy")
    }

    #[test]
    fn parse_rejects_empty_issuer() {
        let err = OidcSubjectPolicy::parse(r#"{"issuer":" ","repository":"acme/widget"}"#)
            .expect_err("empty issuer must not parse");
        assert!(matches!(err, OidcPolicyError::InvalidPolicy(_)));
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let err = OidcSubjectPolicy::parse(r#"{"issuer":"i","repository":"r","extra":"smuggled"}"#)
            .expect_err("unknown fields must not parse");
        assert!(matches!(err, OidcPolicyError::InvalidPolicy(_)));
    }

    #[test]
    fn join_passes_on_issuer_and_repository() {
        let b = binding(serde_json::json!({ "repository": "acme/widget" }));
        let join = policy(None).join(&b).expect("join must pass");
        assert_eq!(join.repository, "acme/widget");
        assert_eq!(join.subject, "repo:acme/widget:ref:refs/tags/v1.0");
    }

    #[test]
    fn join_fails_closed_on_issuer_mismatch() {
        let mut b = binding(serde_json::json!({ "repository": "acme/widget" }));
        b.issuer = "https://evil.example".to_string();
        let err = policy(None).join(&b).expect_err("must reject");
        assert!(matches!(
            err,
            OidcPolicyError::Mismatch {
                claim: "issuer",
                ..
            }
        ));
    }

    #[test]
    fn join_fails_closed_on_repository_mismatch() {
        let b = binding(serde_json::json!({ "repository": "attacker/fork" }));
        let err = policy(None).join(&b).expect_err("must reject");
        assert!(matches!(
            err,
            OidcPolicyError::Mismatch {
                claim: "repository",
                ..
            }
        ));
    }

    #[test]
    fn join_fails_closed_on_missing_claims() {
        let mut b = binding(serde_json::json!({ "repository": "acme/widget" }));
        b.normalized_claims = None;
        let err = policy(None).join(&b).expect_err("must reject");
        assert_eq!(err, OidcPolicyError::MissingClaim("repository"));
    }

    #[test]
    fn workflow_path_pin_matches_any_ref() {
        let b = binding(serde_json::json!({
            "repository": "acme/widget",
            "workflow_ref": "acme/widget/.github/workflows/release.yml@refs/tags/v1.0",
        }));
        let join = policy(Some("acme/widget/.github/workflows/release.yml"))
            .join(&b)
            .expect("path pin matches any ref");
        assert_eq!(
            join.workflow_ref.as_deref(),
            Some("acme/widget/.github/workflows/release.yml@refs/tags/v1.0")
        );
    }

    #[test]
    fn workflow_exact_pin_requires_exact_ref() {
        let b = binding(serde_json::json!({
            "repository": "acme/widget",
            "workflow_ref": "acme/widget/.github/workflows/release.yml@refs/heads/main",
        }));
        let err = policy(Some(
            "acme/widget/.github/workflows/release.yml@refs/tags/v1.0",
        ))
        .join(&b)
        .expect_err("exact pin must reject other refs");
        assert!(matches!(
            err,
            OidcPolicyError::Mismatch {
                claim: "workflow_ref",
                ..
            }
        ));
    }

    #[test]
    fn workflow_pin_fails_closed_when_binding_lacks_workflow_ref() {
        let b = binding(serde_json::json!({ "repository": "acme/widget" }));
        let err = policy(Some("acme/widget/.github/workflows/release.yml"))
            .join(&b)
            .expect_err("must reject");
        assert_eq!(err, OidcPolicyError::MissingClaim("workflow_ref"));
    }
}
