//! Policy evaluation functions.
//!
//! Two evaluation functions:
//! - `evaluate_strict`: Returns `Allow` or `Deny` only. `Indeterminate` → `Deny`.
//! - `evaluate3`: Returns `Allow`, `Deny`, or `Indeterminate`.
//!
//! Use `evaluate_strict` at enforcement points (CI gates, deploy admission).
//! Use `evaluate3` for audit logging, retroactive analysis, policy simulation.

use crate::compiled::{CompiledExpr, CompiledPolicy};
use crate::context::EvalContext;
use crate::decision::{Decision, Outcome, ReasonCode};
use crate::glob::glob_match;
use crate::types::SignerType;

/// Strict evaluation: returns `Allow` or `Deny` only.
///
/// `Indeterminate` is collapsed to `Deny` with the original reason code.
/// Use this at enforcement points (CI gates, deploy admission, runtime checks).
pub fn evaluate_strict(policy: &CompiledPolicy, ctx: &EvalContext) -> Decision {
    let decision = evaluate3(policy, ctx);
    match decision.outcome {
        Outcome::Indeterminate => Decision::deny(
            decision.reason,
            format!(
                "strict mode: indeterminate treated as deny ({})",
                decision.message
            ),
        )
        .with_policy_hash(*policy.source_hash()),
        _ => decision,
    }
}

/// Three-valued evaluation: returns `Allow`, `Deny`, or `Indeterminate`.
///
/// Use this for audit logging, retroactive analysis, policy simulation,
/// and any context where "unknown" is meaningful.
pub fn evaluate3(policy: &CompiledPolicy, ctx: &EvalContext) -> Decision {
    let mut decision = eval_expr(policy.expr(), ctx);
    decision.policy_hash = Some(*policy.source_hash());
    decision
}

fn eval_expr(expr: &CompiledExpr, ctx: &EvalContext) -> Decision {
    match expr {
        CompiledExpr::True => Decision::allow(ReasonCode::Unconditional, "unconditional allow"),
        CompiledExpr::False => Decision::deny(ReasonCode::Unconditional, "unconditional deny"),

        CompiledExpr::And(children) => {
            let mut saw_indeterminate: Option<Decision> = None;
            for child in children {
                let result = eval_expr(child, ctx);
                match result.outcome {
                    Outcome::Deny => return result,
                    Outcome::Indeterminate if saw_indeterminate.is_none() => {
                        saw_indeterminate = Some(result);
                    }
                    _ => {}
                }
            }
            match saw_indeterminate {
                Some(d) => d,
                None => Decision::allow(ReasonCode::CombinatorResult, "all conditions passed"),
            }
        }

        CompiledExpr::Or(children) => {
            let mut saw_indeterminate: Option<Decision> = None;
            for child in children {
                let result = eval_expr(child, ctx);
                match result.outcome {
                    Outcome::Allow => return result,
                    Outcome::Indeterminate if saw_indeterminate.is_none() => {
                        saw_indeterminate = Some(result);
                    }
                    _ => {}
                }
            }
            match saw_indeterminate {
                Some(d) => d,
                None => Decision::deny(ReasonCode::CombinatorResult, "no conditions passed"),
            }
        }

        CompiledExpr::Not(inner) => {
            let result = eval_expr(inner, ctx);
            match result.outcome {
                Outcome::Allow => Decision::deny(
                    ReasonCode::CombinatorResult,
                    format!("NOT({})", result.message),
                ),
                Outcome::Deny => Decision::allow(
                    ReasonCode::CombinatorResult,
                    format!("NOT({})", result.message),
                ),
                Outcome::Indeterminate => result,
            }
        }

        CompiledExpr::HasCapability(cap) => {
            if ctx.capabilities.iter().any(|c| c == cap) {
                Decision::allow(ReasonCode::CapabilityPresent, format!("has '{}'", cap))
            } else {
                Decision::deny(ReasonCode::CapabilityMissing, format!("missing '{}'", cap))
            }
        }

        CompiledExpr::HasAllCapabilities(caps) => {
            let missing: Vec<_> = caps
                .iter()
                .filter(|c| !ctx.capabilities.contains(c))
                .collect();
            if missing.is_empty() {
                Decision::allow(
                    ReasonCode::CapabilityPresent,
                    "has all required capabilities",
                )
            } else {
                Decision::deny(
                    ReasonCode::CapabilityMissing,
                    format!(
                        "missing: {}",
                        missing
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            }
        }

        CompiledExpr::HasAnyCapability(caps) => {
            if caps.iter().any(|c| ctx.capabilities.contains(c)) {
                Decision::allow(
                    ReasonCode::CapabilityPresent,
                    "has at least one required capability",
                )
            } else {
                Decision::deny(
                    ReasonCode::CapabilityMissing,
                    "has none of the required capabilities",
                )
            }
        }

        CompiledExpr::IssuerIs(expected) => {
            if ctx.issuer == *expected {
                Decision::allow(ReasonCode::IssuerMatch, format!("issuer is {}", expected))
            } else {
                Decision::deny(
                    ReasonCode::IssuerMismatch,
                    format!("issuer {} != {}", ctx.issuer, expected),
                )
            }
        }

        CompiledExpr::IssuerIn(allowed) => {
            if allowed.contains(&ctx.issuer) {
                Decision::allow(
                    ReasonCode::IssuerMatch,
                    format!("issuer {} in allowed set", ctx.issuer),
                )
            } else {
                Decision::deny(
                    ReasonCode::IssuerMismatch,
                    format!("issuer {} not in allowed set", ctx.issuer),
                )
            }
        }

        CompiledExpr::SubjectIs(expected) => {
            if ctx.subject == *expected {
                Decision::allow(ReasonCode::IssuerMatch, format!("subject is {}", expected))
            } else {
                Decision::deny(
                    ReasonCode::IssuerMismatch,
                    format!("subject {} != {}", ctx.subject, expected),
                )
            }
        }

        CompiledExpr::DelegatedBy(expected) => match &ctx.delegated_by {
            Some(d) if d == expected => Decision::allow(
                ReasonCode::IssuerMatch,
                format!("delegated by {}", expected),
            ),
            Some(d) => Decision::deny(
                ReasonCode::DelegationMismatch,
                format!("delegated by {}, expected {}", d, expected),
            ),
            None => Decision::deny(ReasonCode::DelegationMismatch, "no delegator present"),
        },

        CompiledExpr::NotRevoked => {
            if !ctx.revoked {
                Decision::allow(ReasonCode::AllChecksPassed, "not revoked")
            } else {
                Decision::deny(ReasonCode::Revoked, "attestation is revoked")
            }
        }

        CompiledExpr::NotExpired => match ctx.expires_at {
            Some(exp) if exp > ctx.now => {
                Decision::allow(ReasonCode::AllChecksPassed, format!("expires {}", exp))
            }
            Some(exp) => Decision::deny(ReasonCode::Expired, format!("expired at {}", exp)),
            None => Decision::allow(ReasonCode::AllChecksPassed, "no expiry set"),
        },

        CompiledExpr::ExpiresAfter(min_seconds) => match ctx.expires_at {
            Some(exp) => {
                let remaining = (exp - ctx.now).num_seconds();
                if remaining >= *min_seconds {
                    Decision::allow(
                        ReasonCode::AllChecksPassed,
                        format!("{}s remaining", remaining),
                    )
                } else {
                    Decision::deny(
                        ReasonCode::InsufficientTtl,
                        format!("{}s remaining, need {}s", remaining, min_seconds),
                    )
                }
            }
            None => {
                Decision::indeterminate(ReasonCode::MissingField, "no expiry set, cannot check TTL")
            }
        },

        CompiledExpr::IssuedWithin(max_seconds) => match ctx.timestamp {
            Some(ts) => {
                let age = (ctx.now - ts).num_seconds();
                if age <= *max_seconds {
                    Decision::allow(ReasonCode::AllChecksPassed, format!("issued {}s ago", age))
                } else {
                    Decision::deny(
                        ReasonCode::IssuedTooLongAgo,
                        format!("issued {}s ago, max {}s", age, max_seconds),
                    )
                }
            }
            None => {
                Decision::indeterminate(ReasonCode::MissingField, "no timestamp on attestation")
            }
        },

        CompiledExpr::RoleIs(expected) => match &ctx.role {
            Some(r) if r == expected => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("role is '{}'", expected),
            ),
            Some(r) => Decision::deny(
                ReasonCode::RoleMismatch,
                format!("role '{}' != '{}'", r, expected),
            ),
            None => Decision::deny(ReasonCode::RoleMismatch, "no role set"),
        },

        CompiledExpr::RoleIn(allowed) => match &ctx.role {
            Some(r) if allowed.contains(r) => {
                Decision::allow(ReasonCode::AllChecksPassed, format!("role '{}' allowed", r))
            }
            Some(r) => Decision::deny(
                ReasonCode::RoleMismatch,
                format!("role '{}' not allowed", r),
            ),
            None => Decision::deny(ReasonCode::RoleMismatch, "no role set"),
        },

        // ── Scope predicates ─────────────────────────────────────────
        CompiledExpr::RepoIs(expected) => match &ctx.repo {
            Some(r) if r == expected => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("repo is '{}'", expected),
            ),
            Some(r) => Decision::deny(
                ReasonCode::ScopeMismatch,
                format!("repo '{}' != '{}'", r, expected),
            ),
            None => Decision::indeterminate(ReasonCode::MissingField, "no repo in context"),
        },

        CompiledExpr::RepoIn(allowed) => match &ctx.repo {
            Some(r) if allowed.contains(r) => {
                Decision::allow(ReasonCode::AllChecksPassed, format!("repo '{}' allowed", r))
            }
            Some(r) => Decision::deny(
                ReasonCode::ScopeMismatch,
                format!("repo '{}' not allowed", r),
            ),
            None => Decision::indeterminate(ReasonCode::MissingField, "no repo in context"),
        },

        CompiledExpr::RefMatches(pattern) => match &ctx.git_ref {
            Some(r) => {
                if glob_match(pattern, r) {
                    Decision::allow(
                        ReasonCode::AllChecksPassed,
                        format!("ref '{}' matches '{}'", r, pattern),
                    )
                } else {
                    Decision::deny(
                        ReasonCode::ScopeMismatch,
                        format!("ref '{}' does not match '{}'", r, pattern),
                    )
                }
            }
            None => Decision::indeterminate(ReasonCode::MissingField, "no ref in context"),
        },

        CompiledExpr::PathAllowed(patterns) => {
            if ctx.paths.is_empty() {
                return Decision::indeterminate(ReasonCode::MissingField, "no paths in context");
            }
            for path in &ctx.paths {
                if !patterns.iter().any(|p| glob_match(p, path)) {
                    return Decision::deny(
                        ReasonCode::ScopeMismatch,
                        format!("path '{}' not matched by any allowed pattern", path),
                    );
                }
            }
            Decision::allow(ReasonCode::AllChecksPassed, "all paths matched")
        }

        CompiledExpr::EnvIs(expected) => match &ctx.environment {
            Some(e) if e == expected => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("env is '{}'", expected),
            ),
            Some(e) => Decision::deny(
                ReasonCode::ScopeMismatch,
                format!("env '{}' != '{}'", e, expected),
            ),
            None => Decision::indeterminate(ReasonCode::MissingField, "no environment in context"),
        },

        CompiledExpr::EnvIn(allowed) => match &ctx.environment {
            Some(e) if allowed.contains(e) => {
                Decision::allow(ReasonCode::AllChecksPassed, format!("env '{}' allowed", e))
            }
            Some(e) => Decision::deny(
                ReasonCode::ScopeMismatch,
                format!("env '{}' not allowed", e),
            ),
            None => Decision::indeterminate(ReasonCode::MissingField, "no environment in context"),
        },

        // ── Workload ─────────────────────────────────────────────────
        CompiledExpr::WorkloadIssuerIs(expected) => match &ctx.workload_issuer {
            Some(i) if i == expected => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("workload issuer is {}", expected),
            ),
            Some(i) => Decision::deny(
                ReasonCode::WorkloadMismatch,
                format!("workload issuer {} != {}", i, expected),
            ),
            None => Decision::indeterminate(ReasonCode::MissingField, "no workload issuer"),
        },

        CompiledExpr::WorkloadClaimEquals { key, value } => match ctx.workload_claims.get(key) {
            Some(v) if v == value => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("workload.{} = '{}'", key, value),
            ),
            Some(v) => Decision::deny(
                ReasonCode::WorkloadMismatch,
                format!("workload.{} = '{}', expected '{}'", key, v, value),
            ),
            None => Decision::indeterminate(
                ReasonCode::MissingField,
                format!("workload claim '{}' not present", key),
            ),
        },

        // ── Signer Type ──────────────────────────────────────────────
        CompiledExpr::IsAgent => match &ctx.signer_type {
            Some(SignerType::Agent) => {
                Decision::allow(ReasonCode::SignerTypeMatch, "signer is agent")
            }
            Some(other) => Decision::deny(
                ReasonCode::SignerTypeMismatch,
                format!("signer is {:?}, expected Agent", other),
            ),
            None => Decision::deny(ReasonCode::SignerTypeMismatch, "signer type not set"),
        },

        CompiledExpr::IsHuman => match &ctx.signer_type {
            Some(SignerType::Human) => {
                Decision::allow(ReasonCode::SignerTypeMatch, "signer is human")
            }
            Some(other) => Decision::deny(
                ReasonCode::SignerTypeMismatch,
                format!("signer is {:?}, expected Human", other),
            ),
            None => Decision::deny(ReasonCode::SignerTypeMismatch, "signer type not set"),
        },

        CompiledExpr::IsWorkload => match &ctx.signer_type {
            Some(SignerType::Workload) => {
                Decision::allow(ReasonCode::SignerTypeMatch, "signer is workload")
            }
            Some(other) => Decision::deny(
                ReasonCode::SignerTypeMismatch,
                format!("signer is {:?}, expected Workload", other),
            ),
            None => Decision::deny(ReasonCode::SignerTypeMismatch, "signer type not set"),
        },

        // ── Chain ────────────────────────────────────────────────────
        CompiledExpr::MaxChainDepth(max) => {
            if ctx.chain_depth <= *max {
                Decision::allow(
                    ReasonCode::AllChecksPassed,
                    format!("chain depth {} <= {}", ctx.chain_depth, max),
                )
            } else {
                Decision::deny(
                    ReasonCode::ChainTooDeep,
                    format!("chain depth {} > {}", ctx.chain_depth, max),
                )
            }
        }

        // ── Escape hatch ─────────────────────────────────────────────
        CompiledExpr::AttrEquals { key, value } => match ctx.attrs.get(key) {
            Some(v) if v == value => Decision::allow(
                ReasonCode::AllChecksPassed,
                format!("attr.{} = '{}'", key, value),
            ),
            Some(v) => Decision::deny(
                ReasonCode::AttrMismatch,
                format!("attr.{} = '{}', expected '{}'", key, v, value),
            ),
            None => Decision::indeterminate(
                ReasonCode::MissingField,
                format!("attr '{}' not present", key),
            ),
        },

        CompiledExpr::AttrIn { key, values } => match ctx.attrs.get(key) {
            Some(v) if values.contains(v) => {
                Decision::allow(ReasonCode::AllChecksPassed, format!("attr.{} in set", key))
            }
            Some(v) => Decision::deny(
                ReasonCode::AttrMismatch,
                format!("attr.{} = '{}' not in set", key, v),
            ),
            None => Decision::indeterminate(
                ReasonCode::MissingField,
                format!("attr '{}' not present", key),
            ),
        },
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::compile::compile;
    use crate::expr::Expr;
    use crate::types::{CanonicalCapability, CanonicalDid};
    use chrono::{Duration, Utc};

    fn did(s: &str) -> CanonicalDid {
        CanonicalDid::parse(s).unwrap()
    }

    fn cap(s: &str) -> CanonicalCapability {
        CanonicalCapability::parse(s).unwrap()
    }

    fn base_ctx() -> EvalContext {
        EvalContext::new(Utc::now(), did("did:keri:issuer"), did("did:keri:subject"))
    }

    #[test]
    fn eval_true() {
        let policy = compile(&Expr::True).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_false() {
        let policy = compile(&Expr::False).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_has_capability_present() {
        let policy = compile(&Expr::HasCapability("sign_commit".into())).unwrap();
        let ctx = base_ctx().capability(cap("sign_commit"));
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_has_capability_missing() {
        let policy = compile(&Expr::HasCapability("sign_commit".into())).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_and_all_pass() {
        let policy = compile(&Expr::And(vec![Expr::True, Expr::True])).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_and_one_fails() {
        let policy = compile(&Expr::And(vec![Expr::True, Expr::False])).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_or_one_passes() {
        let policy = compile(&Expr::Or(vec![Expr::False, Expr::True])).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_or_all_fail() {
        let policy = compile(&Expr::Or(vec![Expr::False, Expr::False])).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_not_inverts() {
        let policy = compile(&Expr::Not(Box::new(Expr::True))).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());

        let policy = compile(&Expr::Not(Box::new(Expr::False))).unwrap();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_issuer_is_match() {
        let policy = compile(&Expr::IssuerIs("did:keri:issuer".into())).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn eval_issuer_is_mismatch() {
        let policy = compile(&Expr::IssuerIs("did:keri:other".into())).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_not_revoked() {
        let policy = compile(&Expr::NotRevoked).unwrap();

        let ctx = base_ctx().revoked(false);
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().revoked(true);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_not_expired() {
        let policy = compile(&Expr::NotExpired).unwrap();
        let now = Utc::now();

        // Not expired
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .expires_at(now + Duration::hours(1));
        assert!(evaluate3(&policy, &ctx).is_allowed());

        // Expired
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .expires_at(now - Duration::hours(1));
        assert!(evaluate3(&policy, &ctx).is_denied());

        // No expiry
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"));
        assert!(evaluate3(&policy, &ctx).is_allowed());
    }

    #[test]
    fn eval_repo_is() {
        let policy = compile(&Expr::RepoIs("org/repo".into())).unwrap();

        let ctx = base_ctx().repo("org/repo");
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().repo("other/repo");
        assert!(evaluate3(&policy, &ctx).is_denied());

        // Missing repo → indeterminate
        let ctx = base_ctx();
        assert!(evaluate3(&policy, &ctx).is_indeterminate());
    }

    #[test]
    fn eval_ref_matches() {
        let policy = compile(&Expr::RefMatches("refs/heads/*".into())).unwrap();

        let ctx = base_ctx().git_ref("refs/heads/main");
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().git_ref("refs/tags/v1");
        assert!(evaluate3(&policy, &ctx).is_denied());

        // Missing ref → indeterminate
        let ctx = base_ctx();
        assert!(evaluate3(&policy, &ctx).is_indeterminate());
    }

    #[test]
    fn eval_strict_converts_indeterminate_to_deny() {
        let policy = compile(&Expr::RepoIs("org/repo".into())).unwrap();
        let ctx = base_ctx(); // No repo set

        let decision = evaluate3(&policy, &ctx);
        assert!(decision.is_indeterminate());

        let decision = evaluate_strict(&policy, &ctx);
        assert!(decision.is_denied());
    }

    #[test]
    fn eval_chain_depth() {
        let policy = compile(&Expr::MaxChainDepth(2)).unwrap();

        let ctx = base_ctx().chain_depth(1);
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().chain_depth(2);
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().chain_depth(3);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_attr_equals() {
        let policy = compile(&Expr::AttrEquals {
            key: "team".into(),
            value: "platform".into(),
        })
        .unwrap();

        let ctx = base_ctx().attr("team", "platform");
        assert!(evaluate3(&policy, &ctx).is_allowed());

        let ctx = base_ctx().attr("team", "other");
        assert!(evaluate3(&policy, &ctx).is_denied());

        // Missing attr → indeterminate
        let ctx = base_ctx();
        assert!(evaluate3(&policy, &ctx).is_indeterminate());
    }

    #[test]
    fn decision_has_policy_hash() {
        let policy = compile(&Expr::True).unwrap();
        let ctx = base_ctx();
        let decision = evaluate3(&policy, &ctx);
        assert!(decision.policy_hash.is_some());
        assert_eq!(decision.policy_hash.unwrap(), *policy.source_hash());
    }

    #[test]
    fn eval_complex_policy() {
        // (NotRevoked AND NotExpired AND (HasCapability("admin") OR HasCapability("write")))
        let expr = Expr::And(vec![
            Expr::NotRevoked,
            Expr::NotExpired,
            Expr::Or(vec![
                Expr::HasCapability("admin".into()),
                Expr::HasCapability("write".into()),
            ]),
        ]);
        let policy = compile(&expr).unwrap();
        let now = Utc::now();

        // Has admin capability
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .capability(cap("admin"))
            .expires_at(now + Duration::hours(1));
        assert!(evaluate3(&policy, &ctx).is_allowed());

        // Has write capability
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .capability(cap("write"))
            .expires_at(now + Duration::hours(1));
        assert!(evaluate3(&policy, &ctx).is_allowed());

        // Missing both capabilities
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .capability(cap("read"))
            .expires_at(now + Duration::hours(1));
        assert!(evaluate3(&policy, &ctx).is_denied());

        // Revoked
        let ctx = EvalContext::new(now, did("did:keri:i"), did("did:keri:s"))
            .capability(cap("admin"))
            .expires_at(now + Duration::hours(1))
            .revoked(true);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    // ── Signer Type tests ───────────────────────────────────────────

    #[test]
    fn eval_is_human_match() {
        let policy = compile(&Expr::IsHuman).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Human);
        assert!(evaluate3(&policy, &ctx).is_allowed());
    }

    #[test]
    fn eval_is_human_mismatch() {
        let policy = compile(&Expr::IsHuman).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Agent);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_is_human_none() {
        let policy = compile(&Expr::IsHuman).unwrap();
        let ctx = base_ctx();
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_is_agent_match() {
        let policy = compile(&Expr::IsAgent).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Agent);
        assert!(evaluate3(&policy, &ctx).is_allowed());
    }

    #[test]
    fn eval_is_agent_mismatch() {
        let policy = compile(&Expr::IsAgent).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Human);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_is_workload_match() {
        let policy = compile(&Expr::IsWorkload).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Workload);
        assert!(evaluate3(&policy, &ctx).is_allowed());
    }

    #[test]
    fn eval_is_workload_mismatch() {
        let policy = compile(&Expr::IsWorkload).unwrap();
        let ctx = base_ctx().signer_type(crate::types::SignerType::Human);
        assert!(evaluate3(&policy, &ctx).is_denied());
    }

    #[test]
    fn eval_signer_type_in_complex_policy() {
        // Agent must have sign_commit capability AND not be revoked
        let expr = Expr::And(vec![
            Expr::IsAgent,
            Expr::HasCapability("sign_commit".into()),
            Expr::NotRevoked,
        ]);
        let policy = compile(&expr).unwrap();

        // Agent with capability — allowed
        let ctx = base_ctx()
            .signer_type(crate::types::SignerType::Agent)
            .capability(cap("sign_commit"));
        assert!(evaluate3(&policy, &ctx).is_allowed());

        // Human with capability — denied (not agent)
        let ctx = base_ctx()
            .signer_type(crate::types::SignerType::Human)
            .capability(cap("sign_commit"));
        assert!(evaluate3(&policy, &ctx).is_denied());
    }
}
