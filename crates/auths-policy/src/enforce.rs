//! Enforcement wrapper with optional shadow evaluation.
//!
//! This module provides the `enforce()` function for production use with
//! optional canary/shadow policy evaluation. The shadow policy is evaluated
//! in parallel but its decision is not used - only logged for comparison.
//!
//! # Usage
//!
//! ```rust,ignore
//! use auths_policy::{enforce, CompiledPolicy, EvalContext};
//!
//! // Simple enforcement (no shadow)
//! let decision = enforce(&production_policy, None, &ctx, |_, _| {});
//!
//! // With shadow policy for canary testing
//! let decision = enforce(&production_policy, Some(&canary_policy), &ctx, |primary, shadow| {
//!     log::warn!("Policy divergence: primary={:?}, shadow={:?}", primary.outcome, shadow.outcome);
//! });
//! ```

use crate::compiled::CompiledPolicy;
use crate::context::EvalContext;
use crate::decision::{Decision, Outcome};
use crate::eval::{evaluate_strict, evaluate3};

/// Divergence event emitted when primary and shadow policies disagree.
#[derive(Debug, Clone)]
pub struct Divergence {
    /// Decision from the primary (enforced) policy.
    pub primary: Decision,
    /// Decision from the shadow (logged-only) policy.
    pub shadow: Decision,
}

impl Divergence {
    /// Returns true if the divergence is a "shadow would deny" case.
    ///
    /// This is the dangerous case: production allows, but the new policy would deny.
    pub fn shadow_would_deny(&self) -> bool {
        self.primary.outcome == Outcome::Allow && self.shadow.outcome == Outcome::Deny
    }

    /// Returns true if the divergence is a "shadow would allow" case.
    ///
    /// This is less dangerous: production denies, but the new policy would allow.
    pub fn shadow_would_allow(&self) -> bool {
        self.primary.outcome == Outcome::Deny && self.shadow.outcome == Outcome::Allow
    }
}

/// Enforce a policy with optional shadow evaluation.
///
/// This is the main entry point for production policy enforcement. It:
/// 1. Evaluates the primary policy with `evaluate_strict` (indeterminate → deny)
/// 2. If a shadow policy is provided, evaluates it with `evaluate3`
/// 3. If the outcomes differ, calls the `on_divergence` callback
/// 4. Returns the primary decision (shadow is never enforced)
///
/// # Arguments
///
/// * `primary` - The policy that controls allow/deny
/// * `shadow` - Optional shadow policy for canary testing
/// * `ctx` - The evaluation context
/// * `on_divergence` - Callback when primary and shadow disagree
///
/// # Example
///
/// ```rust,ignore
/// let decision = enforce(&prod, Some(&canary), &ctx, |div| {
///     metrics::increment("policy.divergence");
///     if div.shadow_would_deny() {
///         alert("Canary policy would deny what prod allows!");
///     }
/// });
/// ```
pub fn enforce<F>(
    primary: &CompiledPolicy,
    shadow: Option<&CompiledPolicy>,
    ctx: &EvalContext,
    on_divergence: F,
) -> Decision
where
    F: FnOnce(Divergence),
{
    let decision = evaluate_strict(primary, ctx);

    if let Some(shadow_policy) = shadow {
        let shadow_decision = evaluate3(shadow_policy, ctx);
        if decision.outcome != shadow_decision.outcome {
            on_divergence(Divergence {
                primary: decision.clone(),
                shadow: shadow_decision,
            });
        }
    }

    decision
}

/// Enforce a policy without shadow evaluation.
///
/// Convenience function when no canary testing is needed.
/// Equivalent to `enforce(policy, None, ctx, |_| {})`.
pub fn enforce_simple(policy: &CompiledPolicy, ctx: &EvalContext) -> Decision {
    evaluate_strict(policy, ctx)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::compile::compile;
    use crate::expr::Expr;
    use crate::types::CanonicalDid;
    use chrono::Utc;
    use std::cell::RefCell;

    fn did(s: &str) -> CanonicalDid {
        CanonicalDid::parse(s).unwrap()
    }

    fn base_ctx() -> EvalContext {
        EvalContext::new(Utc::now(), did("did:keri:issuer"), did("did:keri:subject"))
    }

    #[test]
    fn enforce_no_shadow() {
        let policy = compile(&Expr::True).unwrap();
        let ctx = base_ctx();

        let called = RefCell::new(false);
        let decision = enforce(&policy, None, &ctx, |_| {
            *called.borrow_mut() = true;
        });

        assert!(decision.is_allowed());
        assert!(!*called.borrow()); // Callback not called without shadow
    }

    #[test]
    fn enforce_shadow_agrees() {
        let primary = compile(&Expr::True).unwrap();
        let shadow = compile(&Expr::True).unwrap();
        let ctx = base_ctx();

        let called = RefCell::new(false);
        let decision = enforce(&primary, Some(&shadow), &ctx, |_| {
            *called.borrow_mut() = true;
        });

        assert!(decision.is_allowed());
        assert!(!*called.borrow()); // No divergence
    }

    #[test]
    fn enforce_shadow_diverges() {
        let primary = compile(&Expr::True).unwrap();
        let shadow = compile(&Expr::False).unwrap();
        let ctx = base_ctx();

        let divergence = RefCell::new(None);
        let decision = enforce(&primary, Some(&shadow), &ctx, |div| {
            *divergence.borrow_mut() = Some(div);
        });

        assert!(decision.is_allowed()); // Primary wins
        let div = divergence.borrow();
        let div = div.as_ref().expect("divergence should be captured");
        assert!(div.shadow_would_deny());
        assert!(!div.shadow_would_allow());
    }

    #[test]
    fn enforce_shadow_would_allow() {
        let primary = compile(&Expr::False).unwrap();
        let shadow = compile(&Expr::True).unwrap();
        let ctx = base_ctx();

        let divergence = RefCell::new(None);
        let decision = enforce(&primary, Some(&shadow), &ctx, |div| {
            *divergence.borrow_mut() = Some(div);
        });

        assert!(decision.is_denied()); // Primary wins
        let div = divergence.borrow();
        let div = div.as_ref().expect("divergence should be captured");
        assert!(!div.shadow_would_deny());
        assert!(div.shadow_would_allow());
    }

    #[test]
    fn enforce_simple_works() {
        let policy = compile(&Expr::NotRevoked).unwrap();
        let ctx = base_ctx().revoked(false);

        let decision = enforce_simple(&policy, &ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn enforce_strict_converts_indeterminate() {
        // RepoIs with no repo in context → Indeterminate → Deny in strict mode
        let primary = compile(&Expr::RepoIs("org/repo".into())).unwrap();
        let ctx = base_ctx(); // No repo set

        let decision = enforce_simple(&primary, &ctx);
        assert!(decision.is_denied()); // Strict mode: indeterminate → deny
    }

    #[test]
    fn divergence_indeterminate_vs_allow() {
        // Primary: indeterminate (becomes deny in strict)
        // Shadow: allow (in 3-valued mode)
        let primary = compile(&Expr::RepoIs("org/repo".into())).unwrap();
        let shadow = compile(&Expr::True).unwrap();
        let ctx = base_ctx(); // No repo

        let divergence = RefCell::new(None);
        let decision = enforce(&primary, Some(&shadow), &ctx, |div| {
            *divergence.borrow_mut() = Some(div);
        });

        assert!(decision.is_denied()); // Primary strict: indeterminate → deny
        let div = divergence.borrow();
        let div = div.as_ref().expect("divergence should be captured");
        assert!(div.shadow_would_allow()); // Shadow would allow
    }
}
