//! Semantic policy diff engine.
//!
//! Compares two `auths_policy::Expr` trees and returns a structured list of
//! semantic changes with risk classifications.

use auths_policy::Expr;
use std::collections::HashSet;

/// A single semantic change between two policy expressions.
#[derive(Debug, Clone)]
pub struct PolicyChange {
    /// The kind of change: `"added"`, `"removed"`, or `"changed"`.
    pub kind: String,
    /// Human-readable description of the predicate or structural element that changed.
    pub description: String,
    /// Risk classification: `"HIGH"`, `"MEDIUM"`, or `"LOW"`.
    pub risk: String,
}

/// Errors from policy diff operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyDiffError {
    /// The policy expression could not be parsed.
    #[error("policy parse error: {0}")]
    Parse(String),
}

/// Compute the semantic diff between two compiled policy expressions.
///
/// Args:
/// * `old`: The previous policy expression.
/// * `new`: The updated policy expression.
///
/// Usage:
/// ```ignore
/// let changes = compute_policy_diff(&old_expr, &new_expr);
/// let risk = overall_risk_score(&changes);
/// ```
pub fn compute_policy_diff(old: &Expr, new: &Expr) -> Vec<PolicyChange> {
    let mut changes = Vec::new();

    let old_predicates = collect_predicates(old);
    let new_predicates = collect_predicates(new);

    for pred in &old_predicates {
        if !new_predicates.contains(pred) {
            changes.push(PolicyChange {
                kind: "removed".into(),
                description: pred.clone(),
                risk: removal_risk(pred),
            });
        }
    }

    for pred in &new_predicates {
        if !old_predicates.contains(pred) {
            changes.push(PolicyChange {
                kind: "added".into(),
                description: pred.clone(),
                risk: addition_risk(pred),
            });
        }
    }

    if let Some(change) = check_structural_change(old, new) {
        changes.push(change);
    }

    changes
}

/// Reduce a list of changes to a single risk label (HIGH > MEDIUM > LOW).
///
/// Args:
/// * `changes`: The list of policy changes to assess.
///
/// Usage:
/// ```ignore
/// let risk = overall_risk_score(&changes);
/// assert_eq!(risk, "HIGH");
/// ```
pub fn overall_risk_score(changes: &[PolicyChange]) -> String {
    if changes.iter().any(|c| c.risk == "HIGH") {
        return "HIGH".into();
    }
    if changes.iter().any(|c| c.risk == "MEDIUM") {
        return "MEDIUM".into();
    }
    "LOW".into()
}

fn collect_predicates(expr: &Expr) -> HashSet<String> {
    let mut predicates = HashSet::new();
    collect_predicates_rec(expr, &mut predicates);
    predicates
}

#[allow(clippy::too_many_lines)]
fn collect_predicates_rec(expr: &Expr, predicates: &mut HashSet<String>) {
    match expr {
        Expr::True => {
            predicates.insert("True".into());
        }
        Expr::False => {
            predicates.insert("False".into());
        }
        Expr::And(children) | Expr::Or(children) => {
            for child in children {
                collect_predicates_rec(child, predicates);
            }
        }
        Expr::Not(inner) => {
            collect_predicates_rec(inner, predicates);
        }
        Expr::HasCapability(cap) => {
            predicates.insert(format!("HasCapability({})", cap));
        }
        Expr::HasAllCapabilities(caps) => {
            predicates.insert(format!("HasAllCapabilities({:?})", caps));
        }
        Expr::HasAnyCapability(caps) => {
            predicates.insert(format!("HasAnyCapability({:?})", caps));
        }
        Expr::IssuerIs(did) => {
            predicates.insert(format!("IssuerIs({})", did));
        }
        Expr::IssuerIn(dids) => {
            predicates.insert(format!("IssuerIn({:?})", dids));
        }
        Expr::SubjectIs(did) => {
            predicates.insert(format!("SubjectIs({})", did));
        }
        Expr::DelegatedBy(did) => {
            predicates.insert(format!("DelegatedBy({})", did));
        }
        Expr::NotRevoked => {
            predicates.insert("NotRevoked".into());
        }
        Expr::NotExpired => {
            predicates.insert("NotExpired".into());
        }
        Expr::ExpiresAfter(secs) => {
            predicates.insert(format!("ExpiresAfter({})", secs));
        }
        Expr::IssuedWithin(secs) => {
            predicates.insert(format!("IssuedWithin({})", secs));
        }
        Expr::RoleIs(role) => {
            predicates.insert(format!("RoleIs({})", role));
        }
        Expr::RoleIn(roles) => {
            predicates.insert(format!("RoleIn({:?})", roles));
        }
        Expr::RepoIs(repo) => {
            predicates.insert(format!("RepoIs({})", repo));
        }
        Expr::RepoIn(repos) => {
            predicates.insert(format!("RepoIn({:?})", repos));
        }
        Expr::RefMatches(pattern) => {
            predicates.insert(format!("RefMatches({})", pattern));
        }
        Expr::PathAllowed(patterns) => {
            predicates.insert(format!("PathAllowed({:?})", patterns));
        }
        Expr::EnvIs(env) => {
            predicates.insert(format!("EnvIs({})", env));
        }
        Expr::EnvIn(envs) => {
            predicates.insert(format!("EnvIn({:?})", envs));
        }
        Expr::WorkloadIssuerIs(issuer) => {
            predicates.insert(format!("WorkloadIssuerIs({})", issuer));
        }
        Expr::WorkloadClaimEquals { key, value } => {
            predicates.insert(format!("WorkloadClaimEquals({}, {})", key, value));
        }
        Expr::MaxChainDepth(depth) => {
            predicates.insert(format!("MaxChainDepth({})", depth));
        }
        Expr::AttrEquals { key, value } => {
            predicates.insert(format!("AttrEquals({}, {})", key, value));
        }
        Expr::AttrIn { key, values } => {
            predicates.insert(format!("AttrIn({}, {:?})", key, values));
        }
        Expr::IsAgent => {
            predicates.insert("IsAgent".into());
        }
        Expr::IsHuman => {
            predicates.insert("IsHuman".into());
        }
        Expr::IsWorkload => {
            predicates.insert("IsWorkload".into());
        }
        Expr::ApprovalGate {
            inner, approvers, ..
        } => {
            predicates.insert(format!("ApprovalGate(approvers={:?})", approvers));
            collect_predicates_rec(inner, predicates);
        }
    }
}

fn removal_risk(pred: &str) -> String {
    if pred == "NotRevoked" || pred == "NotExpired" || pred.starts_with("MaxChainDepth") {
        return "HIGH".into();
    }
    if pred.starts_with("IssuerIs")
        || pred.starts_with("RepoIs")
        || pred.starts_with("RefMatches")
        || pred.starts_with("EnvIs")
    {
        return "MEDIUM".into();
    }
    "LOW".into()
}

fn addition_risk(pred: &str) -> String {
    if pred.starts_with("HasCapability") || pred.starts_with("HasAllCapabilities") {
        return "MEDIUM".into();
    }
    "LOW".into()
}

fn check_structural_change(old: &Expr, new: &Expr) -> Option<PolicyChange> {
    match (old, new) {
        (Expr::And(_), Expr::Or(_)) => Some(PolicyChange {
            kind: "changed".into(),
            description: "And → Or at root".into(),
            risk: "HIGH".into(),
        }),
        (Expr::Or(_), Expr::And(_)) => Some(PolicyChange {
            kind: "changed".into(),
            description: "Or → And at root".into(),
            risk: "MEDIUM".into(),
        }),
        _ => None,
    }
}
