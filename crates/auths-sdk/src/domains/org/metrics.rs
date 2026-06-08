//! Fleet metrics — "what we measure" (Epic E1.15), derived from the KEL + the D1
//! delegation walker (no new source of truth).
//!
//! Reports fleet size (live / revoked) and the fraction of live agents whose authority
//! is traceable to the org root. Revocation-to-effect latency is expressed in **KEL
//! positions**, never wall-clock: a revocation takes effect at the exact position it is
//! anchored (any action at ≥ that position is rejected), so the latency is structurally
//! `0`.
//!
//! Note: "policy denials enforced" is emitted to the audit sink (A5,
//! [`crate::audit::emit_policy_decision`]) as a SIEM stream; counting it here would
//! require a queryable audit projection, which is a tracked follow-up. This surface
//! reports the KEL-derivable measures.

use auths_id::keri::types::Prefix;
use serde::Serialize;

use crate::context::AuthsContext;
use crate::domains::org::delegation::list_members;
use crate::domains::org::error::OrgError;
use crate::domains::org::trace::walk_delegation_chain;

/// Fleet governance metrics for one org.
#[derive(Debug, Clone, Serialize)]
pub struct FleetMetrics {
    /// The org's `did:keri:`.
    pub org_did: String,
    /// Total delegated members/agents the org has ever delegated.
    pub agents_total: usize,
    /// Live (non-revoked) agents — the governed fleet.
    pub agents_live: usize,
    /// Revoked agents.
    pub agents_revoked: usize,
    /// Live agents whose delegation chain resolves to the org root (traceable to a
    /// human/root authorizer).
    pub agents_traceable_to_human: usize,
    /// `agents_traceable_to_human / agents_live` (1.0 when there are no live agents).
    pub traceability_fraction: f64,
    /// Revocation-to-effect latency in KEL positions. Always `0` — a revocation is
    /// effective at the position it is anchored (positional, not wall-clock).
    pub revocation_effect_latency_positions: u128,
}

/// Compute [`FleetMetrics`] for an org from its KEL + the delegation walker.
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// let m = fleet_metrics(&ctx, &org_prefix)?;
/// println!("{}/{} agents traceable", m.agents_traceable_to_human, m.agents_live);
/// ```
pub fn fleet_metrics(ctx: &AuthsContext, org_prefix: &Prefix) -> Result<FleetMetrics, OrgError> {
    let members = list_members(ctx, org_prefix)?;
    let agents_total = members.len();
    let agents_revoked = members.iter().filter(|m| m.revoked).count();
    let agents_live = agents_total - agents_revoked;

    let mut traceable = 0usize;
    for member in members.iter().filter(|m| !m.revoked) {
        let prefix = Prefix::new_unchecked(member.member_prefix.clone());
        if let Ok(chain) = walk_delegation_chain(ctx, &prefix, None)
            && chain.depth >= 1
        {
            traceable += 1;
        }
    }

    let traceability_fraction = if agents_live == 0 {
        1.0
    } else {
        traceable as f64 / agents_live as f64
    };

    Ok(FleetMetrics {
        org_did: format!("did:keri:{}", org_prefix.as_str()),
        agents_total,
        agents_live,
        agents_revoked,
        agents_traceable_to_human: traceable,
        traceability_fraction,
        revocation_effect_latency_positions: 0,
    })
}
