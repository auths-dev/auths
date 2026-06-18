//! # auths-mcp-core — the reusable per-tool-call enforcement
//!
//! The engine half of the bounded-agent MCP gateway (PRD §5, Build item 1). This
//! crate harvests the KERI-presentation auth core from `auths-mcp-server` (offline
//! delegated-credential verify + revocation + the capability gate) and adds the
//! **one per-`tools/call` gate** that every brokered call passes through:
//!
//! * **scope ⊆ parent** — the requested tool maps to a capability that must lie
//!   inside the agent's delegator-anchored grant (maps AGT-1);
//! * **quantitative budget** — cumulative session spend must stay under the cap
//!   (maps AGT-4);
//! * **expiry** — the grant must be live at the injected `now`;
//! * **revocation** — liveness is re-derived from the KERI registry on every call
//!   (maps OPS-1);
//!
//! and emits a **signed per-call receipt** for every brokered call, allowed or
//! refused, that `auths verify` can independently replay.
//!
//! ## How the authenticity check is wired (no new crypto)
//!
//! A `tools/call` is canonicalized (RFC-8785 over `{tool, args}`) and the agent
//! signs those exact bytes as an auths artifact — concretely, a git commit whose
//! body is the canonical call and whose `Auths-Scope` trailer names the capability
//! it exercises, signed with the agent's delegated device key. The gate then
//! resolves the agent's delegated KEL **and** its delegator's KEL from the registry
//! and runs [`auths_verifier::verify_commit_against_kel_scoped`] — the same
//! delegation-aware authorization the commit path uses. That single call enforces
//! KEL authenticity, the delegation link (the agent is anchored under the pinned
//! parent root), revocation, expiry against the injected `now`, and scope ⊆ parent
//! — returning a [`auths_verifier::CommitVerdict`] this crate maps to a [`Verdict`].
//! A forged or tampered proof yields a non-`Valid` verdict, so the gateway refuses
//! the call before the downstream tool is ever invoked.

pub mod audit;
pub mod budget;
pub mod gate;
pub mod paymode;
pub mod rail;
pub mod receipt;
pub mod session;

pub use audit::{
    AuditVerdict, SPEND_LOG_GENESIS, SpendLogRecord, audit_spend_log, call_commit_binding,
    read_spend_log, spend_log_path,
};
pub use budget::{
    BudgetError, CrossRailBudget, Hold, ReserveOutcome, ReservedHolds, SettleOutcome,
    SettledCounter,
};
pub use gate::{Decision, GateError, PerCallGate, ToolCall, Verdict};
pub use paymode::{
    BudgetRequired, ModeDisclosure, PaymentMode, StripeRail, TEST_MODE_ENV, X402Rail,
    env_opts_into_test, require_budget,
};
pub use rail::{ExtractedCost, RailError, extract as extract_rail_cost, extract_stripe};
pub use receipt::{Receipt, ReceiptError};
pub use session::Budget;

/// A capability string a downstream tool maps to (e.g. `fs.read`, `fs.write`,
/// `github.comment`). The gate enforces that the capability a `tools/call`
/// requires lies inside the agent's delegator-anchored scope.
///
/// Kept as a thin newtype over `String`: the *containment* judgement is delegated
/// to `auths-verifier` (the scope seal the delegator anchored is read there), so
/// this type only names the capability a given tool exercises.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Capability(pub String);

impl Capability {
    /// The capability a `tools/call` for `tool` requires.
    ///
    /// The map mirrors the demo toolchain the scenario configs wrap: a filesystem
    /// server (`read_file`/`write_file`), a GitHub server (`create_comment`), and a
    /// metered "paid" server (`paid_call`). An unmapped tool conservatively maps to
    /// a synthetic `tool.<name>` capability the delegator will not have granted, so
    /// an unknown tool fails closed as out-of-scope rather than being waved through.
    pub fn for_tool(tool: &str) -> Self {
        let cap = match tool {
            "read_file" | "read" | "fs.read" => "fs.read",
            "write_file" | "write" | "fs.write" => "fs.write",
            "create_comment" | "comment" | "github.comment" => "github.comment",
            "paid_call" | "paid.call" => "paid.call",
            other => return Capability(format!("tool.{other}")),
        };
        Capability(cap.to_string())
    }

    /// The capability as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
