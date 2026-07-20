//! # auths-mcp-core — the reusable per-tool-call enforcement
//!
//! The engine half of the bounded-agent MCP gateway. This
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

pub mod attestation;
pub mod audit;
pub mod budget;
pub mod channel;
pub mod gate;
pub mod money;
pub mod paymode;
pub mod rail;
pub mod receipt;
pub mod session;
pub mod treasury;

pub use attestation::{AttestationError, Attested, RailAttestation};
pub use audit::{
    AnnotatedAudit, AuditResume, AuditVerdict, ChainBreakKind, ConsistentProof, LogReadError,
    RecordFact, SPEND_LOG_GENESIS, Settlement, SpendLogRecord, audit_spend_log,
    audit_spend_log_annotated, audit_spend_log_resumed, call_commit_binding, read_spend_log,
    resolve_spend_log, spend_log_dir, spend_log_path, spend_log_period_path,
};
pub use budget::{
    BudgetError, CounterKey, CounterRef, CrossRailBudget, FlushPolicy, Hold, ReserveOutcome,
    ReservedHolds, SettleOutcome, SettledCounter,
};
pub use channel::{
    ChannelRecord, ChannelSettlement, ChannelState, netted_settle_cents, spend_log_hash,
};
pub use gate::{Decision, GateError, Meter, PerCallGate, ToolCall, Verdict};
pub use money::{Actual, AtomicUsdc, Ceiling, Cents, NonZeroCents};
pub use paymode::{
    BudgetRequired, ModeDisclosure, PaymentMode, StripeRail, TEST_MODE_ENV, X402Rail,
    env_opts_into_test, require_budget,
};
pub use rail::{ExtractedCost, RailError, extract as extract_rail_cost, extract_stripe};
pub use receipt::{Receipt, ReceiptError};
pub use session::{Budget, BudgetParseError};
pub use treasury::{
    FleetLedger, FleetReserveOutcome, SignedTreasuryCheckpoint, TreasuryCheckpoint, TreasuryError,
    TreasuryReply, TreasuryRequest, verify_checkpoint_trail,
};

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
            // The read FAMILY (every `readOnlyHint:true` filesystem tool), not just the one
            // deprecated `read_file` — a modern MCP client told to "read a file" calls
            // `read_text_file`/`list_directory`/`read_multiple_files`. Every name here is an
            // EXPLICIT real tool; an unlisted near-miss still falls through to `tool.<name>` below,
            // so the exact-token boundary the delegator's scope enforces is unchanged.
            "read_file"
            | "read_text_file"
            | "read_media_file"
            | "read_multiple_files"
            | "list_directory"
            | "list_directory_with_sizes"
            | "directory_tree"
            | "get_file_info"
            | "search_files"
            | "read"
            | "fs.read" => "fs.read",
            "write_file" | "edit_file" | "create_directory" | "move_file" | "write"
            | "fs.write" => "fs.write",
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

#[cfg(test)]
mod tests {
    use super::Capability;

    #[test]
    fn fs_read_admits_the_read_family() {
        // A `fs.read` grant covers the whole read family, not just the deprecated `read_file`.
        for tool in [
            "read_file",
            "read_text_file",
            "read_media_file",
            "read_multiple_files",
            "list_directory",
            "list_directory_with_sizes",
            "directory_tree",
            "get_file_info",
            "search_files",
        ] {
            assert_eq!(
                Capability::for_tool(tool).as_str(),
                "fs.read",
                "`{tool}` must map to fs.read"
            );
        }
        // The write family maps to fs.write.
        for tool in ["write_file", "edit_file", "create_directory", "move_file"] {
            assert_eq!(
                Capability::for_tool(tool).as_str(),
                "fs.write",
                "`{tool}` must map to fs.write"
            );
        }
        // An unknown tool still fails closed to a synthetic capability the delegator never granted.
        assert_eq!(Capability::for_tool("rm_rf").as_str(), "tool.rm_rf");
    }

    #[test]
    fn capability_for_tool_never_folds_near_misses() {
        // The tool→capability map is an EXACT-token match — no
        // case-fold, no substring, no unicode-fold, no traversal. Every near-miss of `read_file`
        // falls through to a synthetic `tool.*` the delegator never granted, so `--scope fs.read`
        // refuses it. This MUST survive the read-family widening (which added only real tool names).
        for near_miss in [
            "Read_File",        // case
            "read_file_secret", // suffix
            "xread_file",       // prefix
            "reаd_file",        // Cyrillic 'а' (U+0430), not ASCII 'a'
            "../read_file",     // path traversal
        ] {
            let cap = Capability::for_tool(near_miss);
            assert!(
                cap.as_str().starts_with("tool."),
                "`{near_miss}` must fail closed to a synthetic tool.* capability, got {}",
                cap.as_str()
            );
            assert_ne!(
                cap.as_str(),
                "fs.read",
                "`{near_miss}` must NOT fold to fs.read"
            );
        }
    }
}
