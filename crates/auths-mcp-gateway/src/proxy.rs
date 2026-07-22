//! The real-MCP `wrap` proxy (D1).
//!
//! Speaks MCP JSON-RPC **up** to the agent (an `rmcp` server over stdio) and
//! **down** to the wrapped downstream server (an `rmcp` child-process client over
//! stdio), proxying `tools/list` and `tools/call`. Each `tools/call` passes through
//! the gateway's per-call gate before it is forwarded to the downstream, and every
//! brokered call emits a signed receipt.
//!
//! This is the transport the scripted demos cannot reach: a stock MCP client
//! (Claude Desktop, the Agents SDK, Cursor) connects to the gateway exactly as it
//! would to the raw downstream, and the enforcement is additive middleware (a
//! non-auths client still works, unauthenticated, no receipt).
//!
//! Each brokered `tools/call` is SIGNED as the agent and authenticated through the
//! same `PerCallGate::judge` the hermetic replay path runs — scope ⊆ grant, live,
//! unrevoked, and reserved against the durable cross-rail budget — before it reaches
//! the downstream. The signed proof + receipt are appended to a spend log the offline
//! `verify-spend` re-verifies, so a live run is auditable by anyone, trusting neither
//! this gateway nor its operator. The proxy never fakes a receipt and never silently
//! widens authority.

use std::path::PathBuf;
use std::sync::Arc;

use auths_mcp_core::budget::CrossRailBudget;
use auths_mcp_core::{
    Actual, AtomicUsdc, Budget, Capability, Cents, Decision, Meter, NonZeroCents, PaymentMode,
    Receipt, Settlement, SpendLogRecord, TEST_MODE_ENV, ToolCall, TreasuryReply, Verdict,
    env_opts_into_test, require_budget,
};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::Utc;
use rmcp::model::{
    CallToolRequestParam, CallToolResult, ListToolsResult, PaginatedRequestParam,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::transport::stdio;
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use tokio::sync::Mutex;

/// The gateway's custody vault: the downstream tool's secret(s) the gateway holds
/// and injects into the wrapped downstream, and which the agent never sees.
/// Each entry is an environment variable the downstream reads to authenticate
/// to its credentialed resource — exactly the "API key in an env var" majority this
/// flips into the strongest pitch.
///
/// The vault is sourced ONLY from the gateway's own config/environment (the `wrap`
/// CLI / the gateway process env), never from the agent's MCP request. The agent
/// connects with only its auths delegation; the secret is injected into the
/// downstream child's environment on the brokered path. The value is treated as
/// sensitive: it is never logged, never echoed into receipts or stdout, and its
/// `Debug` is redacted so a stray `{:?}` cannot leak it.
#[derive(Default, Clone)]
pub struct CustodyVault {
    /// (NAME, VALUE) pairs injected into the downstream child's environment.
    entries: Vec<(String, String)>,
}

impl std::fmt::Debug for CustodyVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact: show only the COUNT and the NAMES (never the values). A custodied
        // secret must never reach a log line, even through a derived `{:?}`.
        let names: Vec<&str> = self.entries.iter().map(|(n, _)| n.as_str()).collect();
        write!(
            f,
            "CustodyVault {{ count: {}, names: {names:?} }}",
            self.entries.len()
        )
    }
}

impl CustodyVault {
    /// Build the vault from `--custody-credential` specs. Each spec is either
    /// `NAME=VALUE` (inject `VALUE`) or bare `NAME` (adopt the value from the
    /// gateway's OWN environment — the operator passes the secret out-of-band so it
    /// never appears on the agent-visible command line). A spec with an empty NAME,
    /// or a bare NAME whose value is not present in the gateway's environment, is an
    /// error — never log the value on the error path.
    pub fn from_specs(specs: &[String]) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(specs.len());
        for spec in specs {
            let (name, value) = match spec.split_once('=') {
                Some((name, value)) => (name.trim().to_string(), value.to_string()),
                None => {
                    let name = spec.trim().to_string();
                    // Bare NAME: adopt from the gateway's own env, never echo it.
                    let value = std::env::var(&name).map_err(|_| {
                        format!("`{name}` has no value in the gateway's environment")
                    })?;
                    (name, value)
                }
            };
            if name.is_empty() {
                return Err("a custody credential has an empty NAME".to_string());
            }
            entries.push((name, value));
        }
        Ok(Self { entries })
    }

    /// True when the gateway custodies at least one downstream credential.
    pub fn is_armed(&self) -> bool {
        !self.entries.is_empty()
    }

    /// The custodied variable NAMES (never the values) — safe to surface in a
    /// non-secret operator log so it is auditable WHICH credential is custodied.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Inject the custodied secrets into a downstream child's environment, sourced
    /// from the GATEWAY. This is the mechanism: the spawned downstream reads its
    /// key from its env, the agent's own process never holds it.
    fn inject(&self, command: &mut tokio::process::Command) {
        for (name, value) in &self.entries {
            command.env(name, value);
        }
    }
}

/// The `wrap` configuration parsed from the CLI.
pub struct WrapConfig {
    /// The capabilities the agent is granted.
    pub scope: Vec<String>,
    /// The session budget string (e.g. `"$5"`).
    pub budget: Option<String>,
    /// The grant TTL string (e.g. `"30m"`).
    pub ttl: Option<String>,
    /// The payment rail the wrapped downstream settles on (`Some("x402")` / `Some("stripe")`).
    /// When set, every call is metered on this rail from its response — set by the OPERATOR, so an
    /// agent cannot bypass metering by omitting a per-call declaration. `None` = non-payment.
    pub rail: Option<String>,
    /// The downstream credential(s) the gateway custodies and injects into the
    /// wrapped downstream — the agent never holds them.
    pub custody: CustodyVault,
    /// The downstream MCP server command (everything after `--`).
    pub downstream: Vec<String>,
    /// Opt into SANDBOX payment rails. Real money is the default; this single flag
    /// (or `AUTHS_MCP_TEST_MODE=1`) is the deliberate opt-in to test rails.
    pub test_mode: bool,
    /// Resolve the payment mode, disclose it, and exit — a dry run that touches no
    /// rail and charges nothing.
    pub show_mode: bool,
    /// A dispute reference stamped into every settlement receipt this session
    /// writes (`wrap --dispute-ref`) — the index entry pointing at the evidence
    /// surface that adjudicates a later dispute.
    pub dispute_ref: Option<String>,
    /// Where the signed spend log + registry are written (`wrap --spend-log`). `None` defaults to
    /// an ephemeral per-run OS temp dir (wiped on reboot); a stable dir keeps receipts across runs.
    pub spend_log: Option<PathBuf>,
}

impl WrapConfig {
    /// Whether this session grants a payment capability — i.e. it wraps a rail that
    /// can spend (`paid.call`). The mandatory-cap seatbelt and the mode disclosure
    /// apply exactly to these sessions.
    fn wraps_payment_rail(&self) -> bool {
        self.scope
            .iter()
            .any(|cap| Capability::for_tool(cap).as_str() == "paid.call")
    }
}

/// The directory the live wire builds its signing chain + registry under (org root, the
/// delegated agent, the scope seal, and the spend log). Resolution order: `wrap --spend-log`
/// (explicit, stable), then `AUTHS_MCP_LIVE_DIR`, then `LAB_DIR`, else an ephemeral per-process
/// temp dir. Returns `(dir, defaulted)` where `defaulted` is true ONLY for the temp-dir fallback,
/// so the caller can flag the ephemeral case in the startup banner.
fn live_chain_dir(spend_log: Option<&std::path::Path>) -> (PathBuf, bool) {
    if let Some(dir) = spend_log {
        return (dir.to_path_buf(), false);
    }
    for var in ["AUTHS_MCP_LIVE_DIR", "LAB_DIR"] {
        if let Ok(p) = std::env::var(var)
            && !p.is_empty()
        {
            return (PathBuf::from(p), false);
        }
    }
    (
        std::env::temp_dir().join(format!("auths-mcp-live-{}", std::process::id())),
        true,
    )
}

/// Parse a `--ttl` grant duration (`30m`, `1s`, `2h`, `7d`, or bare seconds) to seconds. A grant
/// TTL is anchored as the delegation's expiry seal, so a malformed TTL must fail the wrap at parse
/// time rather than serve an unenforced bound.
///
/// Args:
/// * `ttl`: the raw `--ttl` string (a suffixed duration or bare seconds).
///
/// Usage:
/// ```ignore
/// assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
/// ```
pub(crate) fn parse_ttl_secs(ttl: &str) -> Result<i64, String> {
    let t = ttl.trim();
    let (num, mult) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86_400),
        _ => (t, 1),
    };
    num.trim()
        .parse::<i64>()
        .map_err(|e| e.to_string())
        .and_then(|n| {
            n.checked_mul(mult)
                .ok_or_else(|| "ttl overflow".to_string())
        })
}

/// The metered shape of one brokered `tools/call`, parsed from the agent's request at the wire
/// boundary. A metered call ALWAYS carries a non-zero ceiling AND a rail, so "metered with a
/// zero/absent amount" is not a constructible state — the cap-bypass class is gone at the type
/// level. An operator rail with no declared amount parses to [`CallCost::AmountRequired`], which
/// the caller refuses BEFORE the gate (the charge cannot be bounded, so forwarding would let the
/// rail charge while the durable cap stayed put).
#[derive(Debug, Clone)]
enum CallCost {
    /// Non-metered (no operator rail, no declared cost): nothing reserved or settled (e.g. `fs.read`).
    Free,
    /// Metered on `rail`, reserving `ceiling` before the rail is touched. `settle` says WHERE the
    /// actual settled cost comes from once the call forwards.
    Metered {
        /// The payment rail this call settles on.
        rail: String,
        /// The non-zero ceiling pre-authorized before the rail is touched.
        ceiling: NonZeroCents,
        /// Where the ACTUAL settled cost is read from after the call forwards.
        settle: SettleSource,
    },
    /// An operator rail is set but the call declared no non-zero amount, so the gate could not bound
    /// the charge. Refused fail-closed at the wire boundary, before the rail is touched.
    AmountRequired {
        /// The operator rail the undeclared call would have settled on.
        rail: String,
    },
}

/// Where a metered call's ACTUAL settled cost is read from once it forwards — modeled explicitly so
/// neither settle source is a silent fallthrough of the other.
#[derive(Debug, Clone)]
enum SettleSource {
    /// The operator configured the rail (`--rail`); the actual cost is read from the rail's OWN
    /// response once the downstream returns — never an agent-declared number.
    RailResponse,
    /// A per-call declaration drove the meter (`_auths_cost_cents` + `_auths_rail`, with no operator
    /// rail); settle exactly this declared cost.
    Declared(Cents),
}

impl CallCost {
    /// The cost the agent's signed call body records — informational (the canonical signed bytes
    /// cover `{tool, args}`, not the cost). For an operator rail the ACTUAL settled cost is read
    /// from the response after forwarding, so the body records the declared ceiling; zero for a
    /// non-metered or refused call.
    fn declared_cost(&self) -> Cents {
        match self {
            CallCost::Free | CallCost::AmountRequired { .. } => Cents::ZERO,
            CallCost::Metered {
                settle: SettleSource::Declared(cost),
                ..
            } => *cost,
            CallCost::Metered {
                ceiling,
                settle: SettleSource::RailResponse,
                ..
            } => ceiling.get(),
        }
    }

    /// The payment rail this call settles (or would have settled) on, for receipt attribution.
    fn rail(&self) -> Option<&str> {
        match self {
            CallCost::Free => None,
            CallCost::Metered { rail, .. } | CallCost::AmountRequired { rail } => {
                Some(rail.as_str())
            }
        }
    }
}

/// The proxy handler: holds the downstream client peer and the session's bound
/// authority (scope/budget). One handler per wrapped session.
struct GatewayProxy {
    /// The connected downstream MCP server (the wrapped tool).
    downstream: RunningService<RoleClient, ()>,
    /// The session's DURABLE cross-rail budget — the verifier-held monotonic SETTLED
    /// counter (persisted under `<repo>/budget-ledger`, keyed to the agent delegation,
    /// summed across rails) + the transient RESERVED holds. This is the SAME
    /// [`CrossRailBudget`] (D8) the hermetic gate drives in `replay.rs`, so the live
    /// `wrap` wire enforces the cross-rail cap from the same counter the gate uses and
    /// cannot allow a call the gate refuses (#281). It supersedes the former v0
    /// in-memory per-session tally, which metered nothing per rail and could diverge
    /// from the durable gate.
    budget: Arc<Mutex<CrossRailBudget>>,
    /// The agent's delegation chain — its delegated signing key plus the registry the
    /// verifier replays. Every brokered call is signed under this, so the offline audit
    /// re-verifies the live wire's proofs exactly as it does the hermetic gate's. Shared
    /// (`Arc`) because the async MCP handler signs from `&self`.
    chain: Arc<crate::chain::Chain>,
    /// The per-call gate resolved over the chain's registry: it authenticates each signed
    /// call (proof + scope ⊆ grant + expiry + revocation) and reserves/settles against the
    /// budget — the SAME [`auths_mcp_core::PerCallGate`] the hermetic gate drives. Behind a
    /// `Mutex` so the delegator KEL can be re-resolved mid-session (revocation propagation);
    /// per-agent calls are already serialized by `prev_binding`, so the lock adds no contention.
    gate: Arc<Mutex<auths_mcp_core::PerCallGate>>,
    /// How often the delegator KEL is re-resolved so a mid-session revocation propagates within
    /// this SLA (default 30s, `AUTHS_MCP_REVOCATION_RECHECK_SECS`) instead of only on restart.
    revocation_recheck: std::time::Duration,
    /// When the delegator KEL was last resolved — the re-resolution is due once this is older than
    /// `revocation_recheck`.
    last_resolved: Arc<Mutex<std::time::Instant>>,
    /// Monotonic per-call index; each call's signing work repo is keyed by it.
    next_call: Arc<std::sync::atomic::AtomicUsize>,
    /// The payment rail the wrapped downstream settles on, set by the operator. When `Some`, every
    /// call is metered on it (the cost is read from the rail's own response), so an agent cannot
    /// bypass the cap by omitting a per-call declaration.
    rail: Option<String>,
    /// The hash of the last persisted spend-log record — threaded into the next call's signed
    /// `Auths-Prev` so the log is a continuous chain the audit can verify is complete. Correct for
    /// the sequential single-agent flow; concurrent persists from multiple agents on one gateway
    /// would need this serialized across sign+append (a follow-on).
    prev_binding: Arc<Mutex<String>>,
    /// The fleet treasury coordinator, when `TREASURY_URL` names one: every metered
    /// call reserves fleet capacity there BEFORE the local budget, so ONE cap binds
    /// N gateway processes. `None` (unset or unreachable) leaves the local — smaller
    /// — budget as the only cap: fail-closed to the tighter bound, never open.
    treasury: Option<Arc<crate::treasury::TreasuryClient>>,
    /// Whether to print a human-readable verdict line per call (`AUTHS_MCP_VERBOSE`). Off by
    /// default so the hot path does no synchronous per-call stderr; metrics carry observability.
    verbose: bool,
    /// The operator's dispute reference (`wrap --dispute-ref`), stamped into every
    /// settlement receipt this session writes.
    dispute_ref: Option<String>,
    /// The payment mode (real vs sandbox) this wrap serves under — resolved once at
    /// construction from `--test-mode` / `AUTHS_MCP_TEST_MODE`. The rail cost extractor
    /// consults it so a MAINNET (real-money) x402 settle meters only in real mode; under
    /// `--test-mode` a mainnet settle is refused rather than mis-metered.
    payment_mode: PaymentMode,
}

impl GatewayProxy {
    /// Pre-authorize a metered call's ceiling against the fleet treasury when one is
    /// configured (`TREASURY_URL`). `Some(decision)` is the fleet's refusal — the
    /// call is `usage-cap-exceeded` before any local reserve or rail touch. `None`
    /// means no coordinator, a fleet grant, or an unreachable coordinator — in every
    /// one of those the local (smaller) budget still judges next, so degradation is
    /// fail-closed to the tighter cap, never open.
    async fn fleet_refusal(
        &self,
        rail: &str,
        ceiling: NonZeroCents,
    ) -> Result<Option<Decision>, McpError> {
        let Some(treasury) = &self.treasury else {
            return Ok(None);
        };
        let Some(TreasuryReply::Refused {
            cap_cents,
            would_be_cents,
        }) = treasury.reserve(&self.chain.agent_did, ceiling.get()).await
        else {
            return Ok(None);
        };
        let cumulative = {
            let budget = self.budget.lock().await;
            budget.settled_cents().map_err(|e| {
                McpError::internal_error(format!("read the cross-rail counter: {e}"), None)
            })?
        };
        Ok(Some(Decision {
            verdict: Verdict::UsageCapExceeded {
                cap_cents,
                would_be_cents,
            },
            cumulative_cents: cumulative,
            reserved_cents: Cents::ZERO,
            hold: None,
            rail: Some(rail.to_string()),
        }))
    }

    /// Derive the metered cost + rail of a brokered call for the cross-rail budget.
    ///
    /// The live per-call *cost extraction* from a rail's charge response is the
    /// metered-rail wiring (a follow-on): a Stripe/x402 server reports the actual on
    /// its response, which the gateway settles. Until that lands on the live wire, the
    /// wrap path honors an explicit declared cost on the request (`_auths_cost_cents` /
    /// `_auths_rail` meta) so a metered downstream config can drive the durable counter;
    /// a call without it is treated as non-metered (reserves and settles nothing). What
    /// #281 fixes is the COUNTER SOURCE — whatever cost a call carries is enforced
    /// against the durable `CrossRailBudget`, not a separate RAM tally.
    fn call_cost(&self, request: &CallToolRequestParam) -> CallCost {
        let args = request.arguments.as_ref();

        // Operator-configured rail: EVERY call is metered on it. The reserve ceiling pre-authorized
        // before the rail is touched is the agent's intended payment (an x402 `amount_atomic` →
        // cents, rounded up, or an explicit `_auths_reserve_ceiling_cents`); the amount actually
        // SETTLED is read from the rail's own response in `call_tool`. Because the OPERATOR sets the
        // rail, an agent cannot bypass metering by omitting a per-call field: with no non-zero amount
        // the call is `AmountRequired` and refused before the rail is touched.
        if let Some(rail) = self.rail.as_deref() {
            // `amount_atomic` is atomic USDC read from the agent's arg (a genuine boundary) →
            // reserve ceiling rounded UP; `_auths_reserve_ceiling_cents` is a raw cent count.
            let ceiling_cents = args
                .and_then(|m| m.get("amount_atomic"))
                .and_then(|v| v.as_u64())
                .map(|a| AtomicUsdc::new(a).to_cents_ceiling())
                .or_else(|| {
                    args.and_then(|m| m.get("_auths_reserve_ceiling_cents"))
                        .and_then(|v| v.as_u64())
                        .map(Cents::new)
                })
                .unwrap_or(Cents::ZERO);
            return match NonZeroCents::new(ceiling_cents) {
                Some(ceiling) => CallCost::Metered {
                    rail: rail.to_string(),
                    ceiling,
                    settle: SettleSource::RailResponse,
                },
                None => CallCost::AmountRequired {
                    rail: rail.to_string(),
                },
            };
        }

        // No operator rail: a non-payment downstream. Honor an explicit per-call declaration so a
        // metered downstream config can still drive the durable counter; else non-metered. A declared
        // cost is metered ONLY when it also names its rail — without one there is nothing to settle on
        // or attribute to, so it is non-metered (a metered call always carries a rail).
        let Some(args) = args else {
            return CallCost::Free;
        };
        // `_auths_cost_cents` is a raw cent count read from the agent's arg (a genuine boundary).
        let cost_cents = args
            .get("_auths_cost_cents")
            .and_then(|v| v.as_u64())
            .map(Cents::new)
            .unwrap_or(Cents::ZERO);
        let (Some(cost), Some(rail)) = (
            NonZeroCents::new(cost_cents),
            args.get("_auths_rail").and_then(|v| v.as_str()),
        ) else {
            return CallCost::Free;
        };
        // The ceiling is the explicit `_auths_reserve_ceiling_cents` when it is non-zero, else the
        // declared cost (itself non-zero) — so the metered ceiling is always non-zero.
        let ceiling = args
            .get("_auths_reserve_ceiling_cents")
            .and_then(|v| v.as_u64())
            .map(Cents::new)
            .and_then(NonZeroCents::new)
            .unwrap_or(cost);
        CallCost::Metered {
            rail: rail.to_string(),
            ceiling,
            settle: SettleSource::Declared(cost.get()),
        }
    }
}

/// Map a per-call [`Verdict`] to a stable Prometheus label value (#7): `granted` = forwarded,
/// `refused` = the cross-rail cap, `denied` = any other fail-closed verdict.
fn verdict_metric_label(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allowed => "granted",
        Verdict::UsageCapExceeded { .. } => "refused",
        _ => "denied",
    }
}

impl ServerHandler for GatewayProxy {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "auths-mcp-gateway: a bounded-agent MCP proxy. Each tools/call is brokered \
                 through a cryptographic delegation (scope/budget/ttl) and receipted."
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    /// Proxy `tools/list` straight through to the downstream — the agent sees the
    /// real downstream tools (enforcement is additive, not a tool rewrite).
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.downstream.list_tools(None).await.map_err(|e| {
            McpError::internal_error(format!("downstream tools/list failed: {e}"), None)
        })
    }

    /// Broker one `tools/call`: gate it, forward to the downstream only on pass,
    /// and return the real downstream result (or a fail-closed error).
    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let call_start = std::time::Instant::now();
        let tool = request.name.to_string();

        // Revocation propagation: re-resolve the delegator KEL (which carries the
        // revocation/expiry seals) on a bounded interval so a mid-session `auths id agent revoke`
        // is observed within the recheck SLA, not only on process restart. A refresh error fails
        // the call CLOSED — never a silently-stale snapshot.
        {
            let mut last = self.last_resolved.lock().await;
            if last.elapsed() >= self.revocation_recheck {
                let registry = GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(self.chain.org_repo()),
                );
                self.gate
                    .lock()
                    .await
                    .refresh_delegator(&registry)
                    .map_err(|e| {
                        McpError::internal_error(
                            format!("re-resolve the delegator KEL for revocation propagation: {e}"),
                            None,
                        )
                    })?;
                *last = std::time::Instant::now();
            }
        }

        // Canonicalize the call the way the offline audit re-derives it, and SIGN it as the
        // agent — the per-call proof `verify-spend` re-verifies. The cost/rail are the call's
        // declared metering; extracting a metered rail's actual cost from its response and
        // signing a settlement over it is the metered follow-on below.
        let cost = self.call_cost(&request);
        let args_value = request
            .arguments
            .clone()
            .map(serde_json::Value::Object)
            .unwrap_or(serde_json::Value::Null);
        let tool_call = ToolCall {
            tool: tool.clone(),
            args: args_value,
            cost_cents: cost.declared_cost(),
        };
        let capability = tool_call.capability();
        let canonical = tool_call.canonical_bytes();
        let idx = self
            .next_call
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Link this call to the prior persisted record (the genesis sentinel for the first) via the
        // signed `Auths-Prev` trailer, so the audit can verify the spend log is a complete chain.
        //
        // Hold the chain head across the ENTIRE call so read-of-prev → sign → append → advance is
        // one atomic critical section. A spend-log hash chain is inherently sequential: without
        // this, two concurrent (pipelined, or multi-in-flight) calls both read the same head and
        // both link to it, forking the log so the offline audit can no longer re-derive it. Calls
        // on different chains (different agents) hold different locks and still run concurrently.
        let mut chain_head = self.prev_binding.lock().await;
        let prev_binding = chain_head.clone();
        let sign_t = std::time::Instant::now();
        let (proof_bytes, proof_sha) = self
            .chain
            .sign_call(idx, &canonical, capability.as_str(), &prev_binding)
            .map_err(|e| McpError::internal_error(format!("sign the brokered call: {e}"), None))?;
        crate::metrics_http::record_stage("sign", sign_t.elapsed());
        // The proof's binding hash is needed for both the settlement's `Auths-Settle-Call` trailer
        // and the next record's `Auths-Prev` — derive it once here rather than hashing twice.
        let call_binding = auths_mcp_core::call_commit_binding(&proof_bytes);

        // Authenticate + pre-authorize over the SIGNED proof: the gate verifies the proof
        // (scope ⊆ grant, live, unrevoked) AND reserves the ceiling against the durable
        // cross-rail counter BEFORE the downstream/rail is touched. A non-Allowed verdict
        // fails closed here — the downstream is never invoked. This is the SAME
        // `PerCallGate::judge` the hermetic gate runs, now on the live wire.
        //
        // An operator rail with no declared amount (`AmountRequired`) is refused HERE, before the
        // gate: the charge cannot be bounded, so the only safe outcome is a fail-closed
        // metered-amount-required — the call is still signed + persisted (below) as a refused record.
        let now = Utc::now();
        let gate_t = std::time::Instant::now();
        let decision = match &cost {
            CallCost::AmountRequired { rail } => {
                let cumulative = {
                    let budget = self.budget.lock().await;
                    budget.settled_cents().map_err(|e| {
                        McpError::internal_error(format!("read the cross-rail counter: {e}"), None)
                    })?
                };
                Decision {
                    verdict: Verdict::MeteredAmountRequired { rail: rail.clone() },
                    cumulative_cents: cumulative,
                    reserved_cents: Cents::ZERO,
                    hold: None,
                    rail: Some(rail.clone()),
                }
            }
            CallCost::Free => {
                // Lock ordering is always gate → budget (the refresh path locks the gate alone).
                let gate = self.gate.lock().await;
                let mut budget = self.budget.lock().await;
                gate.judge(&Meter::Unmetered, &proof_bytes, now, &mut budget)
                    .await
                    .map_err(|e| McpError::internal_error(format!("per-call gate: {e}"), None))?
            }
            CallCost::Metered { rail, ceiling, .. } => {
                match self.fleet_refusal(rail, *ceiling).await? {
                    Some(fleet_refused) => fleet_refused,
                    None => {
                        let meter = Meter::Metered {
                            rail: rail.clone(),
                            ceiling: *ceiling,
                        };
                        let gate = self.gate.lock().await;
                        let mut budget = self.budget.lock().await;
                        gate.judge(&meter, &proof_bytes, now, &mut budget)
                            .await
                            .map_err(|e| {
                                McpError::internal_error(format!("per-call gate: {e}"), None)
                            })?
                    }
                }
            }
        };
        // Forward to the downstream ONLY on a forwarding verdict — a refused call never touches
        // it. Either way the signed proof + receipt are persisted below, so an out-of-scope or
        // over-budget ATTEMPT is recorded too (not silently dropped), exactly as the replay gate
        // records it.
        crate::metrics_http::record_stage("gate", gate_t.elapsed());
        let mut verdict = decision.verdict.clone();
        let mut cumulative = decision.cumulative_cents;
        // For a metered call the rail's response carries the ACTUAL settled cost + reference; these
        // are filled in from that response below and persisted, so the audit sums the agent-signed
        // actual — never a number the agent declared.
        let mut rail_response: Option<Vec<u8>> = None;
        let mut settlement_commit: Option<Vec<u8>> = None;
        let mut settled_charge_ref: Option<String> = None;
        let forwarded = if decision.forwards() {
            let down_t = std::time::Instant::now();
            let result = self.downstream.call_tool(request).await.map_err(|e| {
                McpError::internal_error(format!("downstream tools/call failed: {e}"), None)
            })?;
            crate::metrics_http::record_stage("downstream", down_t.elapsed());

            // A metered call's ACTUAL cost comes from its settle source: an operator rail reads it
            // from the downstream's OWN response (never a number the agent declared) and keeps the
            // raw response so the offline audit can re-extract + cross-check the agent-signed amount;
            // a per-call declaration settles exactly the declared cost. A non-metered call holds
            // nothing, so its settle below is skipped and this amount is unused.
            let actual_cents = match &cost {
                CallCost::Metered {
                    rail,
                    settle: SettleSource::RailResponse,
                    ..
                } => {
                    let resp = result
                        .content
                        .first()
                        .and_then(|c| c.as_text())
                        .map(|t| t.text.clone().into_bytes())
                        .ok_or_else(|| {
                            McpError::internal_error(
                                format!("metered `{rail}` call returned no text response to meter"),
                                None,
                            )
                        })?;
                    let extracted =
                        auths_mcp_core::extract_rail_cost(rail, &resp, self.payment_mode).map_err(
                            |e| {
                                McpError::internal_error(
                                    format!("extract `{rail}` cost from the rail response: {e}"),
                                    None,
                                )
                            },
                        )?;
                    rail_response = Some(resp);
                    settled_charge_ref = Some(extracted.reference);
                    extracted.amount_cents
                }
                CallCost::Metered {
                    settle: SettleSource::Declared(declared),
                    ..
                } => *declared,
                CallCost::Free | CallCost::AmountRequired { .. } => Cents::ZERO,
            };

            // Settle the ACTUAL cost into the durable counter, releasing the reservation slack.
            if let Some(hold) = decision.hold {
                // Lock ordering is always gate → budget.
                let gate = self.gate.lock().await;
                let mut budget = self.budget.lock().await;
                let (settle_verdict, new_cumulative) = gate
                    .settle(&mut budget, hold, Actual::new(actual_cents))
                    .map_err(|e| {
                        McpError::internal_error(
                            format!("settle the cross-rail counter: {e}"),
                            None,
                        )
                    })?;
                verdict = settle_verdict;
                cumulative = new_cumulative;
            }

            // Sign a settlement commit anchoring the agent-signed actual cost, bound to THIS call by
            // the hash of its proof, so the audit cannot be handed a settlement from another call.
            if let (Some(rail), Some(charge_ref), Some(actual)) = (
                cost.rail(),
                settled_charge_ref.as_deref(),
                NonZeroCents::new(actual_cents),
            ) {
                let settle_t = std::time::Instant::now();
                let (bytes, _sha) = self
                    .chain
                    .sign_settlement(idx, &call_binding, rail, actual, charge_ref, cumulative)
                    .map_err(|e| {
                        McpError::internal_error(format!("sign the settlement: {e}"), None)
                    })?;
                settlement_commit = Some(bytes);
                crate::metrics_http::record_stage("settle", settle_t.elapsed());
                metrics::counter!(crate::metrics_http::SETTLE_TOTAL).increment(1);
            }
            Some(result)
        } else {
            None
        };

        // Persist the SIGNED per-call record (forwarded OR refused) so `verify-spend` re-derives
        // the spend — and the refusals — offline, trusting neither this gateway nor its operator.
        // (The agent-signed settlement of a metered rail's actual cost rides on the live
        // rail-response extraction, a follow-on.)
        let receipt = Receipt::for_call(
            &self.chain.agent_did,
            &self.chain.root_did,
            &tool_call,
            &proof_sha,
            verdict.clone(),
            cost.rail(),
            settled_charge_ref.as_deref(),
            decision.reserved_cents,
            cumulative,
            now,
        )
        .with_dispute_ref(self.dispute_ref.as_deref());
        // This record's binding — what the NEXT call's `Auths-Prev` links to. Computed from the
        // bytes about to be stored, before they move into the record.
        let new_binding = call_binding;
        let log_t = std::time::Instant::now();
        if let Err(e) = crate::spend_log::append(
            self.chain.org_repo(),
            &self.chain.agent_did,
            &SpendLogRecord {
                call_commit: proof_bytes,
                receipt,
                // The facilitator attestation is not captured on the live wire yet (a follow-on); the
                // offline audit runs without it.
                settlement: match cost.rail() {
                    Some(rail) => Settlement::Metered {
                        rail: rail.to_string(),
                        rail_response,
                        settlement_commit,
                        rail_attestation: None,
                    },
                    None => Settlement::Unmetered,
                },
            },
        ) {
            return Err(McpError::internal_error(
                format!("persist the signed spend-log record: {e}"),
                None,
            ));
        }
        crate::metrics_http::record_stage("spend_log", log_t.elapsed());
        // Advance the chain head so the next brokered call links to this record — written through
        // the guard held since the read above, closing the atomic critical section. An earlier
        // fail-closed return drops the guard without advancing, so a call that never persisted a
        // record leaves the head untouched and the next call links to the same prev (correct).
        *chain_head = new_binding;

        // Record the call's total latency + verdict (no-ops unless the recorder is installed).
        metrics::histogram!(crate::metrics_http::CALL_LATENCY)
            .record(call_start.elapsed().as_secs_f64());
        metrics::counter!(crate::metrics_http::CALLS_TOTAL, "verdict" => verdict_metric_label(&verdict))
            .increment(1);

        // Human-readable verdict lines are opt-in (`AUTHS_MCP_VERBOSE`): the metrics recorded
        // above are the hot-path observability, and a synchronous per-call stderr write (plus its
        // format allocation) is not free at rate.
        if self.verbose {
            let rail_tag = cost
                .rail()
                .map(|r| format!(" rail={r}"))
                .unwrap_or_default();
            let proof_short = &proof_sha[..proof_sha.len().min(12)];
            if forwarded.is_some() {
                eprintln!(
                    "auths-mcp-gateway: brokered + SIGNED tools/call `{tool}`{rail_tag} (cap={}) — \
                     forwarded; cross-rail settled total ${}.{:02}; proof={proof_short}",
                    capability.as_str(),
                    cumulative.get() / 100,
                    cumulative.get() % 100,
                );
            } else {
                eprintln!(
                    "auths-mcp-gateway: REFUSED + SIGNED tools/call `{tool}`{rail_tag} ({}) — \
                     downstream NOT touched; proof={proof_short}",
                    verdict.code(),
                );
            }
        }
        match forwarded {
            Some(result) => Ok(result),
            None => {
                let refusal = match &verdict {
                    // The refusal teaches the fix: a buyer can self-correct from the
                    // error alone, without docs (the example is a runnable tools/call).
                    Verdict::MeteredAmountRequired { rail } => format!(
                        "metered-amount-required: this downstream settles on `{rail}`, so every \
                         call must declare what it intends to spend before the rail is touched. \
                         Re-send with the amount in your arguments, e.g. \
                         {{\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\
                         \"arguments\":{{\"amount_atomic\":30000}}}}}} \
                         (USDC 6-decimals: 30000 = $0.03) — or declare a raw cent ceiling with \
                         \"_auths_reserve_ceiling_cents\"."
                    ),
                    _ => format!(
                        "{}: the per-call gate refused this call before the downstream was touched",
                        verdict.code()
                    ),
                };
                // Co-deliver a structured verdict the refused caller can KEEP (a re-checkable
                // artifact, not just a console line) — the same verdict the gate returned.
                let proof_short = &proof_sha[..proof_sha.len().min(12)];
                let data = serde_json::json!({
                    "code": verdict.code(),
                    "tool": tool,
                    "refused_before_downstream": true,
                    "proof_ref": proof_short,
                });
                Err(McpError::invalid_request(refusal, Some(data)))
            }
        }
    }
}

/// Resolve the payment mode and DISCLOSE it before any rail is touched — the safety
/// surface for a real-money-by-default gateway.
///
/// Two properties this enforces, in BOTH modes:
///
/// * **The cap is mandatory.** A payment-rail wrap with no `--budget` is refused
///   fail-closed (`budget-required`) before anything is served or charged — real
///   money is the default, so the cross-rail cap is the seatbelt and cannot be
///   skipped. A non-payment wrap needs no budget.
/// * **The mode is disclosed.** The resolved mode (`mode=real` by default, `mode=test`
///   under the single `--test-mode` / `AUTHS_MCP_TEST_MODE=1` opt-in), the resolved
///   Stripe/x402 rails, and the human banner are surfaced so live rails are never
///   silent.
///
/// Returns `Ok(true)` when the caller should STOP after disclosure — either because
/// `--show-mode` requested a resolve-and-disclose dry run (served:false, charged:false)
/// or there is nothing more to do. Returns `Ok(false)` to continue serving the proxy.
/// Returns `Err` on the fail-closed budget refusal.
fn disclose_payment_mode(cfg: &WrapConfig) -> anyhow::Result<bool> {
    let wraps_payment = cfg.wraps_payment_rail();
    // The single opt-in to sandbox rails: the `--test-mode` flag OR its environment
    // twin `AUTHS_MCP_TEST_MODE`. The env var is read here at the I/O boundary (the
    // gateway's own environment, never an agent request); the truthy rule lives in the
    // core port. Absent both, the mode resolves to REAL — real money is the default.
    let env_test = env_opts_into_test(std::env::var(TEST_MODE_ENV).ok().as_deref());
    let mode = PaymentMode::resolve(cfg.test_mode || env_test);
    let disclosure = mode.disclosure();

    // Disclose the mode FIRST so the operator always sees whether real money is live,
    // even on the refusal path below.
    if wraps_payment || cfg.show_mode {
        eprintln!("auths-mcp-gateway: {}", disclosure.banner);
        eprintln!(
            "auths-mcp-gateway: resolved payment mode — {}",
            disclosure.machine_line()
        );
    }

    // The mandatory cap (the seatbelt): a payment rail must carry a --budget, in BOTH
    // modes, fail-closed. Refuse BEFORE serving or touching any rail.
    if let Err(refusal) = require_budget(wraps_payment, cfg.budget.as_deref()) {
        anyhow::bail!(
            "{refusal} (mode={}, served:false, charged:false)",
            mode.token()
        );
    }

    // The resolve-and-disclose dry run stops here: it never serves the proxy and never
    // charges. served:false, charged:false.
    if cfg.show_mode {
        println!(
            "auths-mcp-gateway: --show-mode resolved {} (served:false, charged:false) — \
             no proxy was served and no rail was touched",
            disclosure.machine_line()
        );
        return Ok(true);
    }

    Ok(false)
}

/// Serve the wrap proxy: connect down to the wrapped downstream, then serve MCP up
/// to the agent over stdio, brokering each call. Returns when the agent disconnects.
pub async fn serve(cfg: WrapConfig) -> anyhow::Result<()> {
    if cfg.downstream.is_empty() {
        anyhow::bail!("no downstream command after `--`");
    }

    // Resolve + disclose the payment mode and enforce the mandatory cap BEFORE any
    // rail or downstream is touched. A --show-mode dry run discloses and returns here
    // (served:false, charged:false); a budget-less payment-rail wrap is refused here.
    if disclose_payment_mode(&cfg)? {
        return Ok(());
    }

    // #7 observability: opt-in Prometheus /metrics. Installing the global recorder BEFORE any
    // metered call makes the `metrics::` macros on the hot path live; with the env unset the
    // recorder is never installed and those macros stay cheap no-ops (stdio mode unchanged).
    if let Ok(addr) = std::env::var("AUTHS_MCP_METRICS_ADDR") {
        let handle = auths_telemetry::init_prometheus();
        tokio::spawn(crate::metrics_http::serve_metrics(addr, handle));
    }

    // A PRESENT budget must parse — a malformed `--budget` is refused fail-closed, never silently
    // treated as an unbounded cap (a payment wrap with no budget was already refused above). Only an
    // ABSENT budget on a non-payment wrap is the deliberate unbounded cap.
    let cap_cents = match cfg.budget.as_deref() {
        Some(raw) => Budget::parse(raw)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .cap_cents(),
        None => Budget::unbounded().cap_cents(),
    };

    // If the gateway custodies a downstream credential, audit which credential(s) by NAME (never
    // the value). The secret is injected into the long-lived downstream child spawned below — the
    // agent, and the agent-visible MCP wire, never hold it.
    // A bypass (the same downstream invoked WITHOUT the gateway) lacks the credential and the
    // downstream refuses it; that half is unbypassable by construction of the credentialed resource.
    if cfg.custody.is_armed() {
        eprintln!(
            "auths-mcp-gateway: custody armed — gateway holds downstream credential(s) {:?}; \
             the agent connects with only its delegation and never sees the secret",
            cfg.custody.names(),
        );
    }

    // 1. Connect DOWN to the wrapped downstream MCP server (spawned over stdio),
    //    with the custodied credential injected from the gateway so the long-lived
    //    downstream authenticates to its credentialed resource without the agent
    //    ever holding the key.
    let mut command = tokio::process::Command::new(&cfg.downstream[0]);
    command.args(&cfg.downstream[1..]);
    cfg.custody.inject(&mut command);
    let transport = TokioChildProcess::new(command)
        .map_err(|e| anyhow::anyhow!("spawn downstream `{}`: {e}", cfg.downstream.join(" ")))?;
    let downstream = ()
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP handshake with downstream failed: {e}"))?;

    eprintln!(
        "auths-mcp-gateway: wrapping `{}` — scope={:?} budget={:?} ttl={:?}",
        cfg.downstream.join(" "),
        cfg.scope,
        cfg.budget,
        cfg.ttl,
    );

    // Build the agent's delegation chain (its delegated signing key + the registry the
    // verifier replays) so every brokered call is signed on the live wire exactly as the
    // hermetic gate signs it. The agent also holds a narrow `settle` capability to sign its
    // own settlement commits. The gate resolves the agent + delegator KELs from the chain's
    // registry — the same resolution `verify-spend` runs offline over the persisted log.
    // The chain is built BEFORE the budget so the durable counter can be keyed to the REAL
    // agent delegation under the chain's own registry — the same place the spend log and the
    // printed verify-spend command point — so the offline audit opens the counter the wire advanced.
    let (lab, lab_defaulted) = live_chain_dir(cfg.spend_log.as_deref());
    std::fs::create_dir_all(&lab)
        .map_err(|e| anyhow::anyhow!("create the live signing directory {lab:?}: {e}"))?;
    // Announce the resolved spend-log directory up front, flagging the ephemeral default so
    // "where did the receipts land" is answered without scraping the compound command.
    eprintln!(
        "auths-mcp-gateway: spend-log: {}{}",
        lab.display(),
        if lab_defaulted {
            "  (ephemeral per-run temp dir, wiped on reboot — pass --spend-log <DIR> to keep it)"
        } else {
            ""
        },
    );
    let mut signing_scope = cfg.scope.clone();
    if !signing_scope.iter().any(|c| c == "settle") {
        signing_scope.push("settle".to_string());
    }
    // Parse the grant TTL fail-closed and anchor it as the delegation's expiry seal: a
    // malformed `--ttl` aborts the wrap rather than serving a bound nothing enforces.
    let ttl_secs = cfg
        .ttl
        .as_deref()
        .map(parse_ttl_secs)
        .transpose()
        .map_err(|e| {
            anyhow::anyhow!("invalid --ttl `{}`: {e}", cfg.ttl.as_deref().unwrap_or(""))
        })?;
    let chain = crate::chain::Chain::build(&lab, &signing_scope, ttl_secs)
        .map_err(|e| anyhow::anyhow!("build the agent delegation chain for live signing: {e}"))?;
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(chain.org_repo()));
    let gate = auths_mcp_core::PerCallGate::resolve(&registry, &chain.agent_did, &chain.root_did)
        .map_err(|e| {
        anyhow::anyhow!("resolve the per-call gate over the live registry: {e}")
    })?;

    // Open the DURABLE cross-rail budget the live wire enforces against — the SAME verifier-held
    // CrossRailBudget (D8) the hermetic gate drives: the monotonic SETTLED counter (summed across
    // all rails) plus the transient reserved holds. It is LOCATED by a CounterRef derived from the
    // chain's registry + the real agent `did:keri:`, so the standalone `verify-spend` (handed the
    // same --registry/--agent the wire prints below) opens the SAME counter — no separate verifier
    // repo, no session-key sentinel.
    let counter = auths_mcp_core::CounterRef::for_agent(chain.org_repo(), &chain.agent_did)
        .map_err(|e| anyhow::anyhow!("locate the durable cross-rail counter: {e}"))?;
    let budget = counter
        .open_budget(cap_cents)
        .map_err(|e| anyhow::anyhow!("open the durable cross-rail budget: {e}"))?;
    eprintln!(
        "auths-mcp-gateway: budget enforced from the DURABLE verifier-held cross-rail counter \
         ({record:?}, keyed to the agent delegation, one ${cap}.{rem:02} cap summed across ALL \
         rails) — the SAME counter the hermetic gate and the offline verify-spend open",
        record = counter.record_path(),
        cap = cap_cents.get() / 100,
        rem = cap_cents.get() % 100,
    );

    let spend_log = auths_mcp_core::resolve_spend_log(chain.org_repo(), &chain.agent_did);
    eprintln!(
        "auths-mcp-gateway: live-wire signing ON — agent={} root={}; every brokered call is signed. \
         Re-verify the spend log offline (trusting neither this gateway nor its operator) with:",
        chain.agent_did, chain.root_did,
    );
    // Point the re-verify command at the rotated spend-log DIRECTORY, not
    // `spend_log` above: this line prints at startup BEFORE any call, when the
    // rotated dir does not yet exist and `resolve_spend_log` falls back to the
    // flat path — but every brokered call writes to `spend-log/<delegation>/<period>.jsonl`.
    // `verify-spend --log <dir>` walks all period files, so the emitted command
    // audits the log this session actually writes.
    eprintln!(
        "auths-mcp-gateway: verify-spend-cmd: verify-spend --log {} --registry {} --agent {} --root {}",
        auths_mcp_core::spend_log_dir(chain.org_repo(), &chain.agent_did).display(),
        chain.org_repo().display(),
        chain.agent_did,
        chain.root_did,
    );

    // Continue the spend log's hash chain across restarts: the first call this session signs links
    // its `Auths-Prev` to the LAST record already on disk (or the genesis sentinel for a fresh log).
    let prev_binding = match auths_mcp_core::read_spend_log(&spend_log) {
        Ok(records) => records
            .last()
            .map(|r| auths_mcp_core::call_commit_binding(&r.call_commit))
            .unwrap_or_else(|| auths_mcp_core::SPEND_LOG_GENESIS.to_string()),
        Err(_) => auths_mcp_core::SPEND_LOG_GENESIS.to_string(),
    };

    // The revocation-propagation SLA: how often the delegator KEL is re-resolved so a mid-session
    // revoke is observed. Bounded default (30s); a shorter value tightens the window.
    let revocation_recheck = std::time::Duration::from_secs(
        std::env::var("AUTHS_MCP_REVOCATION_RECHECK_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30),
    );
    eprintln!(
        "auths-mcp-gateway: revocation propagation — the delegator KEL is re-resolved every {}s; \
         a mid-session `auths id agent revoke` stops the next call within that window",
        revocation_recheck.as_secs(),
    );

    let treasury = crate::treasury::TreasuryClient::from_env(&chain.root_did).map(Arc::new);
    // Resolve the payment mode from the SAME single opt-in the disclosure used (`--test-mode`
    // or its env twin) so the per-call cost extractor gates a mainnet x402 settle exactly as the
    // startup banner disclosed: real money only when real mode is active.
    let env_test = env_opts_into_test(std::env::var(TEST_MODE_ENV).ok().as_deref());
    let payment_mode = PaymentMode::resolve(cfg.test_mode || env_test);
    let proxy = GatewayProxy {
        downstream,
        budget: Arc::new(Mutex::new(budget)),
        chain: Arc::new(chain),
        gate: Arc::new(Mutex::new(gate)),
        revocation_recheck,
        last_resolved: Arc::new(Mutex::new(std::time::Instant::now())),
        next_call: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        rail: cfg.rail,
        prev_binding: Arc::new(Mutex::new(prev_binding)),
        treasury,
        verbose: std::env::var("AUTHS_MCP_VERBOSE").is_ok(),
        dispute_ref: cfg.dispute_ref,
        payment_mode,
    };

    // 2. Serve MCP UP to the agent over stdio, brokering each tools/call.
    let server = proxy
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("serving MCP to the agent failed: {e}"))?;

    server
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("gateway server loop: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_secs_handles_suffixes_and_bare_seconds() {
        // The grant TTL is anchored as the delegation expiry seal.
        assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
        assert_eq!(parse_ttl_secs("1s").unwrap(), 1);
        assert_eq!(parse_ttl_secs("2h").unwrap(), 7200);
        assert_eq!(parse_ttl_secs("7d").unwrap(), 604_800);
        // Bare seconds with no suffix.
        assert_eq!(parse_ttl_secs("45").unwrap(), 45);
        assert_eq!(parse_ttl_secs("  90  ").unwrap(), 90);
    }

    #[test]
    fn parse_ttl_secs_fails_closed_on_garbage() {
        // A malformed TTL must be an error, never a silently-unenforced bound.
        assert!(parse_ttl_secs("garbage").is_err());
        assert!(parse_ttl_secs("30x").is_err());
        assert!(parse_ttl_secs("").is_err());
        assert!(parse_ttl_secs("m").is_err());
    }

    #[test]
    fn parses_name_equals_value() {
        let v = CustodyVault::from_specs(&["DOWNSTREAM_API_KEY=sk-abc123".to_string()]).unwrap();
        assert!(v.is_armed());
        assert_eq!(v.names(), vec!["DOWNSTREAM_API_KEY"]);
    }

    #[test]
    fn empty_name_is_rejected() {
        let err = CustodyVault::from_specs(&["=sk-abc123".to_string()]).unwrap_err();
        assert!(err.contains("empty NAME"));
    }

    #[test]
    fn debug_redacts_the_secret_value() {
        // A custodied secret must never reach a log line through a derived `{:?}`.
        let secret = "sk-super-secret-do-not-leak";
        let v = CustodyVault::from_specs(&[format!("DOWNSTREAM_API_KEY={secret}")]).unwrap();
        let dbg = format!("{v:?}");
        assert!(
            !dbg.contains(secret),
            "Debug leaked the custodied secret value: {dbg}"
        );
        // The NAME is fine to surface (auditable WHICH credential is custodied).
        assert!(dbg.contains("DOWNSTREAM_API_KEY"));
    }

    #[test]
    fn empty_specs_is_unarmed() {
        let v = CustodyVault::from_specs(&[]).unwrap();
        assert!(!v.is_armed());
        assert!(v.names().is_empty());
    }

    #[test]
    fn bare_name_missing_from_env_is_rejected() {
        // A bare NAME adopts the value from the gateway's own env; absent, it errors
        // (never silently injects an empty credential) and never echoes a value.
        let absent = "AUTHS_MCP_DEFINITELY_UNSET_CREDENTIAL_X9Z";
        // SAFETY: single-threaded test; we only assert on the absence of this var.
        unsafe {
            std::env::remove_var(absent);
        }
        let err = CustodyVault::from_specs(&[absent.to_string()]).unwrap_err();
        assert!(err.contains(absent));
        assert!(err.contains("no value"));
    }
}
