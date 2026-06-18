//! The real-MCP `wrap` proxy (PRD §5 Build item 2 / D1).
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
//! non-auths client still works, unauthenticated, no receipt — PRD §6).
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
    Budget, Capability, PaymentMode, Receipt, SpendLogRecord, TEST_MODE_ENV, ToolCall,
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
/// and injects into the wrapped downstream, and which the agent never sees (PRD
/// §12). Each entry is an environment variable the downstream reads to authenticate
/// to its credentialed resource — exactly the "API key in an env var" majority §12
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
    /// from the GATEWAY. This is the §12 mechanism: the spawned downstream reads its
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
    /// The agent delegation identifier (`did:keri:…`) the durable cross-rail counter is
    /// keyed to — the counter sums ALL rails for THIS delegation. Defaults to a stable
    /// session key when the live-agent harness has not yet bound the agent's delegation
    /// on the wire (the deferred live leg); the counter SOURCE is durable regardless.
    pub agent_delegation: Option<String>,
    /// The downstream credential(s) the gateway custodies and injects into the
    /// wrapped downstream — the agent never holds them (PRD §12).
    pub custody: CustodyVault,
    /// The downstream MCP server command (everything after `--`).
    pub downstream: Vec<String>,
    /// Opt into SANDBOX payment rails. Real money is the default; this single flag
    /// (or `AUTHS_MCP_TEST_MODE=1`) is the deliberate opt-in to test rails.
    pub test_mode: bool,
    /// Resolve the payment mode, disclose it, and exit — a dry run that touches no
    /// rail and charges nothing.
    pub show_mode: bool,
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

/// The repo path the verifier holds the durable cross-rail counter under (the same
/// `budget-ledger` placement the gate persists to, alongside the KELs/registry the
/// verifier replays). Sourced from the gateway's own environment (`AUTHS_REPO`, then
/// `AUTHS_HOME`), never from the agent's request; falls back to `.auths` under the cwd.
fn verifier_repo_path() -> PathBuf {
    for var in ["AUTHS_REPO", "AUTHS_HOME"] {
        if let Ok(p) = std::env::var(var)
            && !p.is_empty()
        {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(".auths")
}

/// The directory the live wire builds its signing chain + registry under (org root, the
/// delegated agent, the scope seal, and the spend log). Honors `AUTHS_MCP_LIVE_DIR` (then
/// `LAB_DIR`) so a demo/harness can point the chain + log at a known path it later audits
/// with `verify-spend`; otherwise a per-process temp dir.
fn live_chain_dir() -> PathBuf {
    for var in ["AUTHS_MCP_LIVE_DIR", "LAB_DIR"] {
        if let Ok(p) = std::env::var(var)
            && !p.is_empty()
        {
            return PathBuf::from(p);
        }
    }
    std::env::temp_dir().join(format!("auths-mcp-live-{}", std::process::id()))
}

/// The delegation key the durable counter is keyed to on the live wire. Until the
/// live-agent harness binds the agent's `did:keri:` per session (the deferred live
/// leg), a stable filesystem-safe session key keeps the durable counter rooted; the
/// COUNTER SOURCE (durable, cross-rail, verifier-held) is what #281 wires.
fn wire_delegation_key(cfg: &WrapConfig) -> String {
    cfg.agent_delegation
        .clone()
        .unwrap_or_else(|| "wrap-session".to_string())
}

/// The metered cost of one brokered `tools/call`, plus the rail it settles on — the
/// inputs the wire's budget enforcement reserves/settles against the durable
/// cross-rail counter. A non-metered call (e.g. `fs.read`) carries a zero cost and no
/// rail; a metered call (e.g. `paid_call`) carries its known cost and its rail.
///
/// On the live wire the per-call *cost extraction* from a rail's charge response is
/// the metered-rail wiring (a follow-on); what #281 wires is that whatever cost a call
/// carries is enforced against the SAME durable verifier-held [`CrossRailBudget`] the
/// hermetic gate uses — not a separate in-memory tally.
#[derive(Debug, Clone, Default)]
pub struct CallCost {
    /// The cents this call would settle against the cross-rail cap (0 = non-metered).
    pub cost_cents: u64,
    /// The pre-authorization ceiling reserved before the rail is touched. Defaults to
    /// `cost_cents` for a known-cost call.
    pub reserve_ceiling_cents: u64,
    /// The payment rail this metered call settles on (cross-rail attribution).
    pub rail: Option<String>,
}

impl CallCost {
    /// A non-metered call: nothing to reserve or settle (e.g. `fs.read`).
    pub fn free() -> Self {
        Self::default()
    }

    /// A metered call with a known cost on `rail`: reserve and settle the same amount.
    pub fn metered(cost_cents: u64, rail: impl Into<String>) -> Self {
        Self::metered_with_ceiling(cost_cents, cost_cents, rail)
    }

    /// A metered call on `rail` that reserves a `reserve_ceiling_cents` ceiling before
    /// the rail is touched and settles `cost_cents` after (the slack is released). For a
    /// known-cost call the two are equal; a metered call whose final cost is bounded but
    /// not yet known reserves the ceiling.
    pub fn metered_with_ceiling(
        cost_cents: u64,
        reserve_ceiling_cents: u64,
        rail: impl Into<String>,
    ) -> Self {
        Self {
            cost_cents,
            reserve_ceiling_cents,
            rail: Some(rail.into()),
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
    /// budget — the SAME [`auths_mcp_core::PerCallGate`] the hermetic gate drives.
    gate: Arc<auths_mcp_core::PerCallGate>,
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
}

impl GatewayProxy {
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
        // rail, an agent cannot bypass metering by omitting a per-call field.
        if let Some(rail) = self.rail.as_deref() {
            let ceiling = args
                .and_then(|m| m.get("amount_atomic"))
                .and_then(|v| v.as_u64())
                .map(auths_mcp_core::rail::atomic_usdc_to_cents_ceiling)
                .or_else(|| {
                    args.and_then(|m| m.get("_auths_reserve_ceiling_cents"))
                        .and_then(|v| v.as_u64())
                })
                .unwrap_or(0);
            return CallCost::metered_with_ceiling(ceiling, ceiling, rail);
        }

        // No operator rail: a non-payment downstream. Honor an explicit per-call declaration so a
        // metered downstream config can still drive the durable counter; else non-metered.
        let Some(args) = args else {
            return CallCost::free();
        };
        let cost_cents = args
            .get("_auths_cost_cents")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if cost_cents == 0 {
            return CallCost::free();
        }
        let reserve_ceiling_cents = args
            .get("_auths_reserve_ceiling_cents")
            .and_then(|v| v.as_u64())
            .unwrap_or(cost_cents);
        match args.get("_auths_rail").and_then(|v| v.as_str()) {
            Some(rail) if reserve_ceiling_cents == cost_cents => CallCost::metered(cost_cents, rail),
            Some(rail) => CallCost::metered_with_ceiling(cost_cents, reserve_ceiling_cents, rail),
            None => CallCost {
                cost_cents,
                reserve_ceiling_cents,
                rail: None,
            },
        }
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
        let tool = request.name.to_string();

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
            cost_cents: cost.cost_cents,
        };
        let capability = tool_call.capability();
        let canonical = tool_call.canonical_bytes();
        let idx = self
            .next_call
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Link this call to the prior persisted record (the genesis sentinel for the first) via the
        // signed `Auths-Prev` trailer, so the audit can verify the spend log is a complete chain.
        let prev_binding = self.prev_binding.lock().await.clone();
        let (proof_bytes, proof_sha) = self
            .chain
            .sign_call(idx, &canonical, capability.as_str(), &prev_binding)
            .map_err(|e| McpError::internal_error(format!("sign the brokered call: {e}"), None))?;

        // Authenticate + pre-authorize over the SIGNED proof: the gate verifies the proof
        // (scope ⊆ grant, live, unrevoked) AND reserves the ceiling against the durable
        // cross-rail counter BEFORE the downstream/rail is touched. A non-Allowed verdict
        // fails closed here — the downstream is never invoked. This is the SAME
        // `PerCallGate::judge` the hermetic gate runs, now on the live wire.
        let now = Utc::now();
        let decision = {
            let mut budget = self.budget.lock().await;
            self.gate
                .judge(
                    cost.rail.as_deref(),
                    cost.reserve_ceiling_cents,
                    &proof_bytes,
                    now,
                    &mut budget,
                )
                .await
                .map_err(|e| McpError::internal_error(format!("per-call gate: {e}"), None))?
        };
        // Forward to the downstream ONLY on a forwarding verdict — a refused call never touches
        // it. Either way the signed proof + receipt are persisted below, so an out-of-scope or
        // over-budget ATTEMPT is recorded too (not silently dropped), exactly as the replay gate
        // records it.
        let mut verdict = decision.verdict.clone();
        let mut cumulative = decision.cumulative_cents;
        // For a metered call the rail's response carries the ACTUAL settled cost + reference; these
        // are filled in from that response below and persisted, so the audit sums the agent-signed
        // actual — never a number the agent declared.
        let mut rail_response: Option<Vec<u8>> = None;
        let mut settlement_commit: Option<Vec<u8>> = None;
        let mut settled_charge_ref: Option<String> = None;
        let forwarded = if decision.forwards() {
            let result = self.downstream.call_tool(request).await.map_err(|e| {
                McpError::internal_error(format!("downstream tools/call failed: {e}"), None)
            })?;

            // A metered call's ACTUAL cost is read from the downstream's own response (the rail's
            // settlement), not a number the agent declared. Extract it and keep the raw response so
            // the offline audit can re-extract + cross-check the agent-signed amount.
            let actual_cents = if let Some(rail) = cost.rail.as_deref() {
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
                let extracted = auths_mcp_core::extract_rail_cost(rail, &resp).map_err(|e| {
                    McpError::internal_error(
                        format!("extract `{rail}` cost from the rail response: {e}"),
                        None,
                    )
                })?;
                rail_response = Some(resp);
                settled_charge_ref = Some(extracted.reference);
                extracted.amount_cents
            } else {
                cost.cost_cents
            };

            // Settle the ACTUAL cost into the durable counter, releasing the reservation slack.
            if let Some(hold) = decision.hold {
                let mut budget = self.budget.lock().await;
                let (settle_verdict, new_cumulative) = self
                    .gate
                    .settle(&mut budget, hold, actual_cents)
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
            if let (Some(rail), Some(charge_ref)) = (cost.rail.as_deref(), settled_charge_ref.as_deref())
                && actual_cents > 0
            {
                let (bytes, _sha) = self
                    .chain
                    .sign_settlement(
                        idx,
                        &auths_mcp_core::call_commit_binding(&proof_bytes),
                        rail,
                        actual_cents,
                        charge_ref,
                        cumulative,
                    )
                    .map_err(|e| {
                        McpError::internal_error(format!("sign the settlement: {e}"), None)
                    })?;
                settlement_commit = Some(bytes);
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
            cost.rail.as_deref(),
            settled_charge_ref.as_deref(),
            decision.reserved_cents,
            cumulative,
            now,
        );
        // This record's binding — what the NEXT call's `Auths-Prev` links to. Computed from the
        // bytes about to be stored, before they move into the record.
        let new_binding = auths_mcp_core::call_commit_binding(&proof_bytes);
        if let Err(e) = crate::spend_log::append(
            self.chain.org_repo(),
            &self.chain.agent_did,
            &SpendLogRecord {
                call_commit: proof_bytes,
                receipt,
                rail: cost.rail.clone(),
                rail_response,
                settlement_commit,
            },
        ) {
            return Err(McpError::internal_error(
                format!("persist the signed spend-log record: {e}"),
                None,
            ));
        }
        // Advance the chain head so the next brokered call links to this record.
        *self.prev_binding.lock().await = new_binding;

        let rail_tag = cost
            .rail
            .as_deref()
            .map(|r| format!(" rail={r}"))
            .unwrap_or_default();
        let proof_short = &proof_sha[..proof_sha.len().min(12)];
        match forwarded {
            Some(result) => {
                eprintln!(
                    "auths-mcp-gateway: brokered + SIGNED tools/call `{tool}`{rail_tag} (cap={}) — \
                     forwarded; cross-rail settled total ${}.{:02}; proof={proof_short}",
                    capability.as_str(),
                    cumulative / 100,
                    cumulative % 100,
                );
                Ok(result)
            }
            None => {
                eprintln!(
                    "auths-mcp-gateway: REFUSED + SIGNED tools/call `{tool}`{rail_tag} ({}) — \
                     downstream NOT touched; proof={proof_short}",
                    verdict.code(),
                );
                Err(McpError::invalid_request(
                    format!(
                        "{}: the per-call gate refused this call before the downstream was touched",
                        verdict.code()
                    ),
                    None,
                ))
            }
        }
    }
}

/// Spawn the wrapped downstream as a credentialed child with the custodied secret
/// injected from the GATEWAY, and return its stdout — the §12 brokered path proven
/// directly: the gateway supplies a downstream credential the agent never held.
///
/// This is the custody self-check the gateway runs before it serves MCP up to the
/// agent when it custodies a downstream credential. It demonstrates that the
/// brokered path (gateway → downstream, credential injected) reaches the
/// credentialed resource, while the same downstream invoked WITHOUT the gateway
/// (the agent's bypass) lacks the credential and is refused by the downstream
/// itself. The custodied secret is injected only into this child's environment; it
/// is never logged, echoed, or placed in the gateway's own surfaced output.
async fn brokered_custody_check(
    downstream: &[String],
    custody: &CustodyVault,
) -> anyhow::Result<std::process::Output> {
    let mut command = tokio::process::Command::new(&downstream[0]);
    command.args(&downstream[1..]);
    // Inject the custodied credential into the downstream child from the gateway.
    custody.inject(&mut command);
    command
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn downstream `{}`: {e}", downstream.join(" ")))
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

    let cap_cents = cfg
        .budget
        .as_deref()
        .map(Budget::parse)
        .unwrap_or(Budget::Cents(u64::MAX))
        .cap_cents();

    // Custody self-check (PRD §12): if the gateway custodies a downstream
    // credential, prove the brokered path reaches the credentialed downstream WITH
    // the injected secret before serving the agent. The credential is sourced from
    // the gateway and injected into the downstream child's environment; the agent
    // (and the agent-visible MCP wire) never holds it. We surface only the
    // downstream's own result — NEVER the secret. A bypass (the same downstream
    // invoked without the gateway) lacks the credential and the downstream refuses
    // it; that half is unbypassable by construction of the credentialed resource.
    if cfg.custody.is_armed() {
        // Audit which credential is custodied — by NAME only, never the value.
        eprintln!(
            "auths-mcp-gateway: custody armed — gateway holds downstream credential(s) {:?}; \
             the agent connects with only its delegation and never sees the secret",
            cfg.custody.names(),
        );
        let out = brokered_custody_check(&cfg.downstream, &cfg.custody).await?;
        // Forward the downstream's own stdout (its real result) to the brokered
        // surface so a caller observes the credentialed downstream was reached
        // THROUGH the gateway. The secret is not in this stream — only the
        // downstream's response is.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stdout = stdout.trim_end();
        if !out.status.success() {
            // The downstream refused even WITH the gateway's credential — surface
            // its refusal (stderr), not the secret. This is a downstream/config
            // problem, not a custody bypass.
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!(
                "brokered custody check: downstream refused even with the custodied credential: {}",
                stderr.trim_end()
            );
        }
        println!(
            "auths-mcp-gateway: brokered (custodied credential injected) → downstream reached: {stdout}"
        );
        // The preflight ran the downstream to completion (exit 0) with the
        // custodied credential injected — a one-shot credentialed tool, not a
        // long-lived MCP server. The brokered custody path is proven; there is no
        // persistent server to proxy, so return. (A long-lived MCP-over-stdio
        // server would not be wrapped through this one-shot preflight surface — it
        // is served below, with the same credential injected into the proxied
        // child, which is the always-on §12 mechanism.)
        return Ok(());
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

    // Open the DURABLE cross-rail budget the live wire enforces against — the SAME
    // verifier-held CrossRailBudget (D8) the hermetic gate drives: the monotonic SETTLED
    // counter persisted under `<repo>/budget-ledger`, keyed to the agent delegation,
    // summed across all rails, plus the transient reserved holds. This replaces the v0
    // in-memory per-session tally, so the live `wrap` wire cannot allow a cross-rail call
    // the gate refuses (#281).
    let repo = verifier_repo_path();
    let delegation = wire_delegation_key(&cfg);
    let budget = CrossRailBudget::open(&repo, &delegation, cap_cents)
        .map_err(|e| anyhow::anyhow!("open durable cross-rail budget counter: {e}"))?;
    eprintln!(
        "auths-mcp-gateway: budget enforced from the DURABLE verifier-held cross-rail counter \
         (budget-ledger under {repo:?}, keyed to the agent delegation, one ${cap}.{rem:02} cap \
         summed across ALL rails) — the SAME counter the hermetic gate uses",
        repo = repo,
        cap = cap_cents / 100,
        rem = cap_cents % 100,
    );

    // Build the agent's delegation chain (its delegated signing key + the registry the
    // verifier replays) so every brokered call is signed on the live wire exactly as the
    // hermetic gate signs it. The agent also holds a narrow `settle` capability to sign its
    // own settlement commits. The gate resolves the agent + delegator KELs from the chain's
    // registry — the same resolution `verify-spend` runs offline over the persisted log.
    let lab = live_chain_dir();
    std::fs::create_dir_all(&lab)
        .map_err(|e| anyhow::anyhow!("create the live signing directory {lab:?}: {e}"))?;
    let mut signing_scope = cfg.scope.clone();
    if !signing_scope.iter().any(|c| c == "settle") {
        signing_scope.push("settle".to_string());
    }
    let chain = crate::chain::Chain::build(&lab, &signing_scope)
        .map_err(|e| anyhow::anyhow!("build the agent delegation chain for live signing: {e}"))?;
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(chain.org_repo()));
    let gate =
        auths_mcp_core::PerCallGate::resolve(&registry, &chain.agent_did, &chain.root_did)
            .map_err(|e| anyhow::anyhow!("resolve the per-call gate over the live registry: {e}"))?;
    let spend_log = auths_mcp_core::spend_log_path(chain.org_repo(), &chain.agent_did);
    eprintln!(
        "auths-mcp-gateway: live-wire signing ON — agent={} root={}; every brokered call is signed. \
         Re-verify the spend log offline (trusting neither this gateway nor its operator) with:",
        chain.agent_did, chain.root_did,
    );
    eprintln!(
        "auths-mcp-gateway: verify-spend-cmd: verify-spend --log {} --registry {} --agent {} --root {}",
        spend_log.display(),
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

    let proxy = GatewayProxy {
        downstream,
        budget: Arc::new(Mutex::new(budget)),
        chain: Arc::new(chain),
        gate: Arc::new(gate),
        next_call: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        rail: cfg.rail,
        prev_binding: Arc::new(Mutex::new(prev_binding)),
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
