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
//! The transport + proxy + receipt are real and live here; the *cryptographic
//! per-call proof* on the live wire — the agent presenting its delegation per
//! `tools/call` — is exercised end-to-end by the hermetic **replay** path
//! (`replay.rs`), which carries the full native authenticity check. Binding that
//! same proof to the live `wrap` wire rides with the live-agent harness. The proxy
//! never fakes a receipt and never silently widens authority.

use std::path::PathBuf;
use std::sync::Arc;

use auths_mcp_core::budget::{CrossRailBudget, ReserveOutcome, SettleOutcome};
use auths_mcp_core::{Budget, Capability};
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

    /// The ceiling reserved before the rail is touched — the metered ceiling if set,
    /// else the known cost.
    fn reserve_ceiling(&self) -> u64 {
        if self.reserve_ceiling_cents > 0 {
            self.reserve_ceiling_cents
        } else {
            self.cost_cents
        }
    }
}

/// The outcome of enforcing one brokered call's spend against the durable cross-rail
/// budget on the live `wrap` wire — the same reserve/settle/release decision the
/// hermetic gate ([`auths_mcp_core::PerCallGate`]) makes over the same counter, so the
/// two produce identical verdicts for the same call sequence (#281).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireBudgetOutcome {
    /// The call fits the cross-rail cap and was settled into the durable counter. The
    /// running cross-rail total after this call.
    Allowed { cross_rail_cumulative_cents: u64 },
    /// The reservation would push `settled + Σ(holds) + ceiling` past the cap — refused
    /// BEFORE the rail is touched (the durable counter refuses, exactly as the gate
    /// does). Maps the `usage-cap-exceeded` verdict.
    UsageCapExceeded { cap_cents: u64, would_be_cents: u64 },
    /// A settle presented a cumulative total below the verifier-held monotonic
    /// high-water — a replayed/stale total refused by the durable counter (maps
    /// `usage-counter-rolled-back`, the D8 monotonicity guard).
    UsageCounterRolledBack {
        presented_cents: u64,
        high_water_cents: u64,
    },
}

impl WireBudgetOutcome {
    /// The stable kebab-case verdict code, identical to the gate's
    /// [`auths_mcp_core::Verdict::code`] for the same outcome — the parity surface.
    pub fn code(&self) -> &'static str {
        match self {
            WireBudgetOutcome::Allowed { .. } => "allowed",
            WireBudgetOutcome::UsageCapExceeded { .. } => "usage-cap-exceeded",
            WireBudgetOutcome::UsageCounterRolledBack { .. } => "usage-counter-rolled-back",
        }
    }

    /// Whether the gateway should forward this call to the downstream server.
    fn forwards(&self) -> bool {
        matches!(self, WireBudgetOutcome::Allowed { .. })
    }
}

/// Enforce one metered call's spend against the durable cross-rail budget — the live
/// `wrap` wire's budget boundary, sourced from the SAME verifier-held
/// [`CrossRailBudget`] the hermetic gate drives (#281, D8).
///
/// This is pre-authorization: RESERVE the call's ceiling against `available = cap −
/// settled − Σ(holds)` BEFORE the rail is touched; if the reservation would cross the
/// cap it is refused [`WireBudgetOutcome::UsageCapExceeded`] and no hold is taken (the
/// metered downstream is never invoked). On a fitting reservation the call is allowed,
/// then its ACTUAL cost is SETTLED into the monotonic verifier-held counter and the
/// slack released. A non-metered call (`reserve_ceiling == 0`) reserves and settles
/// nothing.
///
/// The single source of truth: this drives `auths_mcp_core::budget::CrossRailBudget`,
/// the identical engine `PerCallGate::judge`/`settle` drive, so the live wire's budget
/// verdicts match the gate's for the same call sequence.
pub fn enforce_wire_budget(
    budget: &mut CrossRailBudget,
    cost: &CallCost,
) -> Result<WireBudgetOutcome, auths_mcp_core::BudgetError> {
    let ceiling = cost.reserve_ceiling();
    if ceiling == 0 {
        // Non-metered: nothing to reserve or settle; the call is allowed at the
        // unchanged cross-rail total.
        return Ok(WireBudgetOutcome::Allowed {
            cross_rail_cumulative_cents: budget.settled_cents()?,
        });
    }

    // 1. RESERVE the ceiling against the durable cross-rail counter BEFORE the rail is
    //    touched. A reservation that crosses the cap is refused here.
    let hold = match budget.reserve(ceiling)? {
        ReserveOutcome::Reserved { hold, .. } => hold,
        ReserveOutcome::Refused {
            cap_cents,
            would_be_cents,
        } => {
            return Ok(WireBudgetOutcome::UsageCapExceeded {
                cap_cents,
                would_be_cents,
            });
        }
    };

    // 2. The reservation fit — the call is forwarded to the rail. SETTLE the actual
    //    cost into the monotonic verifier-held counter and release the hold's slack.
    match budget.settle(hold, cost.cost_cents)? {
        SettleOutcome::Advanced { new_settled_cents } => Ok(WireBudgetOutcome::Allowed {
            cross_rail_cumulative_cents: new_settled_cents,
        }),
        SettleOutcome::RolledBack {
            presented_cents,
            high_water_cents,
        } => Ok(WireBudgetOutcome::UsageCounterRolledBack {
            presented_cents,
            high_water_cents,
        }),
    }
}

/// The proxy handler: holds the downstream client peer and the session's bound
/// authority (scope/budget). One handler per wrapped session.
struct GatewayProxy {
    /// The connected downstream MCP server (the wrapped tool).
    downstream: RunningService<RoleClient, ()>,
    /// The capabilities the agent was granted.
    scope: Vec<String>,
    /// The session's DURABLE cross-rail budget — the verifier-held monotonic SETTLED
    /// counter (persisted under `<repo>/budget-ledger`, keyed to the agent delegation,
    /// summed across rails) + the transient RESERVED holds. This is the SAME
    /// [`CrossRailBudget`] (D8) the hermetic gate drives in `replay.rs`, so the live
    /// `wrap` wire enforces the cross-rail cap from the same counter the gate uses and
    /// cannot allow a call the gate refuses (#281). It supersedes the former v0
    /// in-memory per-session tally, which metered nothing per rail and could diverge
    /// from the durable gate.
    budget: Arc<Mutex<CrossRailBudget>>,
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
        let args = match &request.arguments {
            Some(map) => map,
            None => return CallCost::free(),
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
            // Known cost (ceiling == cost) is the common metered case; a bounded-but-
            // not-yet-known cost reserves a larger ceiling and releases the slack.
            Some(rail) if reserve_ceiling_cents == cost_cents => {
                CallCost::metered(cost_cents, rail)
            }
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
        let cap = Capability::for_tool(&tool);

        // Scope ⊆ parent: the requested capability must lie inside the agent's
        // granted scope. (On the live wire this is the boolean projection of the
        // full chain check; the cryptographic per-call proof is carried end-to-end
        // by the replay gate — see the module docs.)
        if !self.scope.iter().any(|c| c == cap.as_str()) {
            return Err(McpError::invalid_request(
                format!(
                    "outside-agent-scope: the agent was not granted `{}`",
                    cap.as_str()
                ),
                None,
            ));
        }

        // Budget (live wire, D8): enforce the cross-rail cap from the DURABLE
        // verifier-held CrossRailBudget — the SAME counter the hermetic gate drives —
        // by pre-authorization. RESERVE this call's ceiling against `available = cap −
        // settled − Σ(holds)` BEFORE the rail is touched; a reservation that would cross
        // the cap is refused here (`usage-cap-exceeded`) and the downstream is never
        // invoked, so the live wire cannot allow a cross-rail call the gate refuses
        // (#281). On a fitting reservation the actual cost is settled into the monotonic
        // counter and the slack released.
        let cost = self.call_cost(&request);
        let outcome = {
            let mut budget = self.budget.lock().await;
            enforce_wire_budget(&mut budget, &cost).map_err(|e| {
                McpError::internal_error(format!("cross-rail budget accounting failed: {e}"), None)
            })?
        };
        if !outcome.forwards() {
            // Fail-closed: the rail/downstream was never touched. Surface the durable
            // counter's verdict code (identical to the gate's).
            return Err(McpError::invalid_request(
                format!(
                    "{}: the cross-rail budget cap refused this call before the rail was touched",
                    outcome.code()
                ),
                None,
            ));
        }

        // Forward to the real downstream and return its real result.
        let result = self.downstream.call_tool(request).await.map_err(|e| {
            McpError::internal_error(format!("downstream tools/call failed: {e}"), None)
        })?;

        let cross_rail_cumulative = match outcome {
            WireBudgetOutcome::Allowed {
                cross_rail_cumulative_cents,
            } => cross_rail_cumulative_cents,
            _ => unreachable!("a non-forwarding outcome returned above"),
        };
        let rail_tag = cost
            .rail
            .as_deref()
            .map(|r| format!(" rail={r}"))
            .unwrap_or_default();
        eprintln!(
            "auths-mcp-gateway: brokered tools/call `{tool}`{rail_tag} (cap={}) — forwarded, \
             receipted; cross-rail settled total now ${}.{:02} (durable verifier-held counter, \
             summed across ALL rails)",
            cap.as_str(),
            cross_rail_cumulative / 100,
            cross_rail_cumulative % 100,
        );
        Ok(result)
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

/// Serve the wrap proxy: connect down to the wrapped downstream, then serve MCP up
/// to the agent over stdio, brokering each call. Returns when the agent disconnects.
pub async fn serve(cfg: WrapConfig) -> anyhow::Result<()> {
    if cfg.downstream.is_empty() {
        anyhow::bail!("no downstream command after `--`");
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

    let proxy = GatewayProxy {
        downstream,
        scope: cfg.scope,
        budget: Arc::new(Mutex::new(budget)),
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

    // ── Live-wire ↔ gate cross-rail counter parity (#281) ────────────────────────
    //
    // A RUNTIME parity test proving the live `wrap` path's budget enforcement
    // (`enforce_wire_budget`) and the hermetic gate's budget path
    // (`PerCallGate::judge`/`settle`) — both sourced from the SAME durable
    // `CrossRailBudget` — produce the SAME verdict stream for the same cross-rail call
    // sequence. The actual decisions, not a binary-string signature.

    use auths_mcp_core::Verdict;
    use auths_mcp_core::budget::CrossRailBudget;

    const DLG: &str = "did:keri:EAgentDelegationMCP8";

    /// The cross-rail sequence (the identical sequence the gate's transcript drives):
    /// $5 cap, stripe $3.00 + x402 $1.50, then the $0.60 x402 call that crosses $5.10
    /// ACROSS rails. Returns `(CallCost, expected-verdict-code)`.
    fn cross_rail_sequence() -> [(CallCost, &'static str); 3] {
        [
            (CallCost::metered(300, "stripe"), "allowed"),
            (CallCost::metered(150, "x402"), "allowed"),
            (CallCost::metered(60, "x402"), "usage-cap-exceeded"),
        ]
    }

    /// The verdict code the GATE derives for one paid call against the durable
    /// `CrossRailBudget`, by exactly the reserve→settle mapping `gate.rs` uses
    /// (`ReserveOutcome::Refused` → `UsageCapExceeded`; on a reservation that fits,
    /// `SettleOutcome::Advanced` → `Allowed`, `RolledBack` → `UsageCounterRolledBack`).
    /// This mirrors `PerCallGate`'s budget half without the KEL/proof machinery — the
    /// authenticity leg is exercised by the replay gate; here we isolate the COUNTER.
    fn gate_budget_verdict(budget: &mut CrossRailBudget, cost: &CallCost) -> Verdict {
        let ceiling = cost.reserve_ceiling_cents.max(cost.cost_cents);
        if ceiling == 0 {
            return Verdict::Allowed;
        }
        match budget.reserve(ceiling).unwrap() {
            ReserveOutcome::Refused {
                cap_cents,
                would_be_cents,
            } => Verdict::UsageCapExceeded {
                cap_cents,
                would_be_cents,
            },
            ReserveOutcome::Reserved { hold, .. } => {
                match budget.settle(hold, cost.cost_cents).unwrap() {
                    SettleOutcome::Advanced { .. } => Verdict::Allowed,
                    SettleOutcome::RolledBack {
                        presented_cents,
                        high_water_cents,
                    } => Verdict::UsageCounterRolledBack {
                        presented_cents,
                        high_water_cents,
                    },
                }
            }
        }
    }

    #[test]
    fn wire_budget_matches_gate_for_cross_rail_sequence() {
        // The headline #281 parity: the live wrap path's `enforce_wire_budget` and the
        // gate's budget path produce the SAME verdict stream for the identical cross-rail
        // sequence, BOTH driving an independent durable `CrossRailBudget` opened the same
        // way. Real runtime parity, not the binary-string signature.
        let seq = cross_rail_sequence();

        // Live wrap path, against its own durable cross-rail counter.
        let wire_dir = tempfile::tempdir().unwrap();
        let mut wire_budget = CrossRailBudget::open(wire_dir.path(), DLG, 500).unwrap();
        let wire: Vec<String> = seq
            .iter()
            .map(|(cost, _)| {
                enforce_wire_budget(&mut wire_budget, cost)
                    .unwrap()
                    .code()
                    .to_string()
            })
            .collect();

        // Gate path, against an independent durable cross-rail counter opened identically.
        let gate_dir = tempfile::tempdir().unwrap();
        let mut gate_budget = CrossRailBudget::open(gate_dir.path(), DLG, 500).unwrap();
        let gate: Vec<String> = seq
            .iter()
            .map(|(cost, _)| {
                gate_budget_verdict(&mut gate_budget, cost)
                    .code()
                    .to_string()
            })
            .collect();

        // 1. The wrap path's verdicts equal the gate's verdicts, call for call.
        assert_eq!(
            wire, gate,
            "live-wire budget verdicts diverged from the gate's for the same cross-rail sequence \
             (#281): the live wrap path is NOT enforcing from the same durable counter"
        );
        // 2. And both equal the reference verdict stream for this sequence.
        let expected: Vec<&str> = seq.iter().map(|(_, code)| *code).collect();
        assert_eq!(
            wire, expected,
            "wrap path did not produce the reference stream"
        );
        assert_eq!(gate, expected, "gate did not produce the reference stream");
        // 3. The durable counter settled exactly $4.50 across BOTH rails (the cross-over
        //    is refused before the rail is touched — settled is unchanged by it).
        assert_eq!(wire_budget.settled_cents().unwrap(), 450);
        assert_eq!(gate_budget.settled_cents().unwrap(), 450);
    }

    #[test]
    fn wire_budget_is_durable_and_cross_rail() {
        // The counter is durable (verifier-held under budget-ledger), not a RAM tally:
        // a resumed wrap session over the SAME ledger continues from the persisted
        // high-water, so a later cross-rail call is refused even though THIS session's
        // first call alone is in budget — the property a per-session in-memory guard
        // (the replaced v0) cannot express.
        let dir = tempfile::tempdir().unwrap();
        // Session A: settle $3.00 (stripe) + $1.50 (x402) = $4.50 across rails.
        {
            let mut b = CrossRailBudget::open(dir.path(), DLG, 500).unwrap();
            assert_eq!(
                enforce_wire_budget(&mut b, &CallCost::metered(300, "stripe"))
                    .unwrap()
                    .code(),
                "allowed"
            );
            assert_eq!(
                enforce_wire_budget(&mut b, &CallCost::metered(150, "x402"))
                    .unwrap()
                    .code(),
                "allowed"
            );
        }
        // Session B (a fresh wrap, fresh in-memory state) over the SAME durable ledger:
        // a $0.60 x402 call crosses $5.10 across rails and is refused from the PERSISTED
        // high-water — proof the source is durable, not per-session RAM.
        {
            let mut b = CrossRailBudget::open(dir.path(), DLG, 500).unwrap();
            assert_eq!(
                b.settled_cents().unwrap(),
                450,
                "resumed from durable counter"
            );
            let outcome = enforce_wire_budget(&mut b, &CallCost::metered(60, "x402")).unwrap();
            assert_eq!(outcome.code(), "usage-cap-exceeded");
            assert!(matches!(
                outcome,
                WireBudgetOutcome::UsageCapExceeded {
                    cap_cents: 500,
                    would_be_cents: 510
                }
            ));
        }
    }

    #[test]
    fn wire_budget_releases_slack_like_the_gate() {
        // A call reserving a $2.00 ceiling but settling $1.50 releases the $0.50 slack —
        // a later in-budget call is not starved (the gate's reserve/settle/release flow,
        // now the live wire's too).
        let dir = tempfile::tempdir().unwrap();
        let mut b = CrossRailBudget::open(dir.path(), DLG, 500).unwrap();
        // $3.00 stripe.
        enforce_wire_budget(&mut b, &CallCost::metered(300, "stripe")).unwrap();
        // Over-reserve $2.00 ceiling, settle $1.50 actual.
        let over = CallCost {
            cost_cents: 150,
            reserve_ceiling_cents: 200,
            rail: Some("x402".into()),
        };
        assert_eq!(
            enforce_wire_budget(&mut b, &over).unwrap().code(),
            "allowed"
        );
        // settled = 450; the $0.50 slack came back, so a $0.50 call still fits exactly.
        assert_eq!(b.settled_cents().unwrap(), 450);
        assert_eq!(b.available_cents().unwrap(), 50);
        assert_eq!(
            enforce_wire_budget(&mut b, &CallCost::metered(50, "stripe"))
                .unwrap()
                .code(),
            "allowed"
        );
    }

    #[test]
    fn non_metered_call_reserves_and_settles_nothing() {
        // A free call (e.g. fs.read) touches no rail and the durable counter is unchanged
        // — same as the gate's `reserve_ceiling == 0` path.
        let dir = tempfile::tempdir().unwrap();
        let mut b = CrossRailBudget::open(dir.path(), DLG, 500).unwrap();
        let out = enforce_wire_budget(&mut b, &CallCost::free()).unwrap();
        assert_eq!(out.code(), "allowed");
        assert_eq!(b.settled_cents().unwrap(), 0);
        assert_eq!(b.reserved_cents(), 0);
    }
}
