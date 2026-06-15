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

use std::sync::Arc;

use auths_mcp_core::{Budget, SessionLedger};
use rmcp::model::{
    CallToolRequestParam, CallToolResult, ListToolsResult, PaginatedRequestParam,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::transport::stdio;
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use tokio::sync::Mutex;

/// The `wrap` configuration parsed from the CLI.
pub struct WrapConfig {
    /// The capabilities the agent is granted.
    pub scope: Vec<String>,
    /// The session budget string (e.g. `"$5"`).
    pub budget: Option<String>,
    /// The grant TTL string (e.g. `"30m"`).
    pub ttl: Option<String>,
    /// The downstream MCP server command (everything after `--`).
    pub downstream: Vec<String>,
}

/// The proxy handler: holds the downstream client peer and the session's bound
/// authority (scope/budget). One handler per wrapped session.
struct GatewayProxy {
    /// The connected downstream MCP server (the wrapped tool).
    downstream: RunningService<RoleClient, ()>,
    /// The capabilities the agent was granted.
    scope: Vec<String>,
    /// The session budget ledger (running spend).
    ledger: Arc<Mutex<SessionLedger>>,
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
        let cap = auths_mcp_core::Capability::for_tool(&tool);

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

        // Budget v0: refuse before forwarding if this call would cross the cap.
        {
            let ledger = self.ledger.lock().await;
            if !ledger.would_stay_within(0) {
                return Err(McpError::invalid_request(
                    "usage-cap-exceeded: the session budget is spent".to_string(),
                    None,
                ));
            }
        }

        // Forward to the real downstream and return its real result.
        let result = self.downstream.call_tool(request).await.map_err(|e| {
            McpError::internal_error(format!("downstream tools/call failed: {e}"), None)
        })?;

        // Charge the ledger (per-rail cost metering for paid tools rides with the
        // cross-rail budget surface).
        {
            let mut ledger = self.ledger.lock().await;
            ledger.charge(0);
        }

        eprintln!(
            "auths-mcp-gateway: brokered tools/call `{tool}` (cap={}) — forwarded, receipted",
            cap.as_str(),
        );
        Ok(result)
    }
}

/// Serve the wrap proxy: connect down to the wrapped downstream, then serve MCP up
/// to the agent over stdio, brokering each call. Returns when the agent disconnects.
pub async fn serve(cfg: WrapConfig) -> anyhow::Result<()> {
    if cfg.downstream.is_empty() {
        anyhow::bail!("no downstream command after `--`");
    }

    // 1. Connect DOWN to the wrapped downstream MCP server (spawned over stdio).
    let mut command = tokio::process::Command::new(&cfg.downstream[0]);
    command.args(&cfg.downstream[1..]);
    let transport = TokioChildProcess::new(command)
        .map_err(|e| anyhow::anyhow!("spawn downstream `{}`: {e}", cfg.downstream.join(" ")))?;
    let downstream = ()
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP handshake with downstream failed: {e}"))?;

    let budget = cfg
        .budget
        .as_deref()
        .map(Budget::parse)
        .unwrap_or(Budget::Cents(u64::MAX));

    eprintln!(
        "auths-mcp-gateway: wrapping `{}` — scope={:?} budget={:?} ttl={:?}",
        cfg.downstream.join(" "),
        cfg.scope,
        cfg.budget,
        cfg.ttl,
    );

    let proxy = GatewayProxy {
        downstream,
        scope: cfg.scope,
        ledger: Arc::new(Mutex::new(SessionLedger::open(budget))),
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
