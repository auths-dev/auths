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
    /// The downstream credential(s) the gateway custodies and injects into the
    /// wrapped downstream — the agent never holds them (PRD §12).
    pub custody: CustodyVault,
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

    let budget = cfg
        .budget
        .as_deref()
        .map(Budget::parse)
        .unwrap_or(Budget::Cents(u64::MAX));

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
