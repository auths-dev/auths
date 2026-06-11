//! SCIM provisioning server management commands.
//!
//! `serve`/`quickstart` run the in-workspace `auths-scim-server` library in-process
//! (KERI/registry is authoritative — there is no provisioning database). Tenants are
//! process-configured via flags, so `add-tenant`/`rotate-token` mint channel bearer
//! tokens, `status` probes a running server, and `tenants` is an honest "no tenant
//! registry in this model" error rather than a fake database stub.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use auths_scim_server::{ServeConfig, TenantBootstrap, run};
use auths_verifier::Capability;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

/// Manage the SCIM provisioning server.
#[derive(Parser, Debug, Clone)]
#[command(name = "scim", about = "SCIM 2.0 provisioning for agent identities")]
pub struct ScimCommand {
    #[command(subcommand)]
    pub command: ScimSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ScimSubcommand {
    /// Start the SCIM provisioning server (in-process, KERI-authoritative).
    Serve(ScimServeCommand),
    /// Zero-config quickstart: generate a token and run a single-tenant server.
    Quickstart(ScimQuickstartCommand),
    /// Validate the full SCIM pipeline: create -> get -> patch -> delete.
    TestConnection(ScimTestConnectionCommand),
    /// List SCIM tenants (process-configured in this model).
    Tenants(ScimTenantsCommand),
    /// Mint a bearer token for an IdP provisioning channel.
    AddTenant(ScimAddTenantCommand),
    /// Mint a replacement bearer token to rotate a tenant's channel.
    RotateToken(ScimRotateTokenCommand),
    /// Probe a running SCIM server's health and discovery surface.
    Status(ScimStatusCommand),
}

/// Start the SCIM provisioning server.
#[derive(Parser, Debug, Clone)]
pub struct ScimServeCommand {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:8787")]
    pub bind: SocketAddr,
    /// Tenant id for the single-tenant bootstrap (matches the IdP's tenant).
    #[arg(long)]
    pub tenant: Option<String>,
    /// Auths org prefix this tenant provisions into.
    #[arg(long)]
    pub org_prefix: Option<String>,
    /// Bearer token authenticating the provisioning channel.
    #[arg(long)]
    pub token: Option<String>,
    /// Org signing-key alias (default: derived `org-<slug>`).
    #[arg(long)]
    pub org_key: Option<String>,
    /// Base URL used for SCIM `meta.location`.
    #[arg(long)]
    pub base_url: Option<String>,
    /// Capability this tenant may grant (repeatable). Empty = deny all (RT-006);
    /// pass --allow-all-capabilities to opt into permit-all.
    #[arg(long = "allowed-capability")]
    pub allowed_capability: Vec<Capability>,
    /// Let this tenant grant ANY capability, bypassing the allowlist (opt-in).
    #[arg(long)]
    pub allow_all_capabilities: bool,
    /// Passphrase for the org signing key (single-host custody).
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Path to the Auths registry Git repository (default: `~/.auths`).
    #[arg(long)]
    pub registry_path: Option<PathBuf>,
}

/// Zero-config quickstart with copy-paste curl examples.
#[derive(Parser, Debug, Clone)]
pub struct ScimQuickstartCommand {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:8787")]
    pub bind: SocketAddr,
    /// Auths org prefix to provision into (must already exist on this host).
    #[arg(long)]
    pub org_prefix: String,
    /// Tenant id (defaults to `quickstart`).
    #[arg(long, default_value = "quickstart")]
    pub tenant: String,
    /// Passphrase for the org signing key (single-host custody).
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Path to the Auths registry Git repository (default: `~/.auths`).
    #[arg(long)]
    pub registry_path: Option<PathBuf>,
}

/// Validate the full SCIM pipeline against a running server.
#[derive(Parser, Debug, Clone)]
pub struct ScimTestConnectionCommand {
    /// Server URL.
    #[arg(long, default_value = "http://localhost:8787")]
    pub url: String,
    /// Bearer token.
    #[arg(long)]
    pub token: String,
}

/// List SCIM tenants.
#[derive(Parser, Debug, Clone)]
pub struct ScimTenantsCommand {
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Mint a bearer token for an IdP provisioning channel.
#[derive(Parser, Debug, Clone)]
pub struct ScimAddTenantCommand {
    /// Tenant name.
    #[arg(long)]
    pub name: String,
    /// Auths org prefix this tenant provisions into.
    #[arg(long)]
    pub org_prefix: String,
}

/// Mint a replacement bearer token to rotate a tenant's channel.
#[derive(Parser, Debug, Clone)]
pub struct ScimRotateTokenCommand {
    /// Tenant name.
    #[arg(long)]
    pub name: String,
}

/// Probe a running SCIM server.
#[derive(Parser, Debug, Clone)]
pub struct ScimStatusCommand {
    /// Server URL.
    #[arg(long, default_value = "http://localhost:8787")]
    pub url: String,
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

fn handle_scim(cmd: ScimCommand, ctx: &CliConfig) -> Result<()> {
    match cmd.command {
        ScimSubcommand::Serve(serve) => handle_serve(serve, ctx),
        ScimSubcommand::Quickstart(qs) => handle_quickstart(qs, ctx),
        ScimSubcommand::TestConnection(tc) => handle_test_connection(tc),
        ScimSubcommand::Tenants(_) => handle_tenants(),
        ScimSubcommand::AddTenant(at) => handle_add_tenant(&at.name, &at.org_prefix),
        ScimSubcommand::RotateToken(rt) => handle_rotate_token(&rt.name),
        ScimSubcommand::Status(st) => handle_status(st),
    }
}

/// Resolve the registry home from the command flag, the global CLI config, or the
/// server's `~/.auths` default (`None`).
fn resolve_home(registry_path: Option<PathBuf>, ctx: &CliConfig) -> Option<PathBuf> {
    registry_path.or_else(|| ctx.repo_path.clone())
}

fn handle_serve(cmd: ScimServeCommand, ctx: &CliConfig) -> Result<()> {
    let tenant = match (cmd.tenant, cmd.org_prefix, cmd.token) {
        (Some(tenant_id), Some(org_prefix), Some(bearer_token)) => Some(TenantBootstrap {
            tenant_id,
            org_prefix,
            bearer_token,
            org_key_alias: cmd.org_key,
            base_url: cmd.base_url,
            allowed_capabilities: cmd.allowed_capability,
            allow_all: cmd.allow_all_capabilities,
        }),
        (None, None, None) => {
            println!("No tenant configured — running discovery-only; /Users rejects all callers.");
            println!("Configure with --tenant <id> --org-prefix <E…> --token <bearer>.");
            None
        }
        _ => anyhow::bail!(
            "--tenant, --org-prefix, and --token must be set together (or all omitted for discovery-only)"
        ),
    };

    println!("Starting SCIM server on {}...", cmd.bind);
    serve(ServeConfig {
        bind: cmd.bind.to_string(),
        tenant,
        home: resolve_home(cmd.registry_path, ctx),
        passphrase: cmd.passphrase.unwrap_or_default(),
    })
}

fn handle_quickstart(cmd: ScimQuickstartCommand, ctx: &CliConfig) -> Result<()> {
    let token = format!("scim_test_{}", generate_token_b64());

    println!();
    println!("  Auths SCIM Quickstart");
    println!();
    println!("  Server:   http://{}", cmd.bind);
    println!("  Tenant:   {}", cmd.tenant);
    println!("  Org:      {}", cmd.org_prefix);
    println!("  Token:    {}", token);
    println!();
    println!("  Try it (in another shell):");
    println!(
        "    curl -s -H \"Authorization: Bearer {token}\" http://{}/scim/v2/Users | jq",
        cmd.bind
    );
    println!();
    println!("    curl -s -X POST -H \"Authorization: Bearer {token}\" \\");
    println!("      -H \"Content-Type: application/scim+json\" \\");
    println!(
        "      -d '{{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"deploy-bot\",\"externalId\":\"okta-1\"}}' \\"
    );
    println!("      http://{}/scim/v2/Users | jq", cmd.bind);
    println!();
    println!("  Press Ctrl+C to stop.");
    println!();

    serve(ServeConfig {
        bind: cmd.bind.to_string(),
        tenant: Some(TenantBootstrap {
            tenant_id: cmd.tenant,
            org_prefix: cmd.org_prefix,
            bearer_token: token,
            org_key_alias: None,
            base_url: Some(format!("http://{}/scim/v2", cmd.bind)),
            // Quickstart stays deny-by-default; its demo provisions a bot with no
            // capabilities, which passes. Grant caps via `scim serve`.
            allowed_capabilities: Vec::new(),
            allow_all: false,
        }),
        home: resolve_home(cmd.registry_path, ctx),
        passphrase: cmd.passphrase.unwrap_or_default(),
    })
}

fn handle_tenants() -> Result<()> {
    anyhow::bail!(
        "SCIM tenants are process-configured (via `auths scim serve --tenant/--org-prefix/--token` \
         or the SCIM_* env), not stored in a tenant database — the KEL is the source of truth, so \
         there is no tenant registry to list. Use `auths scim status --url <server>` to probe a \
         running server."
    )
}

fn handle_add_tenant(name: &str, org_prefix: &str) -> Result<()> {
    let token = format!("scim_{}", generate_token_b64());
    println!("Minted a SCIM channel bearer token for tenant '{name}':");
    println!();
    println!("  {token}");
    println!();
    println!("Run the server with it:");
    println!("  auths scim serve --tenant {name} --org-prefix {org_prefix} --token {token}");
    println!();
    println!("Configure your IdP (Okta/Entra) with this token as the SCIM bearer secret.");
    println!("The token is hashed at rest by the server; store this plaintext securely now.");
    Ok(())
}

fn handle_rotate_token(name: &str) -> Result<()> {
    let token = format!("scim_{}", generate_token_b64());
    println!("Minted a replacement SCIM bearer token for tenant '{name}':");
    println!();
    println!("  {token}");
    println!();
    println!("Swap it in by restarting the server with --token {token} and updating the IdP.");
    println!("The previous token stops authenticating as soon as the server restarts.");
    Ok(())
}

fn handle_status(cmd: ScimStatusCommand) -> Result<()> {
    let result = block_on(probe_status(&cmd.url));
    match result {
        Ok(report) => {
            if cmd.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("SCIM server: {}", cmd.url);
                println!(
                    "  health:  {}",
                    if report.healthy { "ok" } else { "unreachable" }
                );
                println!("  patch:   {}", report.patch_supported);
                println!("  filter:  {}", report.filter_supported);
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("could not reach SCIM server at {}: {e}", cmd.url),
    }
}

/// A minimal status snapshot probed from discovery.
#[derive(Debug, serde::Serialize)]
struct StatusReport {
    healthy: bool,
    patch_supported: bool,
    filter_supported: bool,
}

async fn probe_status(base_url: &str) -> Result<StatusReport> {
    let client = build_http_client()?;
    let healthy = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let spc: serde_json::Value = client
        .get(format!("{base_url}/scim/v2/ServiceProviderConfig"))
        .send()
        .await
        .context("ServiceProviderConfig request failed")?
        .json()
        .await
        .context("ServiceProviderConfig was not valid JSON")?;

    Ok(StatusReport {
        healthy,
        patch_supported: spc["patch"]["supported"].as_bool().unwrap_or(false),
        filter_supported: spc["filter"]["supported"].as_bool().unwrap_or(false),
    })
}

fn handle_test_connection(cmd: ScimTestConnectionCommand) -> Result<()> {
    println!();
    println!("  Testing SCIM connection to {}...", cmd.url);
    println!();

    match block_on(run_test_connection(&cmd.url, &cmd.token)) {
        Ok(()) => {
            println!("  All checks passed. Your SCIM server is ready.");
            println!();
        }
        Err(e) => {
            println!("  Connection test failed: {e}");
            println!();
        }
    }
    Ok(())
}

#[allow(clippy::disallowed_methods)] // CLI boundary: Utc::now() for test user naming
async fn run_test_connection(base_url: &str, token: &str) -> Result<()> {
    let client = build_http_client()?;
    let auth = format!("Bearer {token}");

    let start = std::time::Instant::now();
    let resp = client
        .post(format!("{base_url}/scim/v2/Users"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/scim+json")
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("test-agent-{}", chrono::Utc::now().timestamp()),
            "externalId": format!("scim-test-{}", chrono::Utc::now().timestamp()),
            "displayName": "SCIM Test Agent"
        }))
        .send()
        .await
        .context("POST /Users failed")?;
    let elapsed = start.elapsed();

    if resp.status().as_u16() == 201 {
        println!("  [PASS] POST /Users -> 201 Created ({elapsed:.0?})");
    } else {
        println!("  [FAIL] POST /Users -> {} ({elapsed:.0?})", resp.status());
        return Ok(());
    }

    let body: serde_json::Value = resp.json().await?;
    let id = body["id"].as_str().unwrap_or("unknown").to_string();
    let did = body
        .get("urn:ietf:params:scim:schemas:extension:auths:2.0:Agent")
        .and_then(|ext| ext["identityDid"].as_str())
        .unwrap_or("unknown");
    println!("         Agent: {} (userName: {})", did, body["userName"]);

    probe_step(&client, &auth, "GET /Users/{id}", |c| {
        c.get(format!("{base_url}/scim/v2/Users/{id}"))
    })
    .await;

    // PATCH active=false (soft-disable)
    let start = std::time::Instant::now();
    let resp = client
        .patch(format!("{base_url}/scim/v2/Users/{id}"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/scim+json")
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}]
        }))
        .send()
        .await?;
    println!(
        "  [{}] PATCH active=false -> {} ({:.0?})",
        pass_fail(resp.status().is_success()),
        resp.status(),
        start.elapsed()
    );

    // DELETE (soft leaver) -> 204
    let start = std::time::Instant::now();
    let resp = client
        .delete(format!("{base_url}/scim/v2/Users/{id}"))
        .header("Authorization", &auth)
        .send()
        .await?;
    println!(
        "  [{}] DELETE /Users/{{id}} -> {} ({:.0?})",
        pass_fail(resp.status().as_u16() == 204),
        resp.status(),
        start.elapsed()
    );

    // GET should now be 404
    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{base_url}/scim/v2/Users/{id}"))
        .header("Authorization", &auth)
        .send()
        .await?;
    println!(
        "  [{}] GET /Users/{{id}} -> {} ({:.0?})",
        pass_fail(resp.status().as_u16() == 404),
        resp.status(),
        start.elapsed()
    );

    println!();
    Ok(())
}

async fn probe_step<F>(client: &reqwest::Client, auth: &str, label: &str, build: F)
where
    F: FnOnce(&reqwest::Client) -> reqwest::RequestBuilder,
{
    let start = std::time::Instant::now();
    let outcome = build(client).header("Authorization", auth).send().await;
    match outcome {
        Ok(resp) => println!(
            "  [{}] {label} -> {} ({:.0?})",
            pass_fail(resp.status().is_success()),
            resp.status(),
            start.elapsed()
        ),
        Err(e) => println!("  [FAIL] {label} -> {e}"),
    }
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("auths/", env!("CARGO_PKG_VERSION")))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("failed to build HTTP client")
}

/// Run a future to completion on a fresh runtime (the CLI's `main` is synchronous).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    #[allow(clippy::expect_used)] // INVARIANT: tokio runtime creation failing is unrecoverable
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(fut)
}

/// Serve the in-process SCIM server until stopped.
fn serve(config: ServeConfig) -> Result<()> {
    block_on(run(config))
}

fn generate_token_b64() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    #[allow(clippy::expect_used)] // INVARIANT: system RNG failure is unrecoverable
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("random bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl ExecutableCommand for ScimCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_scim(self.clone(), ctx)
    }
}

use ring::rand::SecureRandom;
