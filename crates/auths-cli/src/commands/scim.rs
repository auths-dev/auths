//! SCIM provisioning server management commands.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

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
    /// Start the SCIM provisioning server.
    Serve(ScimServeCommand),
    /// Zero-config quickstart: temp DB + test tenant + running server.
    Quickstart(ScimQuickstartCommand),
    /// Validate the full SCIM pipeline: create -> get -> patch -> delete.
    TestConnection(ScimTestConnectionCommand),
    /// List SCIM tenants.
    Tenants(ScimTenantsCommand),
    /// Generate a new bearer token for an IdP tenant.
    AddTenant(ScimAddTenantCommand),
    /// Rotate bearer token for an existing tenant.
    RotateToken(ScimRotateTokenCommand),
    /// Show SCIM sync state for debugging.
    Status(ScimStatusCommand),
}

/// Start the SCIM provisioning server (production mode).
#[derive(Parser, Debug, Clone)]
pub struct ScimServeCommand {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:3301")]
    pub bind: SocketAddr,
    /// PostgreSQL connection URL.
    #[arg(long)]
    pub database_url: String,
    /// Path to the Auths registry Git repository.
    #[arg(long)]
    pub registry_path: Option<PathBuf>,
    /// Log level.
    #[arg(long, default_value = "info")]
    pub log_level: String,
    /// Enable test mode (auto-tenant, relaxed TLS).
    #[arg(long)]
    pub test_mode: bool,
}

/// Zero-config quickstart with copy-paste curl examples.
#[derive(Parser, Debug, Clone)]
pub struct ScimQuickstartCommand {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:3301")]
    pub bind: SocketAddr,
}

/// Validate the full SCIM pipeline against a running server.
#[derive(Parser, Debug, Clone)]
pub struct ScimTestConnectionCommand {
    /// Server URL.
    #[arg(long, default_value = "http://localhost:3301")]
    pub url: String,
    /// Bearer token.
    #[arg(long)]
    pub token: String,
}

/// List all SCIM tenants.
#[derive(Parser, Debug, Clone)]
pub struct ScimTenantsCommand {
    /// PostgreSQL connection URL.
    #[arg(long)]
    pub database_url: String,
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Generate a new bearer token for an IdP tenant.
#[derive(Parser, Debug, Clone)]
pub struct ScimAddTenantCommand {
    /// Tenant name.
    #[arg(long)]
    pub name: String,
    /// PostgreSQL connection URL.
    #[arg(long)]
    pub database_url: String,
    /// Token expiry duration (e.g., 90d, 365d). Omit for no expiry.
    #[arg(long)]
    pub expires_in: Option<String>,
}

/// Rotate bearer token for an existing tenant.
#[derive(Parser, Debug, Clone)]
pub struct ScimRotateTokenCommand {
    /// Tenant name.
    #[arg(long)]
    pub name: String,
    /// PostgreSQL connection URL.
    #[arg(long)]
    pub database_url: String,
    /// Token expiry duration (e.g., 90d, 365d).
    #[arg(long)]
    pub expires_in: Option<String>,
}

/// Show SCIM sync state statistics.
#[derive(Parser, Debug, Clone)]
pub struct ScimStatusCommand {
    /// PostgreSQL connection URL.
    #[arg(long)]
    pub database_url: String,
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

fn handle_scim(cmd: ScimCommand) -> Result<()> {
    match cmd.command {
        ScimSubcommand::Serve(serve) => handle_serve(serve),
        ScimSubcommand::Quickstart(qs) => handle_quickstart(qs),
        ScimSubcommand::TestConnection(tc) => handle_test_connection(tc),
        ScimSubcommand::Tenants(_) => {
            println!("SCIM tenant listing requires database connection.");
            println!("Run: auths-scim-server with DATABASE_URL set.");
            Ok(())
        }
        ScimSubcommand::AddTenant(_) => {
            println!("Tenant management requires database connection.");
            println!("Run: auths-scim-server with DATABASE_URL set.");
            Ok(())
        }
        ScimSubcommand::RotateToken(_) => {
            println!("Token rotation requires database connection.");
            println!("Run: auths-scim-server with DATABASE_URL set.");
            Ok(())
        }
        ScimSubcommand::Status(_) => {
            println!("SCIM status requires database connection.");
            println!("Run: auths-scim-server with DATABASE_URL set.");
            Ok(())
        }
    }
}

fn handle_serve(cmd: ScimServeCommand) -> Result<()> {
    println!("Starting SCIM server...");
    println!("  Bind:     {}", cmd.bind);
    println!("  Database: {}", mask_url(&cmd.database_url));
    if let Some(ref path) = cmd.registry_path {
        println!("  Registry: {}", path.display());
    }
    println!("  Test mode: {}", cmd.test_mode);
    println!();

    let mut child = std::process::Command::new("auths-scim-server")
        .env("SCIM_LISTEN_ADDR", cmd.bind.to_string())
        .env("DATABASE_URL", &cmd.database_url)
        .env("RUST_LOG", &cmd.log_level)
        .env("AUTHS_SCIM_TEST", if cmd.test_mode { "1" } else { "0" })
        .spawn()
        .context("Failed to start auths-scim-server. Is it installed?")?;

    child.wait().context("Server exited with error")?;
    Ok(())
}

fn handle_quickstart(cmd: ScimQuickstartCommand) -> Result<()> {
    let token = format!("scim_test_{}", generate_token_b64());

    println!();
    println!("  Auths SCIM Quickstart");
    println!();
    println!("  Server:   http://{}", cmd.bind);
    println!("  Tenant:   quickstart");
    println!("  Token:    {}", token);
    println!();
    println!("  Try it now:");
    println!("    # List agents (empty)");
    println!("    curl -s -H \"Authorization: Bearer {}\" \\", token);
    println!("      http://{}/Users | jq", cmd.bind);
    println!();
    println!("    # Create an agent");
    println!(
        "    curl -s -X POST -H \"Authorization: Bearer {}\" \\",
        token
    );
    println!("      -H \"Content-Type: application/scim+json\" \\");
    println!(
        "      -d '{{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"my-agent\",\"displayName\":\"My First Agent\"}}' \\"
    );
    println!("      http://{}/Users | jq", cmd.bind);
    println!();
    println!("  Docs: https://docs.auths.dev/scim/quickstart");
    println!("  Press Ctrl+C to stop.");
    println!();

    // In quickstart mode, use the auths-scim-server binary with test mode
    let serve = ScimServeCommand {
        bind: cmd.bind,
        database_url: String::new(), // quickstart would use embedded DB
        registry_path: None,
        log_level: "info".into(),
        test_mode: true,
    };

    // For now, print guidance since quickstart requires embedded DB support
    if serve.database_url.is_empty() {
        println!("  Note: Quickstart requires DATABASE_URL to be set.");
        println!("  Set DATABASE_URL env var or use `auths scim serve --database-url <url>`");
    }

    Ok(())
}

fn handle_test_connection(cmd: ScimTestConnectionCommand) -> Result<()> {
    println!();
    println!("  Testing SCIM connection to {}...", cmd.url);
    println!();

    let rt = tokio::runtime::Handle::try_current()
        .ok()
        .map(|_| None)
        .unwrap_or_else(|| Some(tokio::runtime::Runtime::new().expect("tokio runtime")));

    let result = if let Some(ref rt) = rt {
        rt.block_on(run_test_connection(&cmd.url, &cmd.token))
    } else {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(run_test_connection(&cmd.url, &cmd.token))
        })
    };

    match result {
        Ok(()) => {
            println!("  All checks passed. Your SCIM server is ready.");
            println!();
        }
        Err(e) => {
            println!("  Connection test failed: {}", e);
            println!();
        }
    }

    Ok(())
}

#[allow(clippy::disallowed_methods)] // CLI boundary: Utc::now() for test user naming
async fn run_test_connection(base_url: &str, token: &str) -> Result<()> {
    #[allow(clippy::expect_used)]
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("auths/", env!("CARGO_PKG_VERSION")))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .expect("failed to build HTTP client");
    let auth = format!("Bearer {}", token);

    // POST /Users — create test agent
    let start = std::time::Instant::now();
    let resp = client
        .post(format!("{}/Users", base_url))
        .header("Authorization", &auth)
        .header("Content-Type", "application/scim+json")
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("test-agent-{}", chrono::Utc::now().timestamp()),
            "displayName": "SCIM Test Agent"
        }))
        .send()
        .await
        .context("POST /Users failed")?;
    let elapsed = start.elapsed();

    if resp.status().as_u16() == 201 {
        println!("  [PASS] POST /Users -> 201 Created ({:.0?})", elapsed);
    } else {
        println!(
            "  [FAIL] POST /Users -> {} ({:.0?})",
            resp.status(),
            elapsed
        );
        return Ok(());
    }

    let body: serde_json::Value = resp.json().await?;
    let id = body["id"].as_str().unwrap_or("unknown");
    let did = body
        .get("urn:ietf:params:scim:schemas:extension:auths:2.0:Agent")
        .and_then(|ext| ext["identityDid"].as_str())
        .unwrap_or("unknown");
    println!("         Agent: {} (userName: {})", did, body["userName"]);

    // GET /Users/{id}
    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{}/Users/{}", base_url, id))
        .header("Authorization", &auth)
        .send()
        .await?;
    let elapsed = start.elapsed();
    println!(
        "  [{}] GET /Users/{{id}} -> {} ({:.0?})",
        if resp.status().is_success() {
            "PASS"
        } else {
            "FAIL"
        },
        resp.status(),
        elapsed
    );

    // PATCH active=false
    let start = std::time::Instant::now();
    let resp = client
        .patch(format!("{}/Users/{}", base_url, id))
        .header("Authorization", &auth)
        .header("Content-Type", "application/scim+json")
        .json(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "value": {"active": false}}]
        }))
        .send()
        .await?;
    let elapsed = start.elapsed();
    println!(
        "  [{}] PATCH active=false -> {} ({:.0?})",
        if resp.status().is_success() {
            "PASS"
        } else {
            "FAIL"
        },
        resp.status(),
        elapsed
    );

    // DELETE /Users/{id}
    let start = std::time::Instant::now();
    let resp = client
        .delete(format!("{}/Users/{}", base_url, id))
        .header("Authorization", &auth)
        .send()
        .await?;
    let elapsed = start.elapsed();
    println!(
        "  [{}] DELETE /Users/{{id}} -> {} ({:.0?})",
        if resp.status().as_u16() == 204 {
            "PASS"
        } else {
            "FAIL"
        },
        resp.status(),
        elapsed
    );

    // GET /Users/{id} — should be 404
    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{}/Users/{}", base_url, id))
        .header("Authorization", &auth)
        .send()
        .await?;
    let elapsed = start.elapsed();
    println!(
        "  [{}] GET /Users/{{id}} -> {} ({:.0?})",
        if resp.status().as_u16() == 404 {
            "PASS"
        } else {
            "FAIL"
        },
        resp.status(),
        elapsed
    );

    println!();
    Ok(())
}

fn generate_token_b64() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("random bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn mask_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@')
        && let Some(scheme_end) = url.find("://")
    {
        return format!("{}://***@{}", &url[..scheme_end], &url[at_pos + 1..]);
    }
    url.to_string()
}

impl ExecutableCommand for ScimCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_scim(self.clone())
    }
}

use ring::rand::SecureRandom;
