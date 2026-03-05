// Server binary — env::var and Utc::now() are expected at the process boundary.
#![allow(clippy::disallowed_methods)]
//! Auths MCP Server binary.
//!
//! # Environment Variables
//!
//! - `AUTHS_MCP_BIND_ADDR` - Address to bind (default: 0.0.0.0:8080)
//! - `AUTHS_MCP_JWKS_URL` - OIDC bridge JWKS endpoint
//! - `AUTHS_MCP_EXPECTED_ISSUER` - Expected JWT issuer URL
//! - `AUTHS_MCP_EXPECTED_AUDIENCE` - Expected JWT audience
//! - `AUTHS_MCP_LEEWAY` - Clock skew tolerance in seconds (default: 5)
//! - `AUTHS_MCP_CORS` - Enable CORS (set to "1" or "true")
//! - `AUTHS_MCP_LOG_LEVEL` - Log level (default: info)
//! - `PORT` - Alternative port binding (cloud platform support)

use std::env;

use auths_mcp_server::{McpServerConfig, McpServerState};
use auths_telemetry::init_tracing;

fn main() -> anyhow::Result<()> {
    let mut config = McpServerConfig::default();

    if let Ok(addr) = env::var("AUTHS_MCP_BIND_ADDR") {
        if let Ok(parsed) = addr.parse() {
            config = config.with_addr(parsed);
        }
    } else if let Ok(port) = env::var("PORT")
        && let Ok(parsed) = format!("0.0.0.0:{port}").parse()
    {
        config = config.with_addr(parsed);
    }

    if let Ok(url) = env::var("AUTHS_MCP_JWKS_URL") {
        config = config.with_jwks_url(url);
    }

    if let Ok(issuer) = env::var("AUTHS_MCP_EXPECTED_ISSUER") {
        config = config.with_expected_issuer(issuer);
    }

    if let Ok(audience) = env::var("AUTHS_MCP_EXPECTED_AUDIENCE") {
        config = config.with_expected_audience(audience);
    }

    if let Ok(leeway) = env::var("AUTHS_MCP_LEEWAY")
        && let Ok(secs) = leeway.parse()
    {
        config = config.with_leeway(secs);
    }

    if let Ok(cors) = env::var("AUTHS_MCP_CORS") {
        config = config.with_cors(cors == "1" || cors.to_lowercase() == "true");
    }

    if let Ok(level) = env::var("AUTHS_MCP_LOG_LEVEL") {
        config = config.with_log_level(level);
    }

    init_tracing(&config.log_level, false);

    tracing::info!("Auths MCP Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("JWKS URL: {}", config.jwks_url);
    tracing::info!("Expected issuer: {}", config.expected_issuer);
    tracing::info!("Bind address: {}", config.bind_addr);

    let state = McpServerState::new(config.clone());
    let app = auths_mcp_server::router(state, &config);

    tracing::info!("Starting MCP server on {}", config.bind_addr);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
            axum::serve(listener, app).await?;
            Ok::<(), anyhow::Error>(())
        })?;

    Ok(())
}
