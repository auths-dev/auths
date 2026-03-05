// Server binary — env::var and Utc::now() are expected at the process boundary.
#![allow(clippy::disallowed_methods)]
//! Auths OIDC Bridge binary.
//!
//! # Environment Variables
//!
//! - `AUTHS_OIDC_BIND_ADDR` - Address to bind (default: 0.0.0.0:3300)
//! - `AUTHS_OIDC_ISSUER_URL` - OIDC issuer URL (default: http://localhost:3300)
//! - `AUTHS_OIDC_AUDIENCE` - Default audience for issued tokens
//! - `AUTHS_OIDC_ALLOWED_AUDIENCES` - Comma-separated allowlist of audiences
//! - `AUTHS_OIDC_SIGNING_KEY_PATH` - Path to RSA private key PEM file
//! - `AUTHS_OIDC_SIGNING_KEY_PEM` - Inline RSA private key PEM
//! - `AUTHS_OIDC_DEFAULT_TTL` - Default token TTL in seconds (default: 900)
//! - `AUTHS_OIDC_MAX_TTL` - Maximum token TTL in seconds (default: 3600)
//! - `AUTHS_OIDC_CORS` - Enable CORS (set to "1" or "true")
//! - `AUTHS_OIDC_LOG_LEVEL` - Log level (default: info)
//! - `PORT` - Alternative port binding (cloud platform support)

use std::env;
use std::path::PathBuf;

use auths_oidc_bridge::{BridgeConfig, BridgeState};
use auths_telemetry::init_tracing;

fn main() -> anyhow::Result<()> {
    let mut config = BridgeConfig::default();

    // Apply environment variables
    if let Ok(addr) = env::var("AUTHS_OIDC_BIND_ADDR") {
        if let Ok(parsed) = addr.parse() {
            config = config.with_addr(parsed);
        }
    } else if let Ok(port) = env::var("PORT")
        && let Ok(parsed) = format!("0.0.0.0:{port}").parse()
    {
        config = config.with_addr(parsed);
    }

    if let Ok(url) = env::var("AUTHS_OIDC_ISSUER_URL") {
        config = config.with_issuer_url(url);
    }

    if let Ok(audience) = env::var("AUTHS_OIDC_AUDIENCE") {
        config = config.with_default_audience(audience);
    }

    if let Ok(allowed) = env::var("AUTHS_OIDC_ALLOWED_AUDIENCES") {
        let audiences: Vec<String> = allowed.split(',').map(|s| s.trim().to_string()).collect();
        config = config.with_allowed_audiences(audiences);
    }

    if let Ok(path) = env::var("AUTHS_OIDC_SIGNING_KEY_PATH") {
        config = config.with_signing_key_path(PathBuf::from(path));
    }

    if let Ok(pem) = env::var("AUTHS_OIDC_SIGNING_KEY_PEM") {
        config = config.with_signing_key_pem(pem);
    }

    if let Ok(ttl) = env::var("AUTHS_OIDC_DEFAULT_TTL")
        && let Ok(secs) = ttl.parse()
    {
        config = config.with_default_ttl(secs);
    }

    if let Ok(ttl) = env::var("AUTHS_OIDC_MAX_TTL")
        && let Ok(secs) = ttl.parse()
    {
        config = config.with_max_ttl(secs);
    }

    if let Ok(rpm) = env::var("AUTHS_OIDC_RATE_LIMIT_RPM")
        && let Ok(parsed) = rpm.parse()
    {
        config = config.with_rate_limit_rpm(parsed);
    }

    if let Ok(burst) = env::var("AUTHS_OIDC_RATE_LIMIT_BURST")
        && let Ok(parsed) = burst.parse()
    {
        config = config.with_rate_limit_burst(parsed);
    }

    if let Ok(enabled) = env::var("AUTHS_OIDC_RATE_LIMIT_ENABLED") {
        config = config.with_rate_limit_enabled(enabled == "1" || enabled.to_lowercase() == "true");
    }

    if let Ok(val) = env::var("AUTHS_OIDC_AUDIENCE_VALIDATION")
        && let Some(mode) = auths_oidc_bridge::audience::AudienceValidation::from_str_value(&val)
    {
        config = config.with_audience_validation(mode);
    }

    if let Ok(token) = env::var("AUTHS_OIDC_ADMIN_TOKEN") {
        config = config.with_admin_token(token);
    }

    if let Ok(cors) = env::var("AUTHS_OIDC_CORS") {
        config = config.with_cors(cors == "1" || cors.to_lowercase() == "true");
    }

    if let Ok(level) = env::var("AUTHS_OIDC_LOG_LEVEL") {
        config = config.with_log_level(level);
    }

    // Initialize tracing
    init_tracing(&config.log_level, false);

    tracing::info!("Auths OIDC Bridge v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Issuer URL: {}", config.issuer_url);
    tracing::info!("Bind address: {}", config.bind_addr);

    let state = BridgeState::new(config.clone())?;
    let app = auths_oidc_bridge::routes::router(state, &config);

    tracing::info!("Starting OIDC bridge on {}", config.bind_addr);

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
