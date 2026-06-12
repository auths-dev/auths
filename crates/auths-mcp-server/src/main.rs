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
//!
//! KERI presentation auth (`Authorization: Auths-Presentation`, no issuer in the
//! path) is switched on by `AUTHS_MCP_REGISTRY`; the rest are then required or
//! defaulted:
//!
//! - `AUTHS_MCP_REGISTRY` - Path to the Auths registry repository (enables the mode)
//! - `AUTHS_MCP_ISSUER_ALIAS` - Keychain alias of the pinned credential issuer
//! - `AUTHS_MCP_PRESENTATION_AUDIENCE` - This server's audience for presentations
//! - `AUTHS_MCP_CHALLENGE_TTL_SECS` - Single-use challenge TTL (default: 120)
//! - `AUTHS_MCP_MAX_LIVE_CHALLENGES` - Bound on live challenges (default: 10000)

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use auths_mcp_server::{KeriPresentationConfig, KeriToolAuth, McpServerConfig, McpServerState};
use auths_rp::Audience;
use auths_sdk::attestation::AttestationSink;
use auths_sdk::context::AuthsContext;
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_sdk::ports::{AttestationSource, IdentityStorage, RegistryBackend, SystemClock};
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_telemetry::init_tracing;
use auths_telemetry::sinks::stdout::new_stdout_sink;

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

    let keri_config = keri_presentation_config_from_env()?;

    init_tracing(&config.log_level, false);

    let telemetry =
        auths_telemetry::init_telemetry_with_sink(std::sync::Arc::new(new_stdout_sink()));

    tracing::info!("Auths MCP Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("JWKS URL: {}", config.jwks_url);
    tracing::info!("Expected issuer: {}", config.expected_issuer);
    tracing::info!("Bind address: {}", config.bind_addr);

    let state = match &keri_config {
        Some(keri_cfg) => {
            let ctx = build_registry_context(&keri_cfg.registry_path)?;
            tracing::info!(
                "Auths-Presentation auth enabled (registry: {}, audience: {})",
                keri_cfg.registry_path.display(),
                keri_cfg.audience.as_str()
            );
            let keri = Arc::new(KeriToolAuth::from_config(
                ctx,
                keri_cfg,
                config.tool_capabilities.clone(),
            ));
            McpServerState::with_keri_presentation(config.clone(), keri)
        }
        None => McpServerState::new(config.clone()),
    };
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

    telemetry.shutdown();

    Ok(())
}

/// Parse the optional KERI presentation settings from the environment.
///
/// `AUTHS_MCP_REGISTRY` switches the mode on; the audience and issuer alias are
/// then required — a partial configuration fails loudly at boot instead of
/// silently serving without the presentation path.
fn keri_presentation_config_from_env() -> anyhow::Result<Option<KeriPresentationConfig>> {
    let Ok(registry) = env::var("AUTHS_MCP_REGISTRY") else {
        return Ok(None);
    };
    let audience_raw = env::var("AUTHS_MCP_PRESENTATION_AUDIENCE")
        .context("AUTHS_MCP_PRESENTATION_AUDIENCE must be set when AUTHS_MCP_REGISTRY is")?;
    let audience = Audience::parse(&audience_raw).map_err(|e| {
        anyhow::anyhow!("invalid AUTHS_MCP_PRESENTATION_AUDIENCE '{audience_raw}': {e}")
    })?;
    let issuer_alias = env::var("AUTHS_MCP_ISSUER_ALIAS")
        .context("AUTHS_MCP_ISSUER_ALIAS must be set when AUTHS_MCP_REGISTRY is")?;

    let mut keri_cfg = KeriPresentationConfig::new(
        PathBuf::from(registry),
        KeyAlias::new_unchecked(issuer_alias),
        audience,
    );
    if let Ok(ttl) = env::var("AUTHS_MCP_CHALLENGE_TTL_SECS") {
        keri_cfg = keri_cfg.with_challenge_ttl_secs(
            ttl.parse()
                .context("AUTHS_MCP_CHALLENGE_TTL_SECS must be an integer")?,
        );
    }
    if let Ok(max) = env::var("AUTHS_MCP_MAX_LIVE_CHALLENGES") {
        keri_cfg = keri_cfg.with_max_live_challenges(
            max.parse()
                .context("AUTHS_MCP_MAX_LIVE_CHALLENGES must be an integer")?,
        );
    }
    Ok(Some(keri_cfg))
}

/// Assemble the registry-backed verification context — the binary's composition
/// boundary, mirroring the platform's other server binaries. The keychain backend
/// is selected from the environment (`EnvironmentConfig::from_env`), so the same
/// keychain the issuing CLI writes is the one this server resolves the pinned
/// issuer from.
fn build_registry_context(registry_path: &Path) -> anyhow::Result<Arc<AuthsContext>> {
    let env_config = EnvironmentConfig::from_env();
    let registry: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(registry_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(registry_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage = get_platform_keychain_with_config(&env_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize keychain: {e}"))?;

    Ok(Arc::new(
        AuthsContext::builder()
            .registry(registry)
            .key_storage(Arc::from(key_storage))
            .clock(Arc::new(SystemClock))
            .identity_storage(identity_storage)
            .attestation_sink(attestation_sink)
            .attestation_source(attestation_source)
            .build(),
    ))
}
