//! Auths SCIM 2.0 provisioning server binary.
//!
//! # Configuration
//!
//! - `SCIM_LISTEN_ADDR` — Bind address (default: `0.0.0.0:8787`)
//! - `SCIM_TENANT_ID` / `SCIM_ORG_PREFIX` / `SCIM_BEARER_TOKEN` — single-tenant
//!   bootstrap. When any is unset the server runs discovery-only (no provisioning
//!   channel authenticates), which is honest for a not-yet-configured deployment.

// Binary is the presentation boundary — env vars and printing are expected.
#![allow(clippy::disallowed_methods)]

use auths_scim_server::{ScimServerState, TenantConfig, router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("SCIM_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".into());

    let tenants = match (
        std::env::var("SCIM_TENANT_ID"),
        std::env::var("SCIM_ORG_PREFIX"),
        std::env::var("SCIM_BEARER_TOKEN"),
    ) {
        (Ok(tenant), Ok(org), Ok(token)) => {
            tracing::info!(tenant = %tenant, "configured SCIM tenant");
            vec![TenantConfig::new(tenant, org, &token)]
        }
        _ => {
            tracing::warn!(
                "no tenant configured (set SCIM_TENANT_ID / SCIM_ORG_PREFIX / SCIM_BEARER_TOKEN) \
                 — running discovery-only; /Users will reject all callers (401)"
            );
            vec![]
        }
    };

    let state = ScimServerState::new(tenants);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("Auths SCIM server listening on {bind}");

    axum::serve(listener, app).await?;
    Ok(())
}
