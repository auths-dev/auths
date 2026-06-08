//! Auths SCIM 2.0 provisioning server binary.
//!
//! # Configuration
//!
//! - `SCIM_LISTEN_ADDR` — Bind address (default: `0.0.0.0:8787`)
//! - `SCIM_TENANT_ID` / `SCIM_ORG_PREFIX` / `SCIM_BEARER_TOKEN` — single-tenant
//!   bootstrap. When any is unset the server runs discovery-only (no provisioning
//!   channel authenticates), which is honest for a not-yet-configured deployment.
//! - `SCIM_ORG_KEY` — org signing-key alias (default: derived `org-<slug>`)
//! - `SCIM_BASE_URL` — base URL for SCIM `meta.location`
//! - `SCIM_KEY_PASSPHRASE` — passphrase for the org signing key (single-host custody)

// Binary is the presentation boundary — env vars and printing are expected.
#![allow(clippy::disallowed_methods)]

use auths_scim_server::{ServeConfig, TenantBootstrap, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("SCIM_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".into());

    let tenant = match (
        std::env::var("SCIM_TENANT_ID"),
        std::env::var("SCIM_ORG_PREFIX"),
        std::env::var("SCIM_BEARER_TOKEN"),
    ) {
        (Ok(tenant_id), Ok(org_prefix), Ok(bearer_token)) => {
            tracing::info!(tenant = %tenant_id, "configured SCIM tenant");
            Some(TenantBootstrap {
                tenant_id,
                org_prefix,
                bearer_token,
                org_key_alias: std::env::var("SCIM_ORG_KEY").ok(),
                base_url: std::env::var("SCIM_BASE_URL").ok(),
            })
        }
        _ => {
            tracing::warn!(
                "no tenant configured (set SCIM_TENANT_ID / SCIM_ORG_PREFIX / SCIM_BEARER_TOKEN) \
                 — running discovery-only; /Users will reject all callers (401)"
            );
            None
        }
    };

    run(ServeConfig {
        bind,
        tenant,
        home: None,
        passphrase: std::env::var("SCIM_KEY_PASSPHRASE").unwrap_or_default(),
    })
    .await
}
