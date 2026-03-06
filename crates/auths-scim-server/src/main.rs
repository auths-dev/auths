//! SCIM 2.0 provisioning server binary.

use anyhow::{Context, Result};
use deadpool_postgres::{Config, Runtime};
use tokio_postgres::NoTls;
use tracing_subscriber::EnvFilter;

use auths_scim_server::config::ScimServerConfig;
use auths_scim_server::routes::router;
use auths_scim_server::state::ScimServerState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let server_config =
        ScimServerConfig::from_env().context("Failed to load SCIM server configuration")?;

    let mut pg_config = Config::new();
    pg_config.url = Some(server_config.database_url.clone());
    let pool = pg_config
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .context("Failed to create database pool")?;

    // Run initial schema setup
    let client = pool.get().await.context("Failed to connect to database")?;
    client
        .batch_execute(include_str!("../migrations/001_initial.sql"))
        .await
        .context("Failed to run initial schema setup")?;
    drop(client);

    let listen_addr = server_config.listen_addr.clone();
    let state = ScimServerState::new(server_config, pool);
    let app = router(state);

    tracing::info!("SCIM server listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .context("Failed to bind listener")?;
    axum::serve(listener, app).await.context("Server error")?;

    Ok(())
}
