//! Auths witness server binary.
//!
//! # Configuration
//!
//! - `AUTHS_WITNESS_SIGNING_KEY` — Hex-encoded PKCS#8 Ed25519 key (required)
//! - `AUTHS_WITNESS_NAME` — Witness name (default: "auths-witness")
//! - `AUTHS_WITNESS_CHECKPOINT_PATH` — Checkpoint persistence path (default: /data/last_checkpoint.json)
//! - `AUTHS_WITNESS_BIND_ADDR` — Bind address (default: 0.0.0.0:8080)

// Witness binary is the presentation boundary — env vars, printing, and exit are expected.
#![allow(clippy::disallowed_methods, clippy::exit)]

use std::path::PathBuf;

use auths_checkpoint_cosigner::{WitnessConfig, WitnessState, build_router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let signing_key = std::env::var("AUTHS_WITNESS_SIGNING_KEY").map_err(|_| {
        anyhow::anyhow!("AUTHS_WITNESS_SIGNING_KEY must be set (hex-encoded PKCS#8 Ed25519 key)")
    })?;

    let witness_name =
        std::env::var("AUTHS_WITNESS_NAME").unwrap_or_else(|_| "auths-witness".into());
    let checkpoint_path = std::env::var("AUTHS_WITNESS_CHECKPOINT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/data/last_checkpoint.json"));
    let bind_addr =
        std::env::var("AUTHS_WITNESS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let config = WitnessConfig {
        signing_key_hex: signing_key,
        witness_name: witness_name.clone(),
        checkpoint_path: checkpoint_path.clone(),
        bind_addr: bind_addr.clone(),
    };

    let state = WitnessState::new(&config)?;

    // A cosigner is ONE operator. Loading the witness-diversity policy here only
    // surfaces the honest commons status at startup — a single cosignature is
    // never, by itself, a "the commons agrees" claim. That requires an admitted,
    // diverse quorum, evaluated by auths-monitor against the same policy.
    let policy_result = match std::env::var("AUTHS_WITNESS_POLICY_PATH") {
        Ok(path) => auths_transparency::WitnessPolicy::load(std::path::Path::new(&path)),
        Err(_) => Err(auths_transparency::WitnessPolicyError::NotFound {
            path: "<AUTHS_WITNESS_POLICY_PATH unset>".into(),
        }),
    };
    let ceiling = auths_transparency::ceiling_for_policy_load(&policy_result);

    tracing::info!("Auths Witness Server starting");
    tracing::info!("  Name: {witness_name}");
    tracing::info!("  Checkpoint path: {}", checkpoint_path.display());
    tracing::info!("  Bind address: {bind_addr}");
    tracing::info!("  Witness commons status: {}", ceiling.label);
    if !ceiling.policy_met {
        tracing::info!(
            "this node emits SINGLE-OPERATOR cosignatures; they are not a commons-agreement claim"
        );
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Listening on {bind_addr}");

    axum::serve(listener, app).await?;

    Ok(())
}
