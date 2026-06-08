//! Auths transparency log monitor binary.
//!
//! Periodically verifies the transparency log by fetching checkpoints,
//! checking signatures, verifying entry inclusion proofs, and validating
//! consistency between consecutive checkpoints.
//!
//! # Configuration
//!
//! - `AUTHS_REGISTRY_URL` — Registry base URL (default: https://public.auths.dev)
//! - `AUTHS_MONITOR_INTERVAL_SECS` — Seconds between cycles (default: 300)
//! - `AUTHS_MONITOR_STATE_PATH` — State persistence path (default: /data/monitor_state.json)
//! - `AUTHS_LOG_PUBLIC_KEY` — Hex-encoded Ed25519 public key of the log operator (required)
//! - `AUTHS_LOG_ORIGIN` — Log origin string (default: auths.dev/log)

#![allow(clippy::disallowed_methods, clippy::exit)]

use std::path::PathBuf;

use auths_monitor::{MonitorConfig, run_verification_cycle};
use auths_transparency::{LogOrigin, TrustRoot};
use auths_verifier::Ed25519PublicKey;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let registry_url =
        std::env::var("AUTHS_REGISTRY_URL").unwrap_or_else(|_| "https://public.auths.dev".into());

    let interval_secs: u64 = std::env::var("AUTHS_MONITOR_INTERVAL_SECS")
        .unwrap_or_else(|_| "300".into())
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid AUTHS_MONITOR_INTERVAL_SECS: {e}"))?;

    let state_path = std::env::var("AUTHS_MONITOR_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/data/monitor_state.json"));

    let log_public_key_hex = std::env::var("AUTHS_LOG_PUBLIC_KEY").map_err(|_| {
        anyhow::anyhow!("AUTHS_LOG_PUBLIC_KEY must be set (hex-encoded Ed25519 public key)")
    })?;

    let log_public_key_bytes: [u8; 32] = hex::decode(&log_public_key_hex)
        .map_err(|e| anyhow::anyhow!("invalid hex in AUTHS_LOG_PUBLIC_KEY: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("AUTHS_LOG_PUBLIC_KEY must be exactly 32 bytes"))?;

    let log_origin_str =
        std::env::var("AUTHS_LOG_ORIGIN").unwrap_or_else(|_| "auths.dev/log".into());
    let log_origin = LogOrigin::new(&log_origin_str)
        .map_err(|e| anyhow::anyhow!("invalid AUTHS_LOG_ORIGIN: {e}"))?;

    // Load the witness-diversity policy (fail-closed). Until an independent
    // commons is admitted the shipped/placeholder policy fails to load — that is
    // CORRECT: the monitor then runs fork-detection only and the honest ceiling
    // says "single-operator — not yet independent". We NEVER silently fall back to
    // an unconstrained() that would let a surface imply independence; the failure
    // is surfaced in `honesty_ceiling`, logged below and carried in every report.
    let policy_result = match std::env::var("AUTHS_WITNESS_POLICY_PATH") {
        Ok(path) => auths_transparency::WitnessPolicy::load(std::path::Path::new(&path)),
        Err(_) => Err(auths_transparency::WitnessPolicyError::NotFound {
            path: "<AUTHS_WITNESS_POLICY_PATH unset>".into(),
        }),
    };
    let honesty_ceiling = auths_transparency::ceiling_for_policy_load(&policy_result);

    let independence_policy = match &policy_result {
        Ok(policy) => policy.independence_policy.clone(),
        Err(_) => auths_transparency::IndependencePolicy::unconstrained(),
    };

    let trust_root = TrustRoot {
        log_public_key: Ed25519PublicKey::from_bytes(log_public_key_bytes),
        log_origin,
        witnesses: vec![],
        signature_algorithm: Default::default(),
        ecdsa_log_public_key_der: None,
        independence_policy,
    };

    let config = MonitorConfig {
        registry_url: registry_url.clone(),
        interval_secs,
        trust_root,
        state_path: state_path.clone(),
        honesty_ceiling: honesty_ceiling.clone(),
    };

    tracing::info!("Auths Monitor starting");
    tracing::info!("  Registry URL: {registry_url}");
    tracing::info!("  Interval: {interval_secs}s");
    tracing::info!("  State path: {}", state_path.display());
    tracing::info!("  Witness diversity: {}", honesty_ceiling.label);
    if !honesty_ceiling.policy_met {
        tracing::warn!(
            "no independent witness commons established — fork-detection only; \
             this monitor does NOT assert independent-operator non-equivocation"
        );
    }

    let client = reqwest::Client::new();

    loop {
        tracing::info!("starting verification cycle");

        match run_verification_cycle(&config, &client).await {
            Ok(report) => {
                if report.errors.is_empty() {
                    tracing::info!(
                        checked_size = report.checked_size,
                        entries_verified = report.entries_verified,
                        consistency_ok = report.consistency_ok,
                        "verification cycle passed"
                    );
                } else {
                    for error in &report.errors {
                        tracing::error!(error = %error, "verification failure");
                    }
                }
                for warning in &report.warnings {
                    tracing::warn!(warning = %warning, "verification warning");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "verification cycle failed");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(config.interval_secs)).await;
    }
}
