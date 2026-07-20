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
//! - `AUTHS_WATCH_WITNESSES` — Comma-separated witness base URLs to pull spend anchors from
//! - `AUTHS_WATCH_SEEDS` — Comma-separated seed ids (lowercase hex) to watch
//! - `AUTHS_WATCH_GAP_SECS` — Tolerated silence before a withholding-gap alert (default: 86400)

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

    let watch_witnesses: Vec<String> = std::env::var("AUTHS_WATCH_WITNESSES")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let watch_seeds: Vec<String> = std::env::var("AUTHS_WATCH_SEEDS")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let watch_gap_secs: i64 = std::env::var("AUTHS_WATCH_GAP_SECS")
        .unwrap_or_else(|_| "86400".into())
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid AUTHS_WATCH_GAP_SECS: {e}"))?;
    let alert_webhook = std::env::var("AUTHS_ALERT_WEBHOOK").ok();
    if !watch_witnesses.is_empty() {
        tracing::info!(
            witnesses = watch_witnesses.len(),
            seeds = watch_seeds.len(),
            "spend-anchor watch enabled"
        );
    }

    loop {
        tracing::info!("starting verification cycle");

        if !watch_witnesses.is_empty() && !watch_seeds.is_empty() {
            let observed =
                auths_monitor::fetch_observed_anchors(&client, &watch_witnesses, &watch_seeds)
                    .await;
            if let Some(proof) = auths_monitor::detect_spend_anchor_duplicity(&observed) {
                // The proof is the publishable artifact: emitted whole so any
                // channel can carry it to strangers for offline re-checking.
                match serde_json::to_string(&proof) {
                    Ok(wire) => {
                        tracing::error!(proof = %wire, "SPEND-ANCHOR DUPLICITY DETECTED");
                        push_alert(&client, &alert_webhook, "duplicity", &proof).await;
                    }
                    Err(e) => tracing::error!(error = %e, "duplicity proof serialization"),
                }
            }
            let now = chrono::Utc::now();
            for seed in &watch_seeds {
                let newest = observed
                    .iter()
                    .filter(|o| o.anchor.seed_id.to_hex() == *seed)
                    .map(|o| o.anchor.timestamp)
                    .max();
                if let Some(latest) = newest
                    && let Some(gap) =
                        auths_monitor::withholding_gap(seed, latest, now, watch_gap_secs)
                {
                    tracing::warn!(
                        seed = %gap.seed_id,
                        gap_seconds = gap.gap_seconds,
                        "withholding gap past tolerance"
                    );
                    push_alert(&client, &alert_webhook, "withholding", &gap).await;
                }
            }
        }

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

/// POST a small alert to the operator's configured webhook, if any.
///
/// The hosted watcher's promise — alerts the moment a fork or a silence appears
/// — needs a push, not just a log line; this is that push. Absent
/// `AUTHS_ALERT_WEBHOOK`, tracing stays the only channel (unchanged default), so
/// behavior without config is identical to before.
///
/// Args:
/// * `client`: the shared HTTP client.
/// * `webhook`: the operator's alert URL, or `None` to skip the push.
/// * `kind`: the alert kind (`"duplicity"` or `"withholding"`).
/// * `event`: the alert payload (the proof, or the gap), embedded inline.
async fn push_alert<T: serde::Serialize>(
    client: &reqwest::Client,
    webhook: &Option<String>,
    kind: &str,
    event: &T,
) {
    let Some(url) = webhook else { return };
    let body = serde_json::json!({ "kind": kind, "event": event });
    if let Err(e) = client
        .post(url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        tracing::error!(error = %e, webhook = %url, "alert webhook POST failed");
    }
}
