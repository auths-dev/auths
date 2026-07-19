//! Transparency log verification monitor for auths.
//!
//! Periodically fetches the latest checkpoint from the auths registry,
//! verifies checkpoint signatures, entry inclusion proofs, and consistency
//! between consecutive checkpoints. Alerts on anomalies via `tracing::error`.

// Checkpoint and witness-cosignature crypto is delegated to `auths-transparency`
// (the sanctioned verification crate) — this monitor never names a curve itself.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use auths_transparency::{
    CheckpointStatus, ConsistencyProof, Entry, HonestyCeiling, InclusionProof, SignedCheckpoint,
    TrustRoot, WitnessStatus, hash_leaf, verify_consistency, verify_inclusion,
};
use serde::{Deserialize, Serialize};

/// Cross-operator equivocation detection + portable, third-party-verifiable evidence.
pub mod evidence;
pub use evidence::{
    CheckpointTransition, EquivocationEvidence, OperatorCheckpoint, checkpoint_transition,
    detect_cross_operator_equivocation, verify_equivocation_evidence,
};

/// Operator-to-operator checkpoint gossip (makes equivocation non-repudiable).
///
/// Scope is operator-to-operator. Client-echo / partition-resistant gossip — the
/// defense against a partition that shows the monitor a consistent history while
/// forking to a victim — is a documented limitation tracked in W.0.
pub mod gossip;
pub use gossip::{GossipMessage, GossipReject, GossipState, gossip_detection_strength};

/// Spend-anchor watching: duplicity detection and withholding-gap alerts.
pub mod spend_anchor;
pub use spend_anchor::{
    ObservedAnchor, WithholdingGap, detect_spend_anchor_duplicity, fetch_observed_anchors,
    withholding_gap,
};

/// Monitor configuration loaded from environment variables.
///
/// Args:
/// * `registry_url` — Base URL of the auths registry (e.g., "https://public.auths.dev").
/// * `interval_secs` — Seconds between verification cycles.
/// * `trust_root` — Trust root containing the log's public key and witness set.
/// * `state_path` — Filesystem path for persisting the last-verified checkpoint.
///
/// Usage:
/// ```ignore
/// let config = MonitorConfig {
///     registry_url: "https://public.auths.dev".into(),
///     interval_secs: 300,
///     trust_root,
///     state_path: PathBuf::from("/data/monitor_state.json"),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Base URL of the auths registry.
    pub registry_url: String,
    /// Seconds between verification cycles.
    pub interval_secs: u64,
    /// Trust root for checkpoint signature verification.
    pub trust_root: TrustRoot,
    /// Filesystem path for persisting last-verified checkpoint state.
    pub state_path: PathBuf,
    /// The honest witness-diversity ceiling derived from the loaded witness
    /// policy. Carried into every [`VerificationReport`] so the monitor never
    /// implies an independence it cannot prove: until an independent commons is
    /// admitted this is `policy_met == false` ("single-operator — not yet
    /// independent"), and the monitor does fork-detection only.
    pub honesty_ceiling: HonestyCeiling,
}

/// Report produced by a single verification cycle.
///
/// Args:
/// * `checked_size` — Tree size of the verified checkpoint.
/// * `entries_verified` — Number of individual entries verified in this cycle.
/// * `consistency_ok` — Whether the consistency proof between old and new checkpoint passed.
/// * `errors` — List of verification errors encountered.
/// * `warnings` — List of non-fatal warnings.
///
/// Usage:
/// ```ignore
/// let report = run_verification_cycle(&config, &client).await?;
/// if report.errors.is_empty() {
///     tracing::info!("cycle passed: {} entries verified", report.entries_verified);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Tree size of the verified checkpoint.
    pub checked_size: u64,
    /// Number of individual entries verified in this cycle.
    pub entries_verified: u64,
    /// Whether the consistency proof between old and new checkpoint passed.
    pub consistency_ok: bool,
    /// The honest witness-diversity ceiling for this cycle. When
    /// `honesty_ceiling.policy_met` is false the monitor performs fork-detection
    /// only — equivocation found here means "one operator's view forked", NOT
    /// "independent operators disagree" (which requires an admitted commons).
    pub honesty_ceiling: HonestyCeiling,
    /// List of verification errors encountered.
    pub errors: Vec<String>,
    /// List of non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Persisted monitor state between cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorState {
    last_checkpoint: SignedCheckpoint,
    last_verified_seq: u64,
}

/// Runs a single verification cycle against the registry.
///
/// Fetches the latest checkpoint, verifies its signature, checks consistency
/// with the previously verified checkpoint (if any), and verifies inclusion
/// proofs for all new entries since the last cycle.
///
/// Args:
/// * `config` — Monitor configuration with registry URL, trust root, and state path.
/// * `client` — HTTP client for making requests to the registry.
///
/// Usage:
/// ```ignore
/// let client = reqwest::Client::new();
/// let report = run_verification_cycle(&config, &client).await?;
/// ```
pub async fn run_verification_cycle(
    config: &MonitorConfig,
    client: &reqwest::Client,
) -> Result<VerificationReport, anyhow::Error> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let checkpoint = fetch_checkpoint(client, &config.registry_url).await?;

    verify_checkpoint_signature(&checkpoint, &config.trust_root, &mut errors);
    verify_witness_cosignatures(&checkpoint, &config.trust_root, &mut warnings);

    let previous = load_state(&config.state_path);
    let mut consistency_ok = true;

    let start_seq = if let Some(ref prev) = previous {
        verify_checkpoint_consistency(
            prev,
            &checkpoint,
            client,
            &config.registry_url,
            &mut errors,
            &mut consistency_ok,
        )
        .await;
        prev.last_verified_seq + 1
    } else {
        0
    };

    let mut entries_verified: u64 = 0;
    if checkpoint.checkpoint.size > 0 && start_seq < checkpoint.checkpoint.size {
        for seq in start_seq..checkpoint.checkpoint.size {
            match verify_entry(client, &config.registry_url, seq, &checkpoint).await {
                Ok(()) => entries_verified += 1,
                Err(e) => errors.push(format!("entry {seq}: {e}")),
            }
        }
    }

    let new_state = MonitorState {
        last_checkpoint: checkpoint.clone(),
        last_verified_seq: if checkpoint.checkpoint.size > 0 {
            checkpoint.checkpoint.size - 1
        } else {
            0
        },
    };
    if let Err(e) = persist_state(&config.state_path, &new_state) {
        warnings.push(format!("failed to persist state: {e}"));
    }

    Ok(VerificationReport {
        checked_size: checkpoint.checkpoint.size,
        entries_verified,
        consistency_ok,
        honesty_ceiling: config.honesty_ceiling.clone(),
        errors,
        warnings,
    })
}

async fn fetch_checkpoint(
    client: &reqwest::Client,
    registry_url: &str,
) -> Result<SignedCheckpoint, anyhow::Error> {
    let url = format!("{registry_url}/v1/log/checkpoint");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let checkpoint: SignedCheckpoint = resp.json().await?;
    Ok(checkpoint)
}

fn verify_checkpoint_signature(
    checkpoint: &SignedCheckpoint,
    trust_root: &TrustRoot,
    errors: &mut Vec<String>,
) {
    if checkpoint.checkpoint.origin != trust_root.log_origin {
        errors.push(format!(
            "checkpoint origin mismatch: expected {}, got {}",
            trust_root.log_origin, checkpoint.checkpoint.origin
        ));
        return;
    }

    // Delegate the signature crypto to auths-transparency, which dispatches on the
    // trust root's algorithm (Ed25519 / ECDSA-P256) — no curve is named here.
    match auths_transparency::verify_checkpoint_signature(checkpoint, trust_root) {
        CheckpointStatus::Verified => {}
        CheckpointStatus::NotProvided => {
            errors.push("no checkpoint signature to verify".into());
        }
        other => {
            errors.push(format!(
                "checkpoint signature verification failed: {other:?}"
            ));
        }
    }
}

fn verify_witness_cosignatures(
    checkpoint: &SignedCheckpoint,
    trust_root: &TrustRoot,
    warnings: &mut Vec<String>,
) {
    // Delegate to auths-transparency: constant-time witness matching, Ed25519
    // cosignature verification, and independence evaluation in one place.
    match auths_transparency::verify_witness_cosignatures(checkpoint, trust_root) {
        WitnessStatus::Quorum { .. } | WitnessStatus::NotProvided => {}
        WitnessStatus::Insufficient { verified, required } => {
            warnings.push(format!(
                "witness quorum not met: {verified}/{required} verified"
            ));
        }
        WitnessStatus::NotIndependent {
            verified,
            required,
            shortfalls,
        } => {
            warnings.push(format!(
                "witness quorum reached ({verified}/{required}) but the cosigning set is \
                 not independent: {}",
                shortfalls.join("; ")
            ));
        }
        other => {
            warnings.push(format!("witness verification inconclusive: {other:?}"));
        }
    }
}

async fn verify_checkpoint_consistency(
    previous: &MonitorState,
    current: &SignedCheckpoint,
    client: &reqwest::Client,
    registry_url: &str,
    errors: &mut Vec<String>,
    consistency_ok: &mut bool,
) {
    let old_size = previous.last_checkpoint.checkpoint.size;
    let new_size = current.checkpoint.size;

    if new_size < old_size {
        errors.push(format!(
            "checkpoint regression: size went from {old_size} to {new_size}"
        ));
        *consistency_ok = false;
        return;
    }

    if new_size == old_size {
        if current.checkpoint.root != previous.last_checkpoint.checkpoint.root {
            errors.push(format!(
                "equivocation detected: size {new_size} but root changed from {} to {}",
                previous.last_checkpoint.checkpoint.root, current.checkpoint.root
            ));
            *consistency_ok = false;
        }
        return;
    }

    match fetch_consistency_proof(client, registry_url, old_size, new_size).await {
        Ok(proof) => {
            if let Err(e) = verify_consistency(
                old_size,
                new_size,
                &proof.hashes,
                &previous.last_checkpoint.checkpoint.root,
                &current.checkpoint.root,
            ) {
                errors.push(format!("consistency proof verification failed: {e}"));
                *consistency_ok = false;
            }
        }
        Err(e) => {
            errors.push(format!("failed to fetch consistency proof: {e}"));
            *consistency_ok = false;
        }
    }
}

async fn fetch_consistency_proof(
    client: &reqwest::Client,
    registry_url: &str,
    old_size: u64,
    new_size: u64,
) -> Result<ConsistencyProof, anyhow::Error> {
    let url = format!("{registry_url}/v1/log/consistency?old_size={old_size}&new_size={new_size}");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let proof: ConsistencyProof = resp.json().await?;
    Ok(proof)
}

async fn verify_entry(
    client: &reqwest::Client,
    registry_url: &str,
    seq: u64,
    checkpoint: &SignedCheckpoint,
) -> Result<(), anyhow::Error> {
    let entry = fetch_entry(client, registry_url, seq).await?;
    let inclusion_proof = fetch_inclusion_proof(client, registry_url, seq).await?;

    let leaf_data = entry
        .leaf_data()
        .map_err(|e| anyhow::anyhow!("leaf data serialization failed: {e}"))?;
    let leaf_hash = hash_leaf(&leaf_data);

    verify_inclusion(
        &leaf_hash,
        inclusion_proof.index,
        inclusion_proof.size,
        &inclusion_proof.hashes,
        &inclusion_proof.root,
    )
    .map_err(|e| anyhow::anyhow!("inclusion verification failed: {e}"))?;

    if inclusion_proof.root != checkpoint.checkpoint.root {
        return Err(anyhow::anyhow!(
            "inclusion proof root does not match checkpoint root"
        ));
    }

    Ok(())
}

async fn fetch_entry(
    client: &reqwest::Client,
    registry_url: &str,
    seq: u64,
) -> Result<Entry, anyhow::Error> {
    let url = format!("{registry_url}/v1/log/entry/{seq}");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let entry: Entry = resp.json().await?;
    Ok(entry)
}

async fn fetch_inclusion_proof(
    client: &reqwest::Client,
    registry_url: &str,
    seq: u64,
) -> Result<InclusionProof, anyhow::Error> {
    let url = format!("{registry_url}/v1/log/entry/{seq}/proof");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let proof: InclusionProof = resp.json().await?;
    Ok(proof)
}

fn load_state(path: &Path) -> Option<MonitorState> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn persist_state(path: &Path, state: &MonitorState) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;

    let tmp_path = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)?;

    Ok(())
}
