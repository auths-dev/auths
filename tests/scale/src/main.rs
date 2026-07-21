//! scale-bench — bulk agent-onboarding benchmark for the auths org root KEL.
//!
//! Measures the write path from issue #255 (10k-agent org onboarding) and the
//! read paths that pay for it afterwards (full-KEL replay, chain verification,
//! fleet metrics). Designed to run unchanged on `main` and on comparison
//! branches so results are A/B-comparable; the deterministic invariants
//! (root-KEL event count, git commit count, correctness assertions) matter as
//! much as the timings.
//!
//! Action suite, in order:
//!   1. init registry + bare org root identity (no device #0)
//!   2. provision N delegated agents (`agents::add`) — per-op latency
//!   3. cold full root-KEL replay (`visit_events`) — the verifier's cost
//!   4. chain-verify sample (`validate_delegation` dip vs root KEL)
//!   5. sign sample (agent key via `StorageSigner::sign_with_alias`)
//!   6. revoke sample (individual `agents::revoke`) — per-op latency
//!   7. batch revoke sample (`agents::revoke_batch`) — one event, many seals
//!   8. fleet_metrics — holistic correctness: total/revoked/live must match
//!
//! Caveats recorded in the output:
//!   - built with auths-core `test-utils` (weak Argon2 test params), so KDF
//!     cost is deliberately excluded; identical on every branch, so the A/B
//!     comparison is unaffected.
//!   - timings use `Instant` (CLOCK_UPTIME_RAW on macOS), which does not
//!     advance across system sleep.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use serde_json::json;

use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::testing::IsolatedKeychainHandle;
use auths_core::PrefilledPassphraseProvider;
use auths_crypto::CurveType;
use auths_id::attestation::export::AttestationSink;
use auths_id::keri::types::Prefix;
use auths_id::keri::validate_delegation;
use auths_id::keri::Event;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::{add, revoke, revoke_batch};
use auths_sdk::domains::org::metrics::fleet_metrics;
use auths_sdk::identity::initialize_registry_identity;
use auths_sdk::witness::WitnessParams;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

const PASS: &str = "Scale-bench-passphrase1!";

struct Args {
    agents: usize,
    sign_sample: usize,
    verify_sample: usize,
    revoke_sample: usize,
    batch_revoke_sample: usize,
    registry_dir: Option<PathBuf>,
    out: Option<PathBuf>,
    label: String,
    skip_fleet_metrics: bool,
    bulk_batch: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: scale-bench --agents N [--label NAME] [--out FILE.json]\n\
         \x20                [--sign-sample S] [--verify-sample V]\n\
         \x20                [--revoke-sample R] [--batch-revoke-sample B]\n\
         \x20                [--registry-dir DIR]\n\
         defaults: sign/verify = min(N,500); revoke/batch = min(N/20,200)"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        agents: 100,
        sign_sample: usize::MAX,
        verify_sample: usize::MAX,
        revoke_sample: usize::MAX,
        batch_revoke_sample: usize::MAX,
        registry_dir: None,
        out: None,
        label: "run".to_string(),
        skip_fleet_metrics: false,
        bulk_batch: 0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let val = |it: &mut dyn Iterator<Item = String>| -> String {
            it.next().unwrap_or_else(|| usage())
        };
        match a.as_str() {
            "--agents" => args.agents = val(&mut it).parse().unwrap_or_else(|_| usage()),
            "--sign-sample" => args.sign_sample = val(&mut it).parse().unwrap_or_else(|_| usage()),
            "--verify-sample" => {
                args.verify_sample = val(&mut it).parse().unwrap_or_else(|_| usage())
            }
            "--revoke-sample" => {
                args.revoke_sample = val(&mut it).parse().unwrap_or_else(|_| usage())
            }
            "--batch-revoke-sample" => {
                args.batch_revoke_sample = val(&mut it).parse().unwrap_or_else(|_| usage())
            }
            "--registry-dir" => args.registry_dir = Some(PathBuf::from(val(&mut it))),
            "--out" => args.out = Some(PathBuf::from(val(&mut it))),
            "--label" => args.label = val(&mut it),
            "--skip-fleet-metrics" => args.skip_fleet_metrics = true,
            "--bulk-batch" => args.bulk_batch = val(&mut it).parse().unwrap_or_else(|_| usage()),
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown arg: {other}");
                usage();
            }
        }
    }
    let n = args.agents;
    if args.sign_sample == usize::MAX {
        args.sign_sample = n.min(500);
    }
    if args.verify_sample == usize::MAX {
        args.verify_sample = n.min(500);
    }
    if args.revoke_sample == usize::MAX {
        args.revoke_sample = (n / 20).min(200);
    }
    if args.batch_revoke_sample == usize::MAX {
        args.batch_revoke_sample = (n / 20).min(200);
    }
    if args.revoke_sample + args.batch_revoke_sample > n {
        eprintln!("revoke samples exceed agent count");
        usage();
    }
    args
}

fn git_init_if_needed(path: &Path) -> Result<()> {
    if path.join(".git").exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)?;
    let st = Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .context("spawn git init")?;
    if !st.success() {
        bail!("git init failed in {}", path.display());
    }
    Ok(())
}

/// Mirror of auths-sdk's test helper `build_test_context_with_provider`.
fn build_context(
    registry_path: &Path,
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
    passphrase_provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
) -> Result<AuthsContext> {
    git_init_if_needed(registry_path)?;

    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(registry_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(registry_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;

    let mut builder = AuthsContext::builder()
        .registry(backend)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .repo_path(registry_path.to_path_buf());
    if let Some(pp) = passphrase_provider {
        builder = builder.passphrase_provider(pp);
    }
    Ok(builder.build())
}

fn collect_kel(
    backend: &(dyn RegistryBackend + Send + Sync),
    prefix: &Prefix,
) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .map_err(|e| anyhow::anyhow!("KEL replay failed: {e}"))?;
    Ok(events)
}

fn stats(durs: &mut [Duration]) -> serde_json::Value {
    if durs.is_empty() {
        return json!(null);
    }
    durs.sort();
    let n = durs.len();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let pick = |p: f64| ms(durs[(((n - 1) as f64) * p).round() as usize]);
    let total: f64 = durs.iter().map(|d| d.as_secs_f64()).sum();
    json!({
        "count": n,
        "total_s": total,
        "mean_ms": total * 1000.0 / n as f64,
        "p50_ms": pick(0.50),
        "p95_ms": pick(0.95),
        "p99_ms": pick(0.99),
        "min_ms": ms(durs[0]),
        "max_ms": ms(durs[n - 1]),
        "ops_per_sec": if total > 0.0 { n as f64 / total } else { 0.0 },
    })
}

fn sample_indices(n: usize, k: usize) -> Vec<usize> {
    if k == 0 || n == 0 {
        return Vec::new();
    }
    let k = k.min(n);
    (0..k).map(|i| i * n / k).collect()
}

fn sh(dir: &Path, cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn main() -> Result<()> {
    let args = parse_args();
    let n = args.agents;
    let started_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Where the auths checkout lives (for provenance), and where runs go.
    let bench_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let auths_root = bench_dir.ancestors().nth(2).map(Path::to_path_buf);
    let (git_rev, git_branch) = match &auths_root {
        Some(root) => (
            sh(root, "git", &["rev-parse", "--short", "HEAD"]),
            sh(root, "git", &["rev-parse", "--abbrev-ref", "HEAD"]),
        ),
        None => (None, None),
    };

    let registry_path = args.registry_dir.clone().unwrap_or_else(|| {
        bench_dir
            .join("runs")
            .join(format!("{}-{}", args.label, started_unix))
            .join("registry")
    });
    if registry_path.exists() && registry_path.join(".git").exists() {
        bail!(
            "registry dir {} already holds a repo — use a fresh dir",
            registry_path.display()
        );
    }
    eprintln!("registry: {}", registry_path.display());
    eprintln!(
        "branch: {} @ {}  agents: {n}  label: {}",
        git_branch.as_deref().unwrap_or("?"),
        git_rev.as_deref().unwrap_or("?"),
        args.label
    );

    // ---- Phase 1: registry + bare org root -------------------------------
    let keychain = IsolatedKeychainHandle::new();
    let provider = PrefilledPassphraseProvider::new(PASS);
    let boot = build_context(&registry_path, Arc::new(keychain.clone()), None)?;

    let t = Instant::now();
    let (_org_did, org_alias) = initialize_registry_identity(
        Arc::clone(&boot.registry),
        &KeyAlias::new_unchecked("org-key"),
        &provider,
        &keychain,
        WitnessParams::Disabled,
        CurveType::Ed25519,
        chrono::Utc::now(),
    )
    .map_err(|e| anyhow::anyhow!("init org identity: {e}"))?;
    let init_root_ms = t.elapsed().as_secs_f64() * 1000.0;

    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_context(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(arc_provider),
    )?;
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| anyhow::anyhow!("load identity: {e}"))?;
    let org_prefix_str = managed
        .controller_did
        .as_str()
        .strip_prefix("did:keri:")
        .context("controller_did is not did:keri")?
        .to_string();
    let org_prefix = Prefix::new_unchecked(org_prefix_str.clone());

    // ---- Phase 2: provision N agents --------------------------------------
    if args.bulk_batch > 0 && !cfg!(feature = "bulk") {
        bail!("--bulk-batch requires a build with --features bulk (the KL-9 branch)");
    }
    eprintln!(
        "provisioning {n} agents ({})…",
        if args.bulk_batch > 0 {
            format!("bulk, batch={}", args.bulk_batch)
        } else {
            "per-agent".to_string()
        }
    );
    let mut provision = Vec::with_capacity(n);
    let mut agents: Vec<(String, String, KeyAlias)> = Vec::with_capacity(n); // (did, prefix, alias)
    let phase_provision = Instant::now();
    if args.bulk_batch > 0 {
        #[cfg(feature = "bulk")]
        {
            let aliases: Vec<KeyAlias> = (0..n)
                .map(|i| KeyAlias::new_unchecked(format!("agent-{i:05}")))
                .collect();
            let mut done = 0usize;
            for chunk in aliases.chunks(args.bulk_batch) {
                let t = Instant::now();
                let res = auths_sdk::domains::agents::add_bulk(
                    &ctx,
                    &org_alias,
                    chunk,
                    CurveType::Ed25519,
                    chunk.len(),
                )
                .map_err(|e| anyhow::anyhow!("add_bulk at {done}: {e}"))?;
                // Per-agent share of the batch latency, so percentile fields stay
                // comparable across modes (noted in meta.provision_mode).
                let per = t.elapsed() / chunk.len() as u32;
                for (j, r) in res.into_iter().enumerate() {
                    provision.push(per);
                    agents.push((r.agent_did, r.agent_prefix, chunk[j].clone()));
                }
                done += chunk.len();
                if done % 500 < chunk.len() {
                    let el = phase_provision.elapsed().as_secs_f64();
                    eprintln!("  {done}/{n} agents  ({:.1} agents/s)", done as f64 / el);
                }
            }
        }
    } else {
        for i in 0..n {
            let alias = KeyAlias::new_unchecked(format!("agent-{i:05}"));
            let t = Instant::now();
            let a = add(&ctx, &org_alias, &alias, CurveType::Ed25519)
                .map_err(|e| anyhow::anyhow!("add agent {i}: {e}"))?;
            provision.push(t.elapsed());
            agents.push((a.agent_did, a.agent_prefix, alias));
            if (i + 1) % 500 == 0 {
                let el = phase_provision.elapsed().as_secs_f64();
                eprintln!(
                    "  {}/{n} agents  ({:.1} agents/s)",
                    i + 1,
                    (i + 1) as f64 / el
                );
            }
        }
    }
    let provision_wall_s = phase_provision.elapsed().as_secs_f64();

    // ---- Phase 3: cold full root-KEL replay -------------------------------
    let t = Instant::now();
    let root_kel = collect_kel(ctx.registry.as_ref(), &org_prefix)?;
    let replay_ms = t.elapsed().as_secs_f64() * 1000.0;
    let root_events_after_provision = root_kel.len();

    // ---- Phase 4: chain-verify sample --------------------------------------
    let mut verify = Vec::new();
    let mut verified_ok = 0usize;
    for &i in &sample_indices(n, args.verify_sample) {
        let prefix = Prefix::new_unchecked(agents[i].1.clone());
        let dip = ctx
            .registry
            .get_event(&prefix, 0)
            .map_err(|e| anyhow::anyhow!("get dip {i}: {e}"))?;
        let t = Instant::now();
        validate_delegation(&dip, &root_kel)
            .map_err(|e| anyhow::anyhow!("agent {i} failed chain verification: {e}"))?;
        verify.push(t.elapsed());
        verified_ok += 1;
    }

    // ---- Phase 5: sign sample ----------------------------------------------
    let signer = StorageSigner::new(keychain.clone());
    let mut sign = Vec::new();
    let msg = b"scale-bench canonical payload";
    for &i in &sample_indices(n, args.sign_sample) {
        let t = Instant::now();
        let sig = signer
            .sign_with_alias(&agents[i].2, &provider, msg)
            .map_err(|e| anyhow::anyhow!("sign as agent {i}: {e}"))?;
        sign.push(t.elapsed());
        if sig.is_empty() {
            bail!("agent {i} produced an empty signature");
        }
    }

    // ---- Phase 6: individual revocations (from the tail) -------------------
    let mut revoke_durs = Vec::new();
    let revoke_start = n - args.revoke_sample - args.batch_revoke_sample;
    for i in revoke_start..revoke_start + args.revoke_sample {
        let t = Instant::now();
        revoke(&ctx, &org_alias, &agents[i].0)
            .map_err(|e| anyhow::anyhow!("revoke agent {i}: {e}"))?;
        revoke_durs.push(t.elapsed());
    }

    // ---- Phase 7: batch revocation (one event, many seals) ------------------
    let batch_dids: Vec<String> = agents[n - args.batch_revoke_sample..]
        .iter()
        .map(|a| a.0.clone())
        .collect();
    let mut batch_revoke_ms = None;
    if !batch_dids.is_empty() {
        let t = Instant::now();
        let receipt = revoke_batch(&ctx, &org_alias, &batch_dids)
            .map_err(|e| anyhow::anyhow!("batch revoke: {e}"))?;
        batch_revoke_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
        if receipt.revoked.len() != batch_dids.len() {
            bail!(
                "batch revocation covered {}/{} agents",
                receipt.revoked.len(),
                batch_dids.len()
            );
        }
    }

    // ---- Phase 8: fleet metrics (holistic correctness) ----------------------
    // Optional: this read path is superlinear in fleet size today, so huge runs
    // may skip it and rely on chain-verify + batch receipts for correctness.
    let expected_revoked = args.revoke_sample + args.batch_revoke_sample;
    let mut fleet_metrics_ms = None;
    let mut fleet_counts = (None, None, None);
    if !args.skip_fleet_metrics {
        let t = Instant::now();
        let fm = fleet_metrics(&ctx, &auths_verifier::Prefix::new_unchecked(org_prefix_str))
            .map_err(|e| anyhow::anyhow!("fleet metrics: {e}"))?;
        fleet_metrics_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
        if fm.agents_total != n || fm.agents_revoked != expected_revoked {
            bail!(
                "fleet metrics mismatch: total {} (want {n}), revoked {} (want {expected_revoked})",
                fm.agents_total,
                fm.agents_revoked
            );
        }
        fleet_counts = (
            Some(fm.agents_total),
            Some(fm.agents_revoked),
            Some(fm.agents_live),
        );
    }

    // ---- Deterministic invariants -------------------------------------------
    let tip = ctx
        .registry
        .get_tip(&org_prefix)
        .map_err(|e| anyhow::anyhow!("get tip: {e}"))?;
    let root_events_final = (tip.sequence + 1) as u64;
    let root_ixn_per_agent = (root_events_after_provision.saturating_sub(1)) as f64 / n as f64;
    let commit_count = sh(
        &registry_path,
        "git",
        &["rev-list", "--count", "refs/auths/registry"],
    )
    .or_else(|| sh(&registry_path, "git", &["rev-list", "--count", "HEAD"]))
    .and_then(|s| s.parse::<u64>().ok());
    // Append-degradation signal: mean latency of the first vs last decile.
    let decile = (n / 10).max(1);
    let decile_mean_ms = |slice: &[Duration]| {
        slice.iter().map(|d| d.as_secs_f64()).sum::<f64>() * 1000.0 / slice.len() as f64
    };
    let first_decile_ms = decile_mean_ms(&provision[..decile]);
    let last_decile_ms = decile_mean_ms(&provision[n - decile..]);
    let du_kb = sh(&registry_path, "du", &["-sk", "."])
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<u64>().ok());

    let result = json!({
        "meta": {
            "label": args.label,
            "started_unix": started_unix,
            "git_branch": git_branch,
            "git_rev": git_rev,
            "argon2": "test-utils weak params (KDF cost excluded, identical across branches)",
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
        "params": {
            "agents": n,
            "provision_mode": if args.bulk_batch > 0 { "bulk" } else { "per-agent" },
            "bulk_batch": args.bulk_batch,
            "sign_sample": args.sign_sample,
            "verify_sample": args.verify_sample,
            "revoke_sample": args.revoke_sample,
            "batch_revoke_sample": args.batch_revoke_sample,
        },
        "invariants": {
            "root_kel_events_after_provision": root_events_after_provision,
            "root_kel_events_final": root_events_final,
            "root_anchor_events_per_agent": root_ixn_per_agent,
            "registry_git_commits": commit_count,
            "registry_du_kb": du_kb,
            "chain_verified_ok": verified_ok,
            "expected_revoked": expected_revoked,
            "fleet_total": fleet_counts.0,
            "fleet_revoked": fleet_counts.1,
            "fleet_live": fleet_counts.2,
        },
        "timings": {
            "init_root_ms": init_root_ms,
            "provision": stats(&mut provision),
            "provision_wall_s": provision_wall_s,
            "provision_agents_per_sec": n as f64 / provision_wall_s,
            "provision_first_decile_mean_ms": first_decile_ms,
            "provision_last_decile_mean_ms": last_decile_ms,
            "cold_root_kel_replay_ms": replay_ms,
            "chain_verify": stats(&mut verify),
            "sign": stats(&mut sign),
            "revoke_individual": stats(&mut revoke_durs),
            "revoke_batch_ms": batch_revoke_ms,
            "fleet_metrics_ms": fleet_metrics_ms,
        },
    });

    let rendered = serde_json::to_string_pretty(&result)?;
    if let Some(out) = &args.out {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out, &rendered)?;
        eprintln!("results written to {}", out.display());
    }
    println!("{rendered}");

    eprintln!(
        "\nSUMMARY [{}] {} agents: {:.1} agents/s onboarding, {:.2} root events/agent, \
         replay {:.0} ms, {} commits, {} KB",
        args.label,
        n,
        n as f64 / provision_wall_s,
        root_ixn_per_agent,
        replay_ms,
        commit_count.map_or("?".into(), |c| c.to_string()),
        du_kb.map_or("?".into(), |k| k.to_string()),
    );
    Ok(())
}
