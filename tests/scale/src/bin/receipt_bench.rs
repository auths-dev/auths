//! Witness receipting bench — the accept path (submit → validate → receipt →
//! per-prefix store), measured directly.
//!
//! Complements the bulk-onboarding bench (`scale-bench`): that one measures
//! the git-registry *write* path through the SDK; this one drives the witness
//! node's wire — the same router + write bridge `network.auths.dev` runs —
//! with hand-rolled signed KERI events, so the numbers are the accept path
//! and nothing else.
//!
//! Phases:
//! 1. sequential accepts of N distinct members (flat-vs-growing check)
//! 2. concurrent accepts of N distinct members across C tasks (the
//!    serialization check the per-prefix design exists to win)
//! 3. one member's KEL grown to M events (append cost vs KEL length) plus a
//!    full validated replay at the end (cold-resolve cost)
//! 4. correctness gates: idempotent re-submission, conflicting-event refusal,
//!    roster listing with no KEL walk
//!
//! Usage: cargo run --release --bin receipt-bench -- --members 500 --concurrency 8

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use auths_core::witness::wire::encode_submit_body;
use auths_core::witness::{
    witness_router, witness_signer_from_seed_hex, WitnessServerConfig, WitnessServerState,
};
use auths_keri::{
    compute_next_commitment, finalize_icp_event, finalize_ixn_event, serialize_attachment,
    serialize_for_signing, state_after_event, validate_for_append, verify_event_crypto,
    verify_event_said, CesrKey, Event, IcpEvent, IndexedSignature, IxnEvent, KeriPublicKey,
    KeriSequence, Prefix, Said, Seal, Threshold, VersionString,
};
use auths_sdk::storage::PerPrefixKelStore;
use auths_witness_node::kel_sink::KelStoreSink;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer as _, SigningKey};
use tower::ServiceExt;

struct Args {
    members: usize,
    concurrency: usize,
    kel_growth: usize,
    out: Option<PathBuf>,
    label: String,
    registry_dir: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        members: 500,
        concurrency: 8,
        kel_growth: 200,
        out: None,
        label: "receipt".to_string(),
        registry_dir: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .with_context(|| format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--members" => args.members = value()?.parse()?,
            "--concurrency" => args.concurrency = value()?.parse()?,
            "--kel-growth" => args.kel_growth = value()?.parse()?,
            "--out" => args.out = Some(PathBuf::from(value()?)),
            "--label" => args.label = value()?,
            "--registry-dir" => args.registry_dir = Some(PathBuf::from(value()?)),
            other => bail!("unknown flag {other}"),
        }
    }
    Ok(args)
}

/// One member controller: deterministic keys, a signed icp, and signed ixns.
struct Member {
    key: SigningKey,
    icp: IcpEvent,
    attachment: Vec<u8>,
}

impl Member {
    fn new(id: u64) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&id.to_le_bytes());
        seed[8] = 0xA5;
        let key = SigningKey::from_bytes(&seed);
        let mut next_seed = seed;
        next_seed[9] = 0x5A;
        let next = SigningKey::from_bytes(&next_seed);

        let verkey = |k: &SigningKey| KeriPublicKey::ed25519(k.verifying_key().as_bytes()).unwrap();
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(verkey(&key).to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&verkey(&next))],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let icp = finalize_icp_event(icp).unwrap();
        let attachment = sign_attachment(&key, &Event::Icp(icp.clone()));
        Self {
            key,
            icp,
            attachment,
        }
    }

    fn prefix(&self) -> Prefix {
        self.icp.i.clone()
    }

    fn signed_ixn(&self, seq: u128, prior: &Said, marker: u64) -> (IxnEvent, Vec<u8>) {
        let ixn = IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: self.icp.i.clone(),
            s: KeriSequence::new(seq),
            p: prior.clone(),
            a: vec![Seal::Digest {
                d: Said::new_unchecked(format!("EBenchSeal{marker:034}")),
            }],
        };
        let ixn = finalize_ixn_event(ixn).unwrap();
        let attachment = sign_attachment(&self.key, &Event::Ixn(ixn.clone()));
        (ixn, attachment)
    }
}

fn sign_attachment(key: &SigningKey, event: &Event) -> Vec<u8> {
    let canonical = serialize_for_signing(event).unwrap();
    let sig = key.sign(&canonical);
    serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig.to_bytes().to_vec(),
    }])
    .unwrap()
}

fn witness_app(registry: &Path, data_dir: &Path) -> Result<Router> {
    auths_witness_node::sync::ensure_registry(registry)?;
    std::fs::create_dir_all(data_dir)?;
    let signer = witness_signer_from_seed_hex(auths_crypto::CurveType::Ed25519, &"cd".repeat(32))
        .map_err(|e| anyhow::anyhow!("witness signer: {e}"))?;
    let sink = KelStoreSink::new(PerPrefixKelStore::open(registry));
    let config = WitnessServerConfig::from_signer(data_dir.join("receipts.db"), signer)
        .map_err(|e| anyhow::anyhow!("witness config: {e}"))?
        .with_kel_sink(Arc::new(sink));
    let state =
        WitnessServerState::new(config).map_err(|e| anyhow::anyhow!("witness state: {e}"))?;
    Ok(witness_router(state))
}

async fn submit(app: &Router, prefix: &Prefix, event: &Event, attachment: &[u8]) -> StatusCode {
    let event_json = serialize_for_signing(event).unwrap();
    let body = encode_submit_body(&event_json, attachment).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/witness/{}/event", prefix.as_str()))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

fn stats(mut xs: Vec<Duration>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::json!(null);
    }
    xs.sort();
    let ms = |d: &Duration| d.as_secs_f64() * 1e3;
    let pct = |p: f64| ms(&xs[((xs.len() - 1) as f64 * p) as usize]);
    let mean = xs.iter().map(|d| d.as_secs_f64()).sum::<f64>() / xs.len() as f64 * 1e3;
    let decile = xs.len().max(10) / 10;
    let head: f64 = xs[..decile].iter().map(|d| ms(d)).sum::<f64>() / decile as f64;
    let tail: f64 = xs[xs.len() - decile..].iter().map(|d| ms(d)).sum::<f64>() / decile as f64;
    serde_json::json!({
        "n": xs.len(),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "mean_ms": mean,
        "first_decile_mean_ms": head,
        "last_decile_mean_ms": tail,
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let epoch = chrono::Utc::now().timestamp();
    let run_root = args
        .registry_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("runs/{}-{}", args.label, epoch)));
    std::fs::create_dir_all(&run_root)?;
    let registry = run_root.join("registry");
    let data = run_root.join("data");
    let app = witness_app(&registry, &data)?;
    let store = PerPrefixKelStore::open(&registry);

    eprintln!(
        "receipt-bench: members={} concurrency={} kel-growth={} registry={}",
        args.members,
        args.concurrency,
        args.kel_growth,
        registry.display()
    );

    // Phase 1 — sequential accepts of distinct members.
    let mut seq_latencies = Vec::with_capacity(args.members);
    let seq_members: Vec<Member> = (0..args.members as u64).map(Member::new).collect();
    let t0 = Instant::now();
    for member in &seq_members {
        let t = Instant::now();
        let status = submit(
            &app,
            &member.prefix(),
            &Event::Icp(member.icp.clone()),
            &member.attachment,
        )
        .await;
        if status != StatusCode::OK {
            bail!("sequential accept failed with {status}");
        }
        seq_latencies.push(t.elapsed());
    }
    let seq_wall = t0.elapsed();
    let seq_rate = args.members as f64 / seq_wall.as_secs_f64();
    eprintln!(
        "phase 1: {} sequential accepts in {:.2}s ({seq_rate:.1}/s)",
        args.members,
        seq_wall.as_secs_f64()
    );

    // Phase 2 — concurrent accepts of DIFFERENT distinct members.
    let conc_members: Vec<Member> = (args.members as u64..2 * args.members as u64)
        .map(Member::new)
        .collect();
    let t0 = Instant::now();
    let mut handles = Vec::new();
    let chunk = args.members.div_ceil(args.concurrency.max(1));
    for lane in conc_members.chunks(chunk) {
        let app = app.clone();
        let lane: Vec<(Prefix, IcpEvent, Vec<u8>)> = lane
            .iter()
            .map(|m| (m.prefix(), m.icp.clone(), m.attachment.clone()))
            .collect();
        handles.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(lane.len());
            for (prefix, icp, attachment) in lane {
                let t = Instant::now();
                let status = submit(&app, &prefix, &Event::Icp(icp), &attachment).await;
                if status != StatusCode::OK {
                    return Err(anyhow::anyhow!("concurrent accept failed with {status}"));
                }
                latencies.push(t.elapsed());
            }
            Ok(latencies)
        }));
    }
    let mut conc_latencies = Vec::with_capacity(args.members);
    for handle in handles {
        conc_latencies.extend(handle.await??);
    }
    let conc_wall = t0.elapsed();
    let conc_rate = args.members as f64 / conc_wall.as_secs_f64();
    eprintln!(
        "phase 2: {} concurrent accepts in {:.2}s ({conc_rate:.1}/s, {:.2}x sequential)",
        args.members,
        conc_wall.as_secs_f64(),
        conc_rate / seq_rate
    );

    // Phase 3 — one member's KEL grown event by event.
    let grower = Member::new(u64::MAX / 2);
    let prefix = grower.prefix();
    let status = submit(
        &app,
        &prefix,
        &Event::Icp(grower.icp.clone()),
        &grower.attachment,
    )
    .await;
    if status != StatusCode::OK {
        bail!("growth inception failed with {status}");
    }
    let mut growth_latencies = Vec::with_capacity(args.kel_growth);
    let mut prior = grower.icp.d.clone();
    for i in 0..args.kel_growth {
        let (ixn, attachment) = grower.signed_ixn(1 + i as u128, &prior, i as u64);
        prior = ixn.d.clone();
        let t = Instant::now();
        let status = submit(&app, &prefix, &Event::Ixn(ixn), &attachment).await;
        if status != StatusCode::OK {
            bail!("growth append {i} failed with {status}");
        }
        growth_latencies.push(t.elapsed());
    }

    // Cold validated replay of the grown KEL (what a stale-cache reader pays).
    let t = Instant::now();
    let mut state: Option<auths_keri::KeyState> = None;
    store.visit_events(&prefix, 0, &mut |event| {
        let ok = match &state {
            None => verify_event_said(event)
                .and_then(|()| verify_event_crypto(event, None))
                .is_ok(),
            Some(s) => validate_for_append(event, s).is_ok(),
        };
        if !ok {
            return std::ops::ControlFlow::Break(());
        }
        match state_after_event(state.as_ref(), event) {
            Ok(next) => {
                state = Some(next);
                std::ops::ControlFlow::Continue(())
            }
            Err(_) => std::ops::ControlFlow::Break(()),
        }
    })?;
    let replay = t.elapsed();
    let replayed_seq = state.map(|s| s.sequence).unwrap_or_default();
    if replayed_seq != args.kel_growth as u128 {
        bail!(
            "replay stopped at seq {replayed_seq}, expected {}",
            args.kel_growth
        );
    }
    eprintln!(
        "phase 3: {}-event KEL replayed+validated in {:.1}ms",
        args.kel_growth + 1,
        replay.as_secs_f64() * 1e3
    );

    // Phase 4 — correctness gates.
    let (dup_ixn, dup_att) = grower.signed_ixn(1, &grower.icp.d, 0);
    let idempotent = submit(&app, &prefix, &Event::Ixn(dup_ixn), &dup_att).await;
    if idempotent != StatusCode::OK {
        bail!("idempotent re-submission must be receipted, got {idempotent}");
    }
    let (conflict_ixn, conflict_att) = grower.signed_ixn(1, &grower.icp.d, 999_999);
    let conflict = submit(&app, &prefix, &Event::Ixn(conflict_ixn), &conflict_att).await;
    if conflict != StatusCode::CONFLICT {
        bail!("conflicting event must be refused with 409, got {conflict}");
    }
    let t = Instant::now();
    let roster = store.list_prefixes()?;
    let roster_elapsed = t.elapsed();
    let expected_roster = 2 * args.members + 1;
    if roster.len() != expected_roster {
        bail!(
            "roster holds {} prefixes, expected {expected_roster}",
            roster.len()
        );
    }
    eprintln!(
        "phase 4: gates pass (idempotent 200, conflict 409, roster {} in {:.1}ms)",
        roster.len(),
        roster_elapsed.as_secs_f64() * 1e3
    );

    let du = std::process::Command::new("du")
        .args(["-sk", registry.to_string_lossy().as_ref()])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .and_then(|kb| kb.parse::<u64>().ok())
        });

    let report = serde_json::json!({
        "bench": "receipt-bench",
        "label": args.label,
        "epoch": epoch,
        "members": args.members,
        "concurrency": args.concurrency,
        "kel_growth": args.kel_growth,
        "sequential": {
            "wall_s": seq_wall.as_secs_f64(),
            "accepts_per_s": seq_rate,
            "latency": stats(seq_latencies),
        },
        "concurrent": {
            "wall_s": conc_wall.as_secs_f64(),
            "accepts_per_s": conc_rate,
            "speedup_vs_sequential": conc_rate / seq_rate,
            "latency": stats(conc_latencies),
        },
        "kel_growth_append": stats(growth_latencies),
        "cold_replay_ms": replay.as_secs_f64() * 1e3,
        "roster_ms": roster_elapsed.as_secs_f64() * 1e3,
        "registry_disk_kb": du,
    });
    let rendered = serde_json::to_string_pretty(&report)?;
    println!("{rendered}");
    if let Some(out) = &args.out {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out, &rendered)?;
        eprintln!("receipt-bench: wrote {}", out.display());
    }
    Ok(())
}
