//! Load / volume harness for a running `murmur-relay` (any backend).
//!
//! Drives concurrent deposit (+ optional drain) traffic against a relay over HTTP and
//! reports throughput + latency percentiles + error rate. Pair with `redis-cli INFO
//! memory` to read the backlog's Redis memory in volume mode.
//!
//! Build/run (not in the production image — `--example`, uses dev-deps):
//!   cargo run --release --example loadtest -- \
//!     --url http://127.0.0.1:8787 --concurrency 64 --seconds 20 --payload 256 --mode roundtrip
//!
//! Modes:
//!   roundtrip  deposit then drain the same mailbox (steady state, bounded backlog)
//!   deposit    deposit only (builds a backlog — volume test; watch Redis memory)
//!
//! Args (all optional): --url --concurrency --seconds --payload --mailboxes --mode

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use murmur_core::{MailboxId, OuterEnvelope};

struct Cfg {
    url: String,
    concurrency: usize,
    seconds: u64,
    payload: usize,
    mailboxes: u64,
    mode: String,
}

fn parse_args() -> Cfg {
    let mut c = Cfg {
        url: "http://127.0.0.1:8787".to_string(),
        concurrency: 32,
        seconds: 10,
        payload: 256,
        mailboxes: 64,
        mode: "roundtrip".to_string(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let val = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--url" => { c.url = val; i += 2; }
            "--concurrency" => { c.concurrency = val.parse().unwrap_or(c.concurrency); i += 2; }
            "--seconds" => { c.seconds = val.parse().unwrap_or(c.seconds); i += 2; }
            "--payload" => { c.payload = val.parse().unwrap_or(c.payload); i += 2; }
            "--mailboxes" => { c.mailboxes = val.parse().unwrap_or(c.mailboxes); i += 2; }
            "--mode" => { c.mode = val; i += 2; }
            other => { eprintln!("unknown arg: {other}"); i += 1; }
        }
    }
    c
}

/// A unique ciphertext per (worker, counter) so the relay's replay-dedup never short-
/// circuits the load (the first 16 bytes carry the nonce).
fn payload(worker: usize, counter: u64, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size.max(16)];
    v[0..8].copy_from_slice(&(worker as u64).to_le_bytes());
    v[8..16].copy_from_slice(&counter.to_le_bytes());
    v
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cfg = Arc::new(parse_args());
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(cfg.concurrency)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Liveness before we start hammering.
    match client.get(&cfg.url).send().await {
        Ok(r) => println!("relay: {} ({})", cfg.url, r.status()),
        Err(e) => {
            eprintln!("relay unreachable at {}: {e}", cfg.url);
            std::process::exit(1);
        }
    }
    println!(
        "load: {} workers · {}s · {} B payload · {} mailboxes · mode={}",
        cfg.concurrency, cfg.seconds, cfg.payload, cfg.mailboxes, cfg.mode
    );

    let deadline = Instant::now() + Duration::from_secs(cfg.seconds);
    let ops = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    let mut handles = Vec::with_capacity(cfg.concurrency);
    for w in 0..cfg.concurrency {
        let client = client.clone();
        let cfg = cfg.clone();
        let ops = ops.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            let mut latencies: Vec<u64> = Vec::new();
            let mut counter = 0u64;
            let deposit_url = format!("{}/deposit", cfg.url);
            while Instant::now() < deadline {
                let mbx = format!("mbx-load-{}", (w as u64).wrapping_add(counter) % cfg.mailboxes);
                let body = OuterEnvelope {
                    to_mailbox: MailboxId::new(&mbx),
                    ciphertext: payload(w, counter, cfg.payload),
                }
                .to_frame()
                .unwrap();
                let t0 = Instant::now();
                let resp = client.post(&deposit_url).body(body).send().await;
                let ok = matches!(&resp, Ok(r) if r.status().is_success());
                if !ok {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                latencies.push(t0.elapsed().as_micros() as u64);
                ops.fetch_add(1, Ordering::Relaxed);

                if cfg.mode == "roundtrip" {
                    let _ = client.get(format!("{}/drain/{}", cfg.url, mbx)).send().await;
                }
                counter += 1;
            }
            latencies
        }));
    }

    let mut all: Vec<u64> = Vec::new();
    for h in handles {
        if let Ok(mut l) = h.await {
            all.append(&mut l);
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    all.sort_unstable();

    let total = ops.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    println!("\n── results ─────────────────────────────");
    println!("deposits        : {total}");
    println!("errors          : {errs} ({:.3}%)", errs as f64 / total.max(1) as f64 * 100.0);
    println!("throughput      : {:.0} deposits/s", total as f64 / elapsed);
    println!("latency p50     : {:.2} ms", percentile(&all, 0.50) as f64 / 1000.0);
    println!("latency p99     : {:.2} ms", percentile(&all, 0.99) as f64 / 1000.0);
    println!("latency p999    : {:.2} ms", percentile(&all, 0.999) as f64 / 1000.0);
    println!("latency max     : {:.2} ms", all.last().copied().unwrap_or(0) as f64 / 1000.0);
    if cfg.mode == "deposit" {
        println!("\n(volume mode — read Redis memory: redis-cli -p <port> INFO memory | grep used_memory_human)");
    }
}
