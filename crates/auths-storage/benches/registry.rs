//! Benchmarks for registry operations.
//!
//! Run with: cargo bench --package auths-storage

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::event::{Event, IcpEvent, IxnEvent, KeriSequence};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::{finalize_icp_event, serialize_for_signing};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::hint::black_box;
use tempfile::TempDir;

/// Create a signed ICP event and return (event, prefix, keypair).
fn make_signed_icp() -> (Event, Prefix, Ed25519KeyPair) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let icp = IcpEvent {
        v: "KERI10JSON".to_string(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: "1".to_string(),
        k: vec![key_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp).unwrap();
    let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
    let sig = keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    let prefix = finalized.i.clone();
    (Event::Icp(finalized), prefix, keypair)
}

/// Create a signed IXN event.
fn make_signed_ixn(prefix: &Prefix, seq: u64, prev_said: &str, keypair: &Ed25519KeyPair) -> Event {
    let mut ixn = IxnEvent {
        v: "KERI10JSON".to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: Said::new_unchecked(prev_said.to_string()),
        a: vec![Seal::device_attestation("EBench")],
        x: String::new(),
    };

    let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&json);

    let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
    let sig = keypair.sign(&canonical);
    ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Event::Ixn(ixn)
}

/// Set up a temporary registry backend.
fn setup_registry() -> (TempDir, GitRegistryBackend) {
    let dir = TempDir::new().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (dir, backend)
}

/// Benchmark cached key state lookup at various identity counts.
fn bench_cached_key_state_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_state_lookup");

    for n in [10, 100, 500] {
        let (_dir, backend) = setup_registry();

        // Populate with N identities
        let mut prefixes = Vec::with_capacity(n);
        for _ in 0..n {
            let (icp, prefix, _keypair) = make_signed_icp();
            backend.append_event(&prefix, &icp).unwrap();
            prefixes.push(prefix);
        }

        // Warm the cache by reading once
        let _ = backend.get_key_state(&prefixes[0]);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{n}_identities")),
            &prefixes,
            |b, prefixes| {
                let mut idx = 0;
                b.iter(|| {
                    let prefix = &prefixes[idx % prefixes.len()];
                    let _ = black_box(backend.get_key_state(prefix));
                    idx += 1;
                })
            },
        );
    }

    group.finish();
}

/// Benchmark cache cold start (first read triggers rebuild).
fn bench_cache_cold_start(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_cold_start");

    for n in [10, 100] {
        // Each iteration creates a fresh registry
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{n}_identities")),
            &n,
            |b, &n| {
                b.iter_with_setup(
                    || {
                        let (dir, backend) = setup_registry();
                        let mut first_prefix = Prefix::default();
                        for i in 0..n {
                            let (icp, prefix, _keypair) = make_signed_icp();
                            backend.append_event(&prefix, &icp).unwrap();
                            if i == 0 {
                                first_prefix = prefix;
                            }
                        }
                        // Create a fresh backend to simulate cold cache
                        let fresh_backend = GitRegistryBackend::from_config_unchecked(
                            RegistryConfig::single_tenant(dir.path()),
                        );
                        (dir, fresh_backend, first_prefix)
                    },
                    |(_dir, backend, prefix)| {
                        // Cold start: first read triggers cache rebuild
                        let _ = black_box(backend.get_key_state(&prefix));
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark event append (includes verify_event_crypto + git commit).
fn bench_event_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_append");
    group.throughput(Throughput::Elements(1));

    group.bench_function("interaction_append", |b| {
        b.iter_with_setup(
            || {
                let (dir, backend) = setup_registry();
                let (icp, prefix, keypair) = make_signed_icp();
                backend.append_event(&prefix, &icp).unwrap();
                let said = icp.said().to_string();
                (dir, backend, prefix, said, keypair, 1u64)
            },
            |(dir, backend, prefix, prev_said, keypair, seq)| {
                let ixn = make_signed_ixn(&prefix, seq, &prev_said, &keypair);
                let _ = black_box(backend.append_event(&prefix, &ixn));
                // Keep dir alive
                let _ = &dir;
            },
        );
    });

    group.finish();
}

/// Benchmark append scaling: confirm O(1) regardless of KEL depth.
///
/// Pre-populates a KEL with N events, then benchmarks appending one more.
/// If append is O(1), time should be constant across N values.
fn bench_event_append_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_scaling");
    group.throughput(Throughput::Elements(1));

    for n in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("kel_depth_{n}")),
            &n,
            |b, &n| {
                b.iter_with_setup(
                    || {
                        let (dir, backend) = setup_registry();
                        let (icp, prefix, keypair) = make_signed_icp();
                        backend.append_event(&prefix, &icp).unwrap();

                        let mut prev_said = icp.said().to_string();
                        for seq in 1..=n {
                            let ixn = make_signed_ixn(&prefix, seq, &prev_said, &keypair);
                            prev_said = ixn.said().to_string();
                            backend.append_event(&prefix, &ixn).unwrap();
                        }

                        let next_seq = n + 1;
                        let ixn = make_signed_ixn(&prefix, next_seq, &prev_said, &keypair);
                        (dir, backend, prefix, ixn)
                    },
                    |(_dir, backend, prefix, ixn)| {
                        let _ = black_box(backend.append_event(&prefix, &ixn));
                    },
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cached_key_state_lookup,
    bench_cache_cold_start,
    bench_event_append,
    bench_event_append_scaling,
);
criterion_main!(benches);
