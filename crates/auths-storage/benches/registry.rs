//! Benchmarks for registry operations.
//!
//! Run with: cargo bench --package auths-storage
#![allow(clippy::unwrap_used, clippy::expect_used)]

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::event::{Event, IcpEvent, IxnEvent, KeriSequence};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::{finalize_icp_event, serialize_for_signing};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_keri::{CesrKey, Threshold, VersionString};
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
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(key_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
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
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: Said::new_unchecked(prev_said.to_string()),
        a: vec![Seal::digest("EBench")],
        x: String::new(),
    };

    let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&value).unwrap();

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

/// Benchmark batch vs sequential for N events to a single identity.
fn bench_batch_vs_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_vs_sequential");

    for n in [100, 500, 1000] {
        // Sequential: append N events one at a time
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let (dir, backend) = setup_registry();
                    let (icp, prefix, keypair) = make_signed_icp();

                    let mut events = vec![(prefix.clone(), icp.clone())];
                    let mut prev_said = icp.said().to_string();
                    for seq in 1..n {
                        let ixn = make_signed_ixn(&prefix, seq, &prev_said, &keypair);
                        prev_said = ixn.said().to_string();
                        events.push((prefix.clone(), ixn));
                    }
                    (dir, backend, events)
                },
                |(_dir, backend, events)| {
                    for (prefix, event) in &events {
                        let _ = black_box(backend.append_event(prefix, event));
                    }
                },
            );
        });

        // Batch: append N events in a single batch call
        group.bench_with_input(BenchmarkId::new("batch", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let (dir, backend) = setup_registry();
                    let (icp, prefix, keypair) = make_signed_icp();

                    let mut events = vec![(prefix.clone(), icp.clone())];
                    let mut prev_said = icp.said().to_string();
                    for seq in 1..n {
                        let ixn = make_signed_ixn(&prefix, seq, &prev_said, &keypair);
                        prev_said = ixn.said().to_string();
                        events.push((prefix.clone(), ixn));
                    }
                    (dir, backend, events)
                },
                |(_dir, backend, events)| {
                    let _ = black_box(backend.batch_append_events(&events));
                },
            );
        });
    }

    group.finish();
}

/// Benchmark batch across multiple identities (100 identities x 10 events each).
fn bench_batch_mixed_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_mixed_prefix");

    for (identity_count, events_per_id) in [(10, 10), (100, 10)] {
        let total = identity_count * events_per_id;
        group.throughput(Throughput::Elements(total));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{identity_count}ids_x_{events_per_id}events")),
            &(identity_count, events_per_id),
            |b, &(id_count, ev_count)| {
                b.iter_with_setup(
                    || {
                        let (dir, backend) = setup_registry();
                        let mut all_events = Vec::new();

                        for _ in 0..id_count {
                            let (icp, prefix, keypair) = make_signed_icp();
                            all_events.push((prefix.clone(), icp.clone()));

                            let mut prev_said = icp.said().to_string();
                            for seq in 1..ev_count {
                                let ixn = make_signed_ixn(&prefix, seq, &prev_said, &keypair);
                                prev_said = ixn.said().to_string();
                                all_events.push((prefix.clone(), ixn));
                            }
                        }
                        (dir, backend, all_events)
                    },
                    |(_dir, backend, events)| {
                        let _ = black_box(backend.batch_append_events(&events));
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
    bench_batch_vs_sequential,
    bench_batch_mixed_prefix,
);
criterion_main!(benches);
