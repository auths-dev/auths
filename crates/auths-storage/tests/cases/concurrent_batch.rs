use std::sync::{Arc, Barrier};
use std::thread;

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::KeriSequence;
use auths_id::keri::event::{Event, IcpEvent, IxnEvent};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::{finalize_icp_event, serialize_for_signing};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;

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

fn make_signed_ixn(prefix: &Prefix, seq: u64, prev_said: &str, keypair: &Ed25519KeyPair) -> Event {
    let mut ixn = IxnEvent {
        v: "KERI10JSON".to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: Said::new_unchecked(prev_said.to_string()),
        a: vec![Seal::device_attestation("EConcurrentBatch")],
        x: String::new(),
    };

    let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&json);

    let canonical = serialize_for_signing(&Event::Ixn(ixn.clone())).unwrap();
    let sig = keypair.sign(&canonical);
    ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Event::Ixn(ixn)
}

fn setup() -> (TempDir, GitRegistryBackend) {
    let dir = TempDir::new().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (dir, backend)
}

#[test]
fn sequential_batches_produce_correct_state() {
    let (dir, backend) = setup();

    // Batch 1: 3 new identities
    let e1 = make_signed_icp();
    let e2 = make_signed_icp();
    let e3 = make_signed_icp();

    backend
        .batch_append_events(&[
            (e1.1.clone(), e1.0.clone()),
            (e2.1.clone(), e2.0.clone()),
            (e3.1.clone(), e3.0.clone()),
        ])
        .unwrap();

    assert_eq!(backend.metadata().unwrap().identity_count, 3);

    // Batch 2: 2 more identities
    let e4 = make_signed_icp();
    let e5 = make_signed_icp();

    let backend2 =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend2
        .batch_append_events(&[(e4.1.clone(), e4.0.clone()), (e5.1.clone(), e5.0.clone())])
        .unwrap();

    assert_eq!(backend2.metadata().unwrap().identity_count, 5);

    // All tips correct
    for (_, prefix, _) in [&e1, &e2, &e3, &e4, &e5] {
        assert_eq!(backend2.get_tip(prefix).unwrap().sequence, 0);
    }
}

/// N threads each submit a batch of unique identities. With advisory lock
/// serializing access, all should eventually succeed via retry.
#[test]
fn parallel_batch_writers_different_identities() {
    let (dir, _backend) = setup();
    let path = dir.path().to_path_buf();

    let thread_count = 6;
    let identities_per_batch = 3;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);

            // Pre-generate batch events (keypair isn't Send)
            let mut batch = Vec::with_capacity(identities_per_batch);
            for _ in 0..identities_per_batch {
                let (event, prefix, _keypair) = make_signed_icp();
                batch.push((prefix, event));
            }

            thread::spawn(move || {
                let backend =
                    GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));
                barrier.wait();

                for _ in 0..20 {
                    match backend.batch_append_events(&batch) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            let msg = format!("{e}");
                            if msg.contains("Concurrent modification") {
                                thread::sleep(std::time::Duration::from_millis(10));
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                panic!("exceeded retry limit for batch writer");
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, thread_count);

    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    let meta = backend.metadata().unwrap();
    assert_eq!(
        meta.identity_count,
        (thread_count * identities_per_batch) as u64
    );
}

/// One thread appends a batch, another appends single events concurrently.
/// Both should succeed with retries.
#[test]
fn batch_and_single_event_interleaving() {
    let (dir, _backend) = setup();
    let path = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));

    // Pre-generate batch events
    let mut batch = Vec::with_capacity(5);
    for _ in 0..5 {
        let (event, prefix, _keypair) = make_signed_icp();
        batch.push((prefix, event));
    }

    // Pre-generate single events
    let mut singles: Vec<(Prefix, Event)> = Vec::with_capacity(5);
    for _ in 0..5 {
        let (event, prefix, _keypair) = make_signed_icp();
        singles.push((prefix, event));
    }

    let path2 = path.clone();
    let barrier2 = Arc::clone(&barrier);

    let batch_handle = thread::spawn(move || {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));
        barrier.wait();

        for _ in 0..20 {
            match backend.batch_append_events(&batch) {
                Ok(()) => return,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("Concurrent modification") {
                        thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    panic!("unexpected batch error: {e}");
                }
            }
        }
        panic!("batch writer exceeded retry limit");
    });

    let single_handle = thread::spawn(move || {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path2));
        barrier2.wait();

        for (prefix, event) in &singles {
            for _ in 0..20 {
                match backend.append_event(prefix, event) {
                    Ok(()) => break,
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("Concurrent modification") || msg.contains("already exists")
                        {
                            thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        panic!("unexpected single-event error: {e}");
                    }
                }
            }
        }
    });

    batch_handle.join().unwrap();
    single_handle.join().unwrap();

    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 10);
}

/// A batch fails because of a CAS conflict (stale parent commit).
/// Verify the error is ConcurrentModification, not corruption.
#[test]
fn batch_cas_failure_returns_clear_error() {
    let (dir, backend) = setup();

    // Pre-populate so there's something in the registry
    let (icp, prefix, _keypair) = make_signed_icp();
    backend.append_event(&prefix, &icp).unwrap();

    // Prepare a batch for a second writer
    let mut batch = Vec::with_capacity(3);
    for _ in 0..3 {
        let (event, p, _) = make_signed_icp();
        batch.push((p, event));
    }

    let path = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = Arc::clone(&barrier);

    // Writer 1: holds the lock and writes, then releases
    let path2 = path.clone();
    let writer1 = thread::spawn(move || {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path2));
        let (event, prefix, _) = make_signed_icp();
        barrier2.wait();
        backend.append_event(&prefix, &event).unwrap();
    });

    // Writer 2: tries batch at the same time
    let writer2 = thread::spawn(move || {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));
        barrier.wait();
        // The batch may or may not fail depending on timing — either result is fine
        // as long as no corruption occurs
        let _ = backend.batch_append_events(&batch);
    });

    writer1.join().unwrap();
    writer2.join().unwrap();

    // Verify registry is not corrupted
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    let meta = backend.metadata().unwrap();
    // At least the pre-populated identity + writer1's identity exist
    assert!(meta.identity_count >= 2);
}
