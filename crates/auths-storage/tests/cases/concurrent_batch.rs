use std::sync::{Arc, Barrier};
use std::thread;

use auths_core::crypto::said::compute_next_commitment;
use auths_id::keri::event::{Event, IcpEvent, KeriSequence};
use auths_id::keri::finalize_icp_event;
use auths_id::keri::types::{Prefix, Said};
use auths_id::ports::registry::{RegistryBackend, RegistryError};
use auths_keri::{CesrKey, Threshold, VersionString};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;

use super::mock_ed25519_keypairs::mock_inception_event;

/// Deterministic inception event from a seed byte — no OS entropy needed.
fn seeded_inception_event(seed: u8) -> Event {
    let current_seed = [seed; 32];
    let next_seed = [seed.wrapping_add(128); 32];

    let keypair = Ed25519KeyPair::from_seed_unchecked(&current_seed).unwrap();
    let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

    let next_keypair = Ed25519KeyPair::from_seed_unchecked(&next_seed).unwrap();
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
    };

    let finalized = finalize_icp_event(icp).expect("fixture event must finalize");
    let _ = keypair; // signature attached at KEL-append boundary, not here.
    Event::Icp(finalized)
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

    let e1 = mock_inception_event(0);
    let e2 = mock_inception_event(1);
    let e3 = mock_inception_event(2);
    let p1 = e1.prefix().clone();
    let p2 = e2.prefix().clone();
    let p3 = e3.prefix().clone();

    backend
        .batch_append_events(&[(p1.clone(), e1), (p2.clone(), e2), (p3.clone(), e3)])
        .unwrap();

    assert_eq!(backend.metadata().unwrap().identity_count, 3);

    let e4 = mock_inception_event(3);
    let e5 = mock_inception_event(4);
    let p4 = e4.prefix().clone();
    let p5 = e5.prefix().clone();

    let backend2 =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend2
        .batch_append_events(&[(p4.clone(), e4), (p5.clone(), e5)])
        .unwrap();

    assert_eq!(backend2.metadata().unwrap().identity_count, 5);

    for prefix in [&p1, &p2, &p3, &p4, &p5] {
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
        .map(|t| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);

            // Deterministic seeds based on thread index — no entropy needed
            let base = (t * identities_per_batch) as u8 + 100;
            let mut batch = Vec::with_capacity(identities_per_batch);
            for i in 0..identities_per_batch {
                let event = seeded_inception_event(base + i as u8);
                let prefix = event.prefix().clone();
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

    let mut batch = Vec::with_capacity(5);
    for i in 0..5u8 {
        let event = seeded_inception_event(200 + i);
        let prefix = event.prefix().clone();
        batch.push((prefix, event));
    }

    let mut singles = Vec::with_capacity(5);
    for i in 0..5u8 {
        let event = seeded_inception_event(210 + i);
        let prefix = event.prefix().clone();
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

    let icp = mock_inception_event(5);
    let prefix = icp.prefix().clone();
    backend.append_event(&prefix, &icp).unwrap();

    let mut batch = Vec::with_capacity(3);
    for i in 0..3u8 {
        let event = seeded_inception_event(220 + i);
        let p = event.prefix().clone();
        batch.push((p, event));
    }

    let path = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = Arc::clone(&barrier);

    let path2 = path.clone();
    let writer1 = thread::spawn(move || -> Result<(), RegistryError> {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path2));
        let event = seeded_inception_event(230);
        let prefix = event.prefix().clone();
        barrier2.wait();
        backend.append_event(&prefix, &event)
    });

    let writer2 = thread::spawn(move || -> Result<(), RegistryError> {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));
        barrier.wait();
        backend.batch_append_events(&batch)
    });

    let r1 = writer1.join().unwrap();
    let r2 = writer2.join().unwrap();

    // At least one must succeed; the loser gets ConcurrentModification
    assert!(r1.is_ok() || r2.is_ok(), "at least one writer must succeed");
    for r in [&r1, &r2] {
        if let Err(e) = r {
            assert!(
                matches!(e, RegistryError::ConcurrentModification(_)),
                "expected ConcurrentModification, got: {e:?}"
            );
        }
    }

    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    let meta = backend.metadata().unwrap();
    assert!(meta.identity_count >= 2);
}
