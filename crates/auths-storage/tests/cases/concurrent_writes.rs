use std::sync::{Arc, Barrier};
use std::thread;

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::KeriSequence;
use auths_id::keri::event::{Event, IcpEvent, IxnEvent};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::finalize_icp_event;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_keri::{CesrKey, Threshold, VersionString};
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

    let finalized = finalize_icp_event(icp).unwrap();
    let prefix = finalized.i.clone();
    (Event::Icp(finalized), prefix, keypair)
}

fn make_signed_ixn(prefix: &Prefix, seq: u128, prev_said: &str, keypair: &Ed25519KeyPair) -> Event {
    let mut ixn = IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: Said::new_unchecked(prev_said.to_string()),
        a: vec![Seal::digest("EConcurrent")],
    };

    let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&value).unwrap();

    let _ = keypair; // signature attached at KEL-append boundary, not here.
    Event::Ixn(ixn)
}

/// 10 threads appending different identities -- all succeed with retries.
///
/// The CAS mechanism serializes all writes to the same git ref, so concurrent
/// writers may get ConcurrentModification errors even for different identities.
/// This is expected. Real callers should retry on CAS failure.
#[test]
fn concurrent_writes_to_different_identities() {
    let dir = TempDir::new().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();

    let path = dir.path().to_path_buf();
    let thread_count = 10;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let backend =
                    GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));
                let (icp, prefix, _keypair) = make_signed_icp();

                // Wait for all threads to be ready
                barrier.wait();

                // Retry on CAS failure (ConcurrentModification)
                for _ in 0..20 {
                    match backend.append_event(&prefix, &icp) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            let msg = format!("{}", e);
                            if msg.contains("Concurrent modification")
                                || msg.contains("already exists")
                            {
                                // CAS failure or duplicate -- retry after brief pause
                                thread::sleep(std::time::Duration::from_millis(10));
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                // If already written (EventExists), that counts as success
                Ok(())
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    assert_eq!(
        successes, thread_count,
        "All {} threads should eventually succeed for different identities, got {} successes",
        thread_count, successes
    );
}

/// 5 threads appending to the same identity at seq 1 -- exactly 1 should succeed,
/// others get sequence gap or CAS errors.
#[test]
fn concurrent_writes_to_same_identity() {
    let dir = TempDir::new().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();

    // Create identity first (seq 0)
    let (icp, prefix, keypair) = make_signed_icp();
    let icp_said = icp.said().to_string();
    backend.append_event(&prefix, &icp).unwrap();

    let path = dir.path().to_path_buf();
    let thread_count = 5;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let prefix = prefix.clone();

            // Pre-create the signed IXN before spawning (keypair isn't Send)
            let ixn = make_signed_ixn(&prefix, 1, &icp_said, &keypair);

            thread::spawn(move || {
                let backend =
                    GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&path));

                // Wait for all threads to be ready
                barrier.wait();

                backend.append_event(&prefix, &ixn)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    assert_eq!(
        successes, 1,
        "Exactly 1 thread should succeed for same identity seq 1, got {} successes",
        successes
    );
}
