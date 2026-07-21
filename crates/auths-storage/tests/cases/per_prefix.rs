//! Per-prefix KEL store: independent refs, full-ruleset appends, and the
//! no-global-lock concurrency the witness write path is built on.

use std::sync::{Arc, Barrier};
use std::thread;

use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::KeriSequence;
use auths_id::keri::event::{Event, IcpEvent, IxnEvent};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::validate::finalize_icp_event;
use auths_keri::{CesrKey, IndexedSignature, Threshold, VersionString, serialize_attachment};
use auths_storage::git::{KelAppendOutcome, PerPrefixKelStore, kel_ref};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;

fn make_signed_icp() -> (Event, Prefix, Ed25519KeyPair, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key_encoded = auths_keri::KeriPublicKey::ed25519(keypair.public_key().as_ref())
        .unwrap()
        .to_qb64()
        .unwrap();
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let next_commitment = compute_next_commitment(
        &auths_keri::KeriPublicKey::ed25519(next_keypair.public_key().as_ref()).unwrap(),
    );

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
    let event = Event::Icp(finalized);
    let attachment = sign_event(&event, &keypair);
    (event, prefix, keypair, attachment)
}

fn make_signed_ixn(
    prefix: &Prefix,
    seq: u128,
    prev: &Said,
    seal: &str,
    keypair: &Ed25519KeyPair,
) -> (Event, Vec<u8>) {
    let mut ixn = IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: prev.clone(),
        a: vec![Seal::digest(seal)],
    };
    let value = serde_json::to_value(Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&value).unwrap();
    let event = Event::Ixn(ixn);
    let attachment = sign_event(&event, keypair);
    (event, attachment)
}

fn sign_event(event: &Event, keypair: &Ed25519KeyPair) -> Vec<u8> {
    let canonical = auths_keri::serialize_for_signing(event).unwrap();
    let sig = keypair.sign(&canonical);
    serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig.as_ref().to_vec(),
    }])
    .unwrap()
}

fn store_in(dir: &TempDir) -> PerPrefixKelStore {
    git2::Repository::init(dir.path()).unwrap();
    PerPrefixKelStore::open(dir.path())
}

#[test]
fn append_read_and_resolve_roundtrip() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (icp, prefix, keypair, icp_att) = make_signed_icp();

    assert_eq!(
        store.append_signed_event(&prefix, &icp, &icp_att).unwrap(),
        KelAppendOutcome::Appended
    );
    let (ixn, ixn_att) = make_signed_ixn(&prefix, 1, icp.said(), "ESealOne", &keypair);
    assert_eq!(
        store.append_signed_event(&prefix, &ixn, &ixn_att).unwrap(),
        KelAppendOutcome::Appended
    );

    let tip = store.get_tip(&prefix).unwrap();
    assert_eq!(tip.sequence, 1);
    assert_eq!(&tip.said, ixn.said());

    let state = store.get_key_state(&prefix).unwrap();
    assert_eq!(state.sequence, 1);
    assert_eq!(state.last_event_said, *ixn.said());

    let stored = store.get_event(&prefix, 0).unwrap();
    assert_eq!(stored.said(), icp.said());
    assert_eq!(store.get_attachment(&prefix, 1).unwrap().unwrap(), ixn_att);

    let mut seen = Vec::new();
    store
        .visit_events(&prefix, 0, &mut |e| {
            seen.push(e.said().clone());
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(seen, vec![icp.said().clone(), ixn.said().clone()]);

    // The ref layout is per prefix, sharded, under the served namespace.
    let ref_name = kel_ref(&prefix).unwrap();
    assert!(ref_name.starts_with("refs/auths/kel/"));
    assert!(ref_name.ends_with(prefix.as_str()));
    let repo = git2::Repository::open(dir.path()).unwrap();
    assert!(repo.find_reference(&ref_name).is_ok());
}

#[test]
fn resubmission_is_idempotent_and_conflict_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (icp, prefix, keypair, icp_att) = make_signed_icp();
    store.append_signed_event(&prefix, &icp, &icp_att).unwrap();
    let (ixn, ixn_att) = make_signed_ixn(&prefix, 1, icp.said(), "ESealOne", &keypair);
    store.append_signed_event(&prefix, &ixn, &ixn_att).unwrap();

    // Identical event again: stored no-op.
    assert_eq!(
        store.append_signed_event(&prefix, &ixn, &ixn_att).unwrap(),
        KelAppendOutcome::AlreadyStored
    );

    // A different event at the occupied sequence: refused, never a fork.
    let (conflicting, conflict_att) =
        make_signed_ixn(&prefix, 1, icp.said(), "ESealConflicting", &keypair);
    let err = store
        .append_signed_event(&prefix, &conflicting, &conflict_att)
        .unwrap_err();
    assert!(
        matches!(
            err,
            auths_id::ports::registry::RegistryError::EventExists { .. }
        ),
        "conflict must be EventExists, got: {err:?}"
    );

    // The chain is untouched.
    assert_eq!(store.get_tip(&prefix).unwrap().said, *ixn.said());
}

#[test]
fn unverifiable_attachment_signature_is_rejected() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (icp, prefix, _keypair, _good_att) = make_signed_icp();

    // Sign with a DIFFERENT key: the attachment parses but cannot verify
    // against the event's declared key list.
    let rng = SystemRandom::new();
    let stranger =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let forged = sign_event(&icp, &stranger);

    let err = store
        .append_signed_event(&prefix, &icp, &forged)
        .unwrap_err();
    assert!(
        matches!(
            err,
            auths_id::ports::registry::RegistryError::InvalidEvent { .. }
        ),
        "forged signature must be InvalidEvent, got: {err:?}"
    );
    assert!(store.get_tip(&prefix).is_err(), "nothing may be stored");
}

/// The design's headline property: distinct identities never contend — no
/// retry loops, no ConcurrentModification, unlike the packed single-ref
/// backend whose equivalent test must retry on CAS failure.
#[test]
fn concurrent_distinct_identities_append_without_retries() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let members: Vec<(Event, Prefix, Vec<u8>)> = (0..10)
        .map(|_| {
            let (icp, prefix, _kp, att) = make_signed_icp();
            (icp, prefix, att)
        })
        .collect();

    let barrier = Arc::new(Barrier::new(members.len()));
    let handles: Vec<_> = members
        .into_iter()
        .map(|(icp, prefix, att)| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store
                    .append_signed_event(&prefix, &icp, &att)
                    .map(|outcome| (prefix, outcome))
            })
        })
        .collect();

    let mut prefixes = Vec::new();
    for handle in handles {
        let (prefix, outcome) = handle
            .join()
            .unwrap()
            .expect("concurrent distinct appends must succeed FIRST TRY");
        assert_eq!(outcome, KelAppendOutcome::Appended);
        prefixes.push(prefix);
    }

    let mut held = store.list_prefixes().unwrap();
    held.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    prefixes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(held, prefixes);
}
