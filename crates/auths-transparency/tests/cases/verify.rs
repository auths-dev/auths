#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use auths_transparency::bundle::{
    CheckpointStatus, InclusionStatus, OfflineBundle, SignatureStatus, WitnessStatus,
};
use auths_transparency::checkpoint::{Checkpoint, SignedCheckpoint, WitnessCosignature};
use auths_transparency::entry::{Entry, EntryBody, EntryContent, EntryType};
use auths_transparency::merkle::{compute_root, hash_leaf};
use auths_transparency::proof::InclusionProof;
use auths_transparency::types::{LogOrigin, MerkleHash};
use auths_transparency::{TrustRoot, TrustRootWitness, verify_bundle};
use auths_verifier::{CanonicalDid, DeviceDID, Ed25519PublicKey, Ed25519Signature};
use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixed_ts() -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339("2025-06-15T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn fixed_now() -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

/// End-to-end: generate keys, sign entry, build tree, sign checkpoint, verify bundle.
#[test]
fn verify_bundle_end_to_end_single_entry() {
    let log_kp = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
    let log_pk: [u8; 32] = log_kp.public_key().as_ref().try_into().unwrap();

    let actor_kp = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
    let actor_pk: [u8; 32] = actor_kp.public_key().as_ref().try_into().unwrap();
    let actor_did = auths_crypto::ed25519_pubkey_to_did_key(&actor_pk);

    // Build entry
    let content = EntryContent {
        entry_type: EntryType::DeviceBind,
        body: EntryBody::DeviceBind {
            device_did: DeviceDID::new_unchecked(&actor_did),
            public_key: Ed25519PublicKey::from_bytes(actor_pk),
        },
        actor_did: CanonicalDid::new_unchecked(&actor_did),
    };
    let canonical = content.canonicalize().unwrap();
    let sig_bytes = actor_kp.sign(&canonical);
    let actor_sig = Ed25519Signature::try_from_slice(sig_bytes.as_ref()).unwrap();

    let entry = Entry {
        sequence: 0,
        timestamp: fixed_ts(),
        content,
        actor_sig,
    };

    // Build Merkle tree (single leaf)
    let leaf_data = entry.leaf_data().unwrap();
    let leaf_hash = hash_leaf(&leaf_data);
    let root = compute_root(&[leaf_hash]);

    // Sign checkpoint
    let checkpoint = Checkpoint {
        origin: LogOrigin::new("test.dev/log").unwrap(),
        size: 1,
        root,
        timestamp: fixed_ts(),
    };
    let note_body = checkpoint.to_note_body();
    let log_sig =
        Ed25519Signature::try_from_slice(log_kp.sign(note_body.as_bytes()).as_ref()).unwrap();

    let bundle = OfflineBundle {
        entry,
        inclusion_proof: InclusionProof {
            index: 0,
            size: 1,
            root,
            hashes: vec![],
        },
        signed_checkpoint: SignedCheckpoint {
            checkpoint,
            log_signature: log_sig,
            log_public_key: Ed25519PublicKey::from_bytes(log_pk),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        },
        delegation_chain: vec![],
    };

    let trust_root = TrustRoot {
        log_public_key: Ed25519PublicKey::from_bytes(log_pk),
        log_origin: LogOrigin::new("test.dev/log").unwrap(),
        witnesses: vec![],
        signature_algorithm: Default::default(),
    };

    let report = verify_bundle(&bundle, &trust_root, fixed_now());
    assert_eq!(report.signature, SignatureStatus::Verified);
    assert_eq!(report.inclusion, InclusionStatus::Verified);
    assert_eq!(report.checkpoint, CheckpointStatus::Verified);
    assert!(report.is_valid());
}

/// End-to-end with multiple entries and inclusion proof.
#[test]
fn verify_bundle_multi_leaf_tree() {
    let log_kp = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
    let log_pk: [u8; 32] = log_kp.public_key().as_ref().try_into().unwrap();

    let actor_kp = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
    let actor_pk: [u8; 32] = actor_kp.public_key().as_ref().try_into().unwrap();
    let actor_did = auths_crypto::ed25519_pubkey_to_did_key(&actor_pk);

    // Build 4 entries for a proper inclusion proof
    let mut entries = Vec::new();
    for seq in 0..4u128 {
        let content = EntryContent {
            entry_type: EntryType::DeviceBind,
            body: EntryBody::DeviceBind {
                device_did: DeviceDID::new_unchecked(&actor_did),
                public_key: Ed25519PublicKey::from_bytes(actor_pk),
            },
            actor_did: CanonicalDid::new_unchecked(&actor_did),
        };
        let canonical = content.canonicalize().unwrap();
        let sig_bytes = actor_kp.sign(&canonical);
        let actor_sig = Ed25519Signature::try_from_slice(sig_bytes.as_ref()).unwrap();

        entries.push(Entry {
            sequence: seq,
            timestamp: fixed_ts(),
            content,
            actor_sig,
        });
    }

    let leaf_hashes: Vec<MerkleHash> = entries
        .iter()
        .map(|e| hash_leaf(&e.leaf_data().unwrap()))
        .collect();
    let root = compute_root(&leaf_hashes);

    // Build inclusion proof for entry 2 (index 2 in 4-leaf tree)
    // Siblings: leaf[3], then hash(leaf[0], leaf[1])
    let h01 = auths_transparency::merkle::hash_children(&leaf_hashes[0], &leaf_hashes[1]);
    let proof_hashes = vec![leaf_hashes[3], h01];

    let checkpoint = Checkpoint {
        origin: LogOrigin::new("test.dev/log").unwrap(),
        size: 4,
        root,
        timestamp: fixed_ts(),
    };
    let note_body = checkpoint.to_note_body();
    let log_sig =
        Ed25519Signature::try_from_slice(log_kp.sign(note_body.as_bytes()).as_ref()).unwrap();

    let bundle = OfflineBundle {
        entry: entries[2].clone(),
        inclusion_proof: InclusionProof {
            index: 2,
            size: 4,
            root,
            hashes: proof_hashes,
        },
        signed_checkpoint: SignedCheckpoint {
            checkpoint,
            log_signature: log_sig,
            log_public_key: Ed25519PublicKey::from_bytes(log_pk),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        },
        delegation_chain: vec![],
    };

    let trust_root = TrustRoot {
        log_public_key: Ed25519PublicKey::from_bytes(log_pk),
        log_origin: LogOrigin::new("test.dev/log").unwrap(),
        witnesses: vec![],
        signature_algorithm: Default::default(),
    };

    let report = verify_bundle(&bundle, &trust_root, fixed_now());
    assert_eq!(report.signature, SignatureStatus::Verified);
    assert_eq!(report.inclusion, InclusionStatus::Verified);
    assert_eq!(report.checkpoint, CheckpointStatus::Verified);
    assert!(report.is_valid());
}

/// Witness quorum verification end-to-end.
#[test]
fn verify_bundle_with_witnesses() {
    let log_kp = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
    let log_pk: [u8; 32] = log_kp.public_key().as_ref().try_into().unwrap();

    let actor_kp = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
    let actor_pk: [u8; 32] = actor_kp.public_key().as_ref().try_into().unwrap();
    let actor_did = auths_crypto::ed25519_pubkey_to_did_key(&actor_pk);

    let w1_kp = Ed25519KeyPair::from_seed_unchecked(&[10u8; 32]).unwrap();
    let w1_pk: [u8; 32] = w1_kp.public_key().as_ref().try_into().unwrap();

    let content = EntryContent {
        entry_type: EntryType::DeviceBind,
        body: EntryBody::DeviceBind {
            device_did: DeviceDID::new_unchecked(&actor_did),
            public_key: Ed25519PublicKey::from_bytes(actor_pk),
        },
        actor_did: CanonicalDid::new_unchecked(&actor_did),
    };
    let canonical = content.canonicalize().unwrap();
    let sig_bytes = actor_kp.sign(&canonical);
    let actor_sig = Ed25519Signature::try_from_slice(sig_bytes.as_ref()).unwrap();

    let entry = Entry {
        sequence: 0,
        timestamp: fixed_ts(),
        content,
        actor_sig,
    };

    let leaf_hash = hash_leaf(&entry.leaf_data().unwrap());
    let root = compute_root(&[leaf_hash]);

    let checkpoint = Checkpoint {
        origin: LogOrigin::new("test.dev/log").unwrap(),
        size: 1,
        root,
        timestamp: fixed_ts(),
    };
    let note_body = checkpoint.to_note_body();
    let log_sig =
        Ed25519Signature::try_from_slice(log_kp.sign(note_body.as_bytes()).as_ref()).unwrap();
    let w1_sig =
        Ed25519Signature::try_from_slice(w1_kp.sign(note_body.as_bytes()).as_ref()).unwrap();

    let bundle = OfflineBundle {
        entry,
        inclusion_proof: InclusionProof {
            index: 0,
            size: 1,
            root,
            hashes: vec![],
        },
        signed_checkpoint: SignedCheckpoint {
            checkpoint,
            log_signature: log_sig,
            log_public_key: Ed25519PublicKey::from_bytes(log_pk),
            witnesses: vec![WitnessCosignature {
                witness_name: "w1".into(),
                witness_public_key: Ed25519PublicKey::from_bytes(w1_pk),
                signature: w1_sig,
                timestamp: fixed_ts(),
            }],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        },
        delegation_chain: vec![],
    };

    let trust_root = TrustRoot {
        log_public_key: Ed25519PublicKey::from_bytes(log_pk),
        log_origin: LogOrigin::new("test.dev/log").unwrap(),
        witnesses: vec![TrustRootWitness {
            witness_did: DeviceDID::new_unchecked(auths_crypto::ed25519_pubkey_to_did_key(&w1_pk)),
            name: "w1".into(),
            public_key: Ed25519PublicKey::from_bytes(w1_pk),
        }],
        signature_algorithm: Default::default(),
    };

    let report = verify_bundle(&bundle, &trust_root, fixed_now());
    assert!(matches!(
        report.witnesses,
        WitnessStatus::Quorum {
            verified: 1,
            required: 1
        }
    ));
    assert!(report.is_valid());
}
