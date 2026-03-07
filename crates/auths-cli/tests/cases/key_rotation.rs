use tempfile::tempdir;

use auths_id::identity::events::KeyRotationEvent;
use auths_id::storage::keri::KeriGitStorage;
use auths_verifier::keri::Prefix;

use chrono::Utc;
use sha2::{Digest, Sha256};

#[test]
fn test_key_rotation_event_chain_integrity() {
    // Setup: create temp directory for Git repo
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = temp_dir.path();

    // Initialize a bare Git repo
    git2::Repository::init(repo_path).expect("Failed to init Git repo");

    // Create KERI storage
    let keri_storage = KeriGitStorage::new(repo_path);
    let did_prefix = "TestRotation123";
    let prefix = Prefix::new_unchecked(did_prefix.to_string());

    // 1. Create inception event (sequence 0)
    let inception_event = KeyRotationEvent::new(
        0,
        String::new(), // No previous hash for inception
        vec![0u8; 32], // Old key (placeholder for inception)
        vec![1u8; 32], // Initial key
        Utc::now(),
        vec![2u8; 64], // Signature
    );

    let commit1 = keri_storage
        .append_rotation_event(&prefix, &inception_event, chrono::Utc::now())
        .expect("Failed to append inception event");

    // Compute hash for next event
    let commit1_hash = {
        let mut hasher = Sha256::new();
        hasher.update(commit1.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    };

    // 2. Create rotation event (sequence 1)
    let rotation_event = KeyRotationEvent::new(
        1,
        commit1_hash.clone(),
        vec![1u8; 32], // Old key (was initial key)
        vec![3u8; 32], // New key
        Utc::now(),
        vec![4u8; 64], // Signature by old key
    );

    let _commit2 = keri_storage
        .append_rotation_event(&prefix, &rotation_event, chrono::Utc::now())
        .expect("Failed to append rotation event");

    // 3. Verify KEL contains both events
    let kel_history = keri_storage
        .read_kel_history(&prefix)
        .expect("Failed to read KEL history");

    assert_eq!(
        kel_history.len(),
        2,
        "KEL should contain 2 events (inception + rotation)"
    );

    // 4. Verify events are in correct order (oldest first)
    let event1: KeyRotationEvent =
        serde_json::from_slice(&kel_history[0]).expect("Failed to parse event 1");
    let event2: KeyRotationEvent =
        serde_json::from_slice(&kel_history[1]).expect("Failed to parse event 2");

    assert_eq!(
        event1.sequence, 0,
        "First event should be inception (seq 0)"
    );
    assert_eq!(
        event2.sequence, 1,
        "Second event should be rotation (seq 1)"
    );
    assert_eq!(
        event2.previous_hash, commit1_hash,
        "Rotation event should reference inception commit"
    );

    // 5. Verify chain linkage - old key in rotation matches new key in inception
    assert_eq!(
        event2.old_public_key, event1.new_public_key,
        "Rotation old_key should match inception new_key"
    );
}

#[test]
fn test_key_rotation_chain_integrity_rejection() {
    // Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = temp_dir.path();
    git2::Repository::init(repo_path).expect("Failed to init Git repo");

    let keri_storage = KeriGitStorage::new(repo_path);
    let did_prefix = "TestChainReject";
    let prefix = Prefix::new_unchecked(did_prefix.to_string());

    // 1. Create inception event
    let inception_event = KeyRotationEvent::new(
        0,
        String::new(),
        vec![0u8; 32],
        vec![1u8; 32],
        Utc::now(),
        vec![2u8; 64],
    );

    keri_storage
        .append_rotation_event(&prefix, &inception_event, chrono::Utc::now())
        .expect("Failed to append inception");

    // 2. Try to create rotation with WRONG previous_hash
    let bad_rotation = KeyRotationEvent::new(
        1,
        "wrong_hash_value".to_string(), // Invalid hash
        vec![1u8; 32],
        vec![3u8; 32],
        Utc::now(),
        vec![4u8; 64],
    );

    let result = keri_storage.append_rotation_event(&prefix, &bad_rotation, chrono::Utc::now());

    // 3. Verify the invalid rotation is rejected
    assert!(
        result.is_err(),
        "Should reject rotation with invalid previous_hash"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Chain integrity violation"),
        "Error should mention chain integrity"
    );

    // 4. Verify KEL only has 1 event (the valid inception)
    let kel_history = keri_storage
        .read_kel_history(&prefix)
        .expect("Failed to read KEL");
    assert_eq!(kel_history.len(), 1, "KEL should only have inception event");
}

#[test]
fn test_multiple_rotations_maintain_history() {
    // Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = temp_dir.path();
    git2::Repository::init(repo_path).expect("Failed to init Git repo");

    let keri_storage = KeriGitStorage::new(repo_path);
    let did_prefix = "TestMultiRotate";
    let prefix = Prefix::new_unchecked(did_prefix.to_string());

    // Create a chain of 5 events (1 inception + 4 rotations)
    let mut previous_hash = String::new();
    let mut previous_new_key = vec![0u8; 32];

    for seq in 0..5 {
        let old_key = previous_new_key.clone();
        let new_key = vec![(seq + 1) as u8; 32];

        let event = KeyRotationEvent::new(
            seq,
            previous_hash.clone(),
            old_key,
            new_key.clone(),
            Utc::now(),
            vec![(seq + 100) as u8; 64],
        );

        let commit_oid = keri_storage
            .append_rotation_event(&prefix, &event, chrono::Utc::now())
            .unwrap_or_else(|_| panic!("Failed to append event {}", seq));

        // Update for next iteration
        let mut hasher = Sha256::new();
        hasher.update(commit_oid.to_string().as_bytes());
        previous_hash = format!("{:x}", hasher.finalize());
        previous_new_key = new_key;
    }

    // Verify all 5 events are in KEL
    let kel_history = keri_storage
        .read_kel_history(&prefix)
        .expect("Failed to read KEL");

    assert_eq!(kel_history.len(), 5, "KEL should contain 5 events");

    // Verify sequence numbers are correct
    for (i, event_bytes) in kel_history.iter().enumerate() {
        let event: KeyRotationEvent =
            serde_json::from_slice(event_bytes).expect("Failed to parse event");
        assert_eq!(
            event.sequence, i as u64,
            "Event {} should have sequence {}",
            i, i
        );
    }
}
