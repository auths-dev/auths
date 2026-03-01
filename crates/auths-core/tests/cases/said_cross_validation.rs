use auths_core::crypto::{compute_next_commitment, compute_said, verify_commitment};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Inline copy of the verifier's `compute_said()` logic.
/// SYNC: must match auths-verifier/src/keri.rs `fn compute_said()`
fn verifier_compute_said(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}

/// Inline copy of the verifier's `compute_commitment()` logic.
/// SYNC: must match auths-verifier/src/keri.rs `fn compute_commitment()`
fn verifier_compute_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}

#[test]
fn compute_said_matches_verifier_for_random_inputs() {
    // Test 1000 random-ish inputs of varying lengths.
    for i in 0u32..1000 {
        let input: Vec<u8> = {
            let seed = i.to_le_bytes();
            let hash = blake3::hash(&seed);
            // Use the hash bytes as our "random" input, varying length
            let len = (i as usize % 128) + 1;
            hash.as_bytes()[..len.min(32)].to_vec()
        };

        let core_said = compute_said(&input).to_string();
        let verifier_said = verifier_compute_said(&input);

        assert_eq!(
            core_said,
            verifier_said,
            "SAID mismatch at iteration {i} for input of length {}",
            input.len()
        );
    }
}

#[test]
fn compute_commitment_matches_verifier_for_random_keys() {
    for i in 0u32..1000 {
        // Generate a deterministic 32-byte "public key" from each iteration.
        let key = blake3::hash(&i.to_le_bytes());
        let key_bytes = key.as_bytes();

        let core_commitment = compute_next_commitment(key_bytes);
        let verifier_commitment = verifier_compute_commitment(key_bytes);

        assert_eq!(
            core_commitment, verifier_commitment,
            "Commitment mismatch at iteration {i}"
        );
    }
}

#[test]
fn verify_commitment_round_trips_with_verifier_commitment() {
    for i in 0u32..100 {
        let key = blake3::hash(&i.to_le_bytes());
        let key_bytes = key.as_bytes();

        // Compute commitment via verifier logic
        let commitment = verifier_compute_commitment(key_bytes);

        // Verify via auths-core's verify_commitment
        assert!(
            verify_commitment(key_bytes, &commitment),
            "verify_commitment failed for verifier-generated commitment at iteration {i}"
        );
    }
}

#[test]
fn said_known_vector() {
    // A fixed known-input test to catch algorithm changes.
    let input = b"{\"t\":\"icp\",\"s\":\"0\"}";
    let core = compute_said(input).to_string();
    let verifier = verifier_compute_said(input);
    assert_eq!(core, verifier);
    assert!(core.starts_with('E'));
    assert_eq!(core.len(), 44); // 'E' + 43 chars of base64url
}
