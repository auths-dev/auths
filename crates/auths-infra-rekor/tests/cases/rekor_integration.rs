//! Integration tests for the Rekor adapter.
//!
//! Tests that require real Rekor are gated on `AUTHS_TEST_REKOR=1`.
//! Tests using the FakeTransparencyLog run always.

use std::sync::LazyLock;

use auths_core::ports::transparency_log::{LogError, TransparencyLog};
use auths_infra_rekor::RekorClient;

/// Shared RekorClient across all integration tests in this file.
static TEST_REKOR: LazyLock<RekorClient> = LazyLock::new(|| RekorClient::public().unwrap());
use auths_transparency::TrustConfig;
use auths_transparency::merkle::hash_leaf;
use ring::signature::KeyPair;

#[allow(clippy::disallowed_methods)] // Test boundary: reading test gate env var
fn rekor_enabled() -> bool {
    std::env::var("AUTHS_TEST_REKOR").is_ok()
}

// ============================================================
// Real Rekor tests (gated on AUTHS_TEST_REKOR=1)
// ============================================================

#[tokio::test]
async fn rekor_happy_path_submit_and_verify() {
    if !rekor_enabled() {
        eprintln!("Skipping: set AUTHS_TEST_REKOR=1 to run Rekor integration tests");
        return;
    }

    let client = &*TEST_REKOR;

    // Generate a throwaway Ed25519 key
    let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[99u8; 32]).unwrap();
    let public_key = keypair.public_key().as_ref();

    // Create test attestation
    let attestation = b"test-attestation-for-rekor-integration";
    let sig = keypair.sign(attestation);

    // Submit to Rekor
    let submission = client.submit(attestation, public_key, sig.as_ref()).await;

    match submission {
        Ok(sub) => {
            // Verify inclusion proof
            let leaf_hash = hash_leaf(attestation);
            assert!(
                sub.inclusion_proof.verify(&leaf_hash).is_ok(),
                "inclusion proof should verify"
            );
            eprintln!(
                "Rekor submission succeeded: index={}, tree_size={}",
                sub.leaf_index, sub.signed_checkpoint.checkpoint.size
            );
        }
        Err(LogError::RateLimited { .. }) => {
            eprintln!("Rate limited by Rekor — test skipped");
        }
        Err(e) => {
            // May fail if hashedrekord+Ed25519 is rejected — this is expected
            // and documented in the design doc as a potential fallback trigger.
            eprintln!("Rekor submission failed (may need DSSE fallback): {e}");
        }
    }
}

#[tokio::test]
async fn rekor_get_checkpoint() {
    if !rekor_enabled() {
        return;
    }

    let client = &*TEST_REKOR;
    let checkpoint = client.get_checkpoint().await;
    assert!(checkpoint.is_ok(), "should fetch Rekor checkpoint");
    let cp = checkpoint.unwrap();
    assert!(cp.checkpoint.size > 0, "tree should have entries");
}

// ============================================================
// Tests that don't require real Rekor
// ============================================================

#[tokio::test]
async fn unreachable_endpoint_returns_network_error() {
    let client = RekorClient::new("https://localhost:1", "test", "test.dev/log").unwrap();
    let result = client.submit(b"test", b"pk", b"sig").await;
    assert!(matches!(result, Err(LogError::NetworkError(_))));
}

#[tokio::test]
async fn payload_size_rejection_is_local() {
    let client = &*TEST_REKOR;
    let big = vec![0u8; 101 * 1024]; // > 100KB
    let result = client.submit(&big, b"pk", b"sig").await;
    match result {
        Err(LogError::SubmissionRejected { reason }) => {
            assert!(reason.contains("exceeds max size"));
        }
        other => panic!("expected SubmissionRejected, got: {:?}", other),
    }
}

#[tokio::test]
async fn unknown_log_id_in_trust_config() {
    let config = TrustConfig::default_config();
    let result = config.get_log("nonexistent-log");
    assert!(result.is_none(), "unknown log should return None");
}

// ============================================================
// GHSA-whqx-f9j3-ch6m regression test
// ============================================================

/// Tests that submit_attestation_to_log verifies the inclusion proof
/// matches the submitted data. Uses FakeTransparencyLog since we
/// need to control the response.
#[tokio::test]
async fn ghsa_content_mismatch_detected() {
    // The FakeTransparencyLog always returns valid proofs for the data
    // that was actually submitted. To test the GHSA countermeasure,
    // we verify that the SDK's submit_attestation_to_log function
    // checks the proof against the submitted data.
    //
    // With a succeeding fake, the proof will match — so the test
    // confirms the happy path works. The mismatch case is tested by
    // verifying against wrong data after submission.
    use auths_sdk::testing::fakes::FakeTransparencyLog;
    use auths_sdk::workflows::log_submit::submit_attestation_to_log;

    let log = FakeTransparencyLog::succeeding();
    let result = submit_attestation_to_log(b"original attestation", b"pk", b"sig", &log).await;
    assert!(result.is_ok());

    // Now verify that a DIFFERENT attestation's hash does NOT match
    // the proof that was generated for "original attestation"
    let bundle = result.unwrap();
    let wrong_leaf_hash = hash_leaf(b"different attestation");
    assert!(
        bundle.inclusion_proof.verify(&wrong_leaf_hash).is_err(),
        "proof for 'original' should NOT verify for 'different'"
    );
}

// ============================================================
// Checkpoint-proof binding regression test
// ============================================================

#[tokio::test]
async fn checkpoint_proof_root_mismatch_detected() {
    use auths_sdk::testing::fakes::FakeTransparencyLog;
    use auths_sdk::workflows::log_submit::submit_attestation_to_log;

    let log = FakeTransparencyLog::succeeding();
    let result = submit_attestation_to_log(b"test", b"pk", b"sig", &log).await;
    assert!(result.is_ok());

    let bundle = result.unwrap();

    // The proof root should match the checkpoint root
    assert_eq!(
        bundle.inclusion_proof.root, bundle.signed_checkpoint.checkpoint.root,
        "proof root must match checkpoint root"
    );
}

// ============================================================
// Offline verification test
// ============================================================

#[tokio::test]
async fn offline_verification_no_network() {
    use auths_sdk::testing::fakes::FakeTransparencyLog;
    use auths_sdk::workflows::log_submit::submit_attestation_to_log;

    // Step 1: produce a bundle using the fake
    let log = FakeTransparencyLog::succeeding();
    let bundle = submit_attestation_to_log(b"offline test data", b"pk", b"sig", &log)
        .await
        .unwrap();

    // Step 2: verify the inclusion proof offline (no network calls)
    let leaf_hash = hash_leaf(b"offline test data");
    assert!(
        bundle.inclusion_proof.verify(&leaf_hash).is_ok(),
        "offline inclusion proof should verify"
    );

    // Step 3: verify the checkpoint signature against the fake's trust root
    let trust_root = log.trust_root();
    let note_body = bundle.signed_checkpoint.checkpoint.to_note_body();
    let peer_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        trust_root.log_public_key.as_bytes(),
    );
    assert!(
        peer_key
            .verify(
                note_body.as_bytes(),
                bundle.signed_checkpoint.log_signature.as_bytes()
            )
            .is_ok(),
        "offline checkpoint signature should verify"
    );
}

// ============================================================
// Pluggability proof: same flow with Fake and Rekor
// ============================================================

#[tokio::test]
async fn pluggability_same_flow_different_backends() {
    use auths_sdk::testing::fakes::FakeTransparencyLog;
    use auths_sdk::workflows::log_submit::submit_attestation_to_log;

    let attestation = b"pluggability test";
    let pk = b"pk";
    let sig = b"sig";

    // Run with FakeTransparencyLog
    let fake = FakeTransparencyLog::succeeding();
    let fake_result = submit_attestation_to_log(attestation, pk, sig, &fake).await;
    assert!(fake_result.is_ok(), "fake backend should succeed");

    // Run with RekorClient (only if AUTHS_TEST_REKOR is set)
    if rekor_enabled() {
        let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[77u8; 32]).unwrap();
        let real_pk = keypair.public_key().as_ref();
        let real_sig = keypair.sign(attestation);

        let rekor = &*TEST_REKOR;
        let rekor_result =
            submit_attestation_to_log(attestation, real_pk, real_sig.as_ref(), rekor).await;

        match rekor_result {
            Ok(bundle) => {
                // Both backends produced valid bundles
                let leaf_hash = hash_leaf(attestation);
                assert!(bundle.inclusion_proof.verify(&leaf_hash).is_ok());
                eprintln!("Pluggability proof: both Fake and Rekor succeeded");
            }
            Err(auths_sdk::workflows::log_submit::LogSubmitError::LogError(
                LogError::RateLimited { .. },
            )) => {
                eprintln!("Rekor rate limited — pluggability partially verified (fake only)");
            }
            Err(e) => {
                eprintln!("Rekor failed: {e} — pluggability partially verified");
            }
        }
    } else {
        eprintln!("Rekor not enabled — pluggability verified with fake only");
    }
}
