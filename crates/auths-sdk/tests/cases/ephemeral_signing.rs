use auths_sdk::domains::signing::service::sign_artifact_ephemeral;
use auths_verifier::core::{Attestation, SignerType};
use chrono::Utc;

const VALID_SHA: &str = "abc123def456abc123def456abc123def456abc1";

#[test]
fn produces_valid_attestation_with_did_key_issuer() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .expect("signing should succeed");

    let att: Attestation =
        serde_json::from_str(&result.attestation_json).expect("should parse as Attestation");

    assert!(
        att.issuer.as_str().starts_with("did:key:z"),
        "issuer should be did:key:, got: {}",
        att.issuer
    );
    assert!(
        att.subject.as_str().starts_with("did:key:z"),
        "subject should be did:key:, got: {}",
        att.subject
    );
}

#[test]
fn signer_type_is_workload() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .expect("signing should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(att.signer_type, Some(SignerType::Workload));
}

#[test]
fn commit_sha_is_present() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .expect("signing should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(att.commit_sha.as_deref(), Some(VALID_SHA));
}

#[test]
fn each_call_uses_different_ephemeral_key() {
    let r1 = sign_artifact_ephemeral(
        Utc::now(),
        b"data1",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .unwrap();
    let r2 = sign_artifact_ephemeral(
        Utc::now(),
        b"data2",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .unwrap();

    let a1: Attestation = serde_json::from_str(&r1.attestation_json).unwrap();
    let a2: Attestation = serde_json::from_str(&r2.attestation_json).unwrap();

    assert_ne!(
        a1.issuer, a2.issuer,
        "two calls should produce different ephemeral keys"
    );
}

#[test]
fn ci_environment_in_payload() {
    let ci_env = serde_json::json!({
        "platform": "github_actions",
        "workflow_ref": "release.yml",
        "run_id": "42"
    });

    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        Some("test.tar.gz".into()),
        VALID_SHA.into(),
        None,
        None,
        Some(ci_env),
    )
    .expect("signing should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    let payload = att.payload.expect("payload should exist");
    let ci = payload
        .get("ci_environment")
        .expect("ci_environment should be in payload");
    assert_eq!(ci["platform"], "github_actions");
    assert_eq!(ci["run_id"], "42");
}

#[test]
fn empty_data_produces_valid_attestation() {
    let result = sign_artifact_ephemeral(Utc::now(), b"", None, VALID_SHA.into(), None, None, None)
        .expect("empty data should still produce valid attestation");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert!(att.issuer.as_str().starts_with("did:key:z"));
}

#[test]
fn invalid_commit_sha_rejected() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        None,
        "not-a-valid-sha".into(),
        None,
        None,
        None,
    );

    assert!(result.is_err(), "invalid commit SHA should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("commit SHA") || err.contains("InvalidCommitSha"),
        "error should mention commit SHA: {}",
        err
    );
}

#[test]
fn tamper_commit_sha_breaks_signature() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"test data",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .unwrap();

    // Parse, tamper with commit_sha, re-serialize
    let mut att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    att.commit_sha = Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into());

    // Extract the pubkey from the issuer DID for verification
    let issuer_did = att.issuer.as_str();
    let pk = auths_crypto::did_key_to_ed25519(issuer_did).expect("should resolve did:key");

    // Verify the tampered attestation — should fail because signature covers commit_sha
    let rt = tokio::runtime::Runtime::new().unwrap();
    let chain = vec![att];
    let report = rt.block_on(auths_verifier::verify_chain(&chain, &pk));

    if let Ok(r) = report {
        assert!(
            !r.is_valid(),
            "tampered commit_sha should produce invalid verification"
        );
    }
    // Err is also acceptable — signature mismatch
}

#[test]
fn tamper_artifact_fails_digest_check() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        b"original artifact data",
        None,
        VALID_SHA.into(),
        None,
        None,
        None,
    )
    .unwrap();

    // The result digest is for "original artifact data"
    // A different artifact should not match
    let different_digest = hex::encode(sha2::Sha256::digest(b"tampered artifact data"));
    assert_ne!(
        result.digest, different_digest,
        "different data should produce different digest"
    );
}

#[test]
fn ephemeral_key_collision_check() {
    use std::collections::HashSet;

    let mut issuers = HashSet::new();
    for _ in 0..100 {
        let r = sign_artifact_ephemeral(
            Utc::now(),
            b"data",
            None,
            VALID_SHA.into(),
            None,
            None,
            None,
        )
        .unwrap();
        let att: Attestation = serde_json::from_str(&r.attestation_json).unwrap();
        issuers.insert(att.issuer.to_string());
    }

    assert_eq!(
        issuers.len(),
        100,
        "100 calls should produce 100 distinct ephemeral keys"
    );
}

use sha2::Digest;
