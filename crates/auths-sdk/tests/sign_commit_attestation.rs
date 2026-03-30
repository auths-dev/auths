//! Integration tests for commit signing and attestation verification.
//!
//! COMMENTED OUT: Tests for workflows that moved to auths-api.
//! To avoid violating the one-way dependency rule (auths-api imports from auths-sdk, never reverse),
//! these tests have been moved to auths-api/tests/ where the workflows live.

/*
use auths_crypto::testing::gen_keypair;
use auths_sdk::workflows::machine_identity::{
    OidcMachineIdentity, SignCommitParams, sign_commit_with_identity,
};
use chrono::Utc;
use ring::signature::KeyPair;
use serde_json::json;*/

/*
#[test]
fn test_sign_commit_with_oidc_binding() {
    let keypair = gen_keypair();
    let pubkey = keypair.public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();

    let mut normalized_claims = serde_json::Map::new();
    normalized_claims.insert("repo".to_string(), "owner/repo".into());
    normalized_claims.insert("actor".to_string(), "alice".into());

    let oidc_identity = OidcMachineIdentity {
        platform: "github".to_string(),
        subject: "repo:owner/repo:ref:refs/heads/main".to_string(),
        token_exp: 1704067200,
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "sigstore".to_string(),
        jti: Some("jti-test-12345".to_string()),
        normalized_claims,
    };

    #[allow(clippy::disallowed_methods)] // test code
    let timestamp = Utc::now();
    let params = SignCommitParams {
        commit_sha: "abc123def456789abcdef".to_string(),
        issuer_did: "did:keri:Eissuer".to_string(),
        device_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR".to_string(),
        commit_message: Some("feat: add sign-commit feature".to_string()),
        author: Some("Alice Developer".to_string()),
        oidc_binding: Some(oidc_identity),
        timestamp,
    };

    let attestation = sign_commit_with_identity(&params, &keypair, &pubkey_bytes)
        .expect("sign_commit_with_identity should succeed");

    // Verify attestation structure
    assert_eq!(attestation.version, 1);
    assert_eq!(
        attestation.commit_sha,
        Some("abc123def456789abcdef".to_string())
    );
    assert_eq!(
        attestation.commit_message,
        Some("feat: add sign-commit feature".to_string())
    );
    assert_eq!(attestation.author, Some("Alice Developer".to_string()));

    // Verify OIDC binding
    assert!(attestation.oidc_binding.is_some());
    let binding = attestation.oidc_binding.unwrap();
    assert_eq!(
        binding.issuer,
        "https://token.actions.githubusercontent.com"
    );
    assert_eq!(binding.platform, Some("github".to_string()));
    assert_eq!(binding.jti, Some("jti-test-12345".to_string()));
    assert!(binding.normalized_claims.is_some());

    // Verify signatures are non-empty
    assert!(!attestation.identity_signature.is_empty());
}

#[test]
fn test_sign_commit_without_oidc_binding() {
    let keypair = gen_keypair();
    let pubkey = keypair.public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();

    #[allow(clippy::disallowed_methods)] // test code
    let timestamp = Utc::now();
    let params = SignCommitParams {
        commit_sha: "fedcba9876543210fedcba".to_string(),
        issuer_did: "did:keri:Eissuer".to_string(),
        device_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR".to_string(),
        commit_message: Some("refactor: cleanup".to_string()),
        author: Some("Bob".to_string()),
        oidc_binding: None,
        timestamp,
    };

    let attestation = sign_commit_with_identity(&params, &keypair, &pubkey_bytes)
        .expect("sign_commit_with_identity should succeed without OIDC");

    // Verify attestation has commit metadata
    assert_eq!(
        attestation.commit_sha,
        Some("fedcba9876543210fedcba".to_string())
    );
    assert_eq!(
        attestation.commit_message,
        Some("refactor: cleanup".to_string())
    );

    // Verify no OIDC binding when not provided
    assert!(attestation.oidc_binding.is_none());

    // Verify signatures present
    assert!(!attestation.identity_signature.is_empty());
}

#[test]
fn test_attestation_serialization_roundtrip() {
    let keypair = gen_keypair();
    let pubkey = keypair.public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();

    let mut claims = serde_json::Map::new();
    claims.insert("run_id".to_string(), json!("12345"));

    let oidc = OidcMachineIdentity {
        platform: "github".to_string(),
        subject: "workload:12345".to_string(),
        token_exp: 1704067200,
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "sigstore".to_string(),
        jti: Some("jti-12345".to_string()),
        normalized_claims: claims,
    };

    #[allow(clippy::disallowed_methods)] // test code
    let timestamp = Utc::now();
    let params = SignCommitParams {
        commit_sha: "1234567890abcdef1234567890abcdef12345678".to_string(),
        issuer_did: "did:keri:Eissuer".to_string(),
        device_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR".to_string(),
        commit_message: Some("feat: test".to_string()),
        author: Some("Tester".to_string()),
        oidc_binding: Some(oidc),
        timestamp,
    };

    let attestation = sign_commit_with_identity(&params, &keypair, &pubkey_bytes)
        .expect("Creating attestation should succeed");

    // Serialize to JSON
    let json_str =
        serde_json::to_string(&attestation).expect("Attestation should be serializable to JSON");

    // Deserialize back
    let deserialized: auths_verifier::core::Attestation =
        serde_json::from_str(&json_str).expect("JSON should deserialize back to Attestation");

    // Verify roundtrip preserves key fields
    assert_eq!(deserialized.commit_sha, attestation.commit_sha);
    assert_eq!(deserialized.commit_message, attestation.commit_message);
    assert_eq!(deserialized.author, attestation.author);
    assert_eq!(deserialized.oidc_binding, attestation.oidc_binding);
}

#[test]
fn test_attestation_rid_format() {
    let keypair = gen_keypair();
    let pubkey = keypair.public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();

    let commit_sha = "abc123def456";

    #[allow(clippy::disallowed_methods)] // test code
    let timestamp = Utc::now();
    let params = SignCommitParams {
        commit_sha: commit_sha.to_string(),
        issuer_did: "did:keri:Eissuer".to_string(),
        device_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR".to_string(),
        commit_message: None,
        author: None,
        oidc_binding: None,
        timestamp,
    };

    let attestation = sign_commit_with_identity(&params, &keypair, &pubkey_bytes)
        .expect("Should create attestation");

    // Verify RID follows pattern: auths/commits/<sha>
    let expected_rid = format!("auths/commits/{}", commit_sha);
    assert_eq!(attestation.rid.as_str(), expected_rid);
}

#[test]
fn test_multiple_commits_independent_attestations() {
    let keypair = gen_keypair();
    let pubkey = keypair.public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();

    let shas = ["aaa111", "bbb222", "ccc333"];
    let mut attestations = vec![];

    for sha in shas.iter() {
        #[allow(clippy::disallowed_methods)] // test code
        let timestamp = Utc::now();
        let params = SignCommitParams {
            commit_sha: sha.to_string(),
            issuer_did: "did:keri:Eissuer".to_string(),
            device_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcERV3PcxP7o8awhz7vMPFR".to_string(),
            commit_message: Some(format!("Commit {}", sha)),
            author: None,
            oidc_binding: None,
            timestamp,
        };

        let att = sign_commit_with_identity(&params, &keypair, &pubkey_bytes)
            .expect("Should create attestation");
        attestations.push(att);
    }

    // Verify each attestation has correct commit SHA
    for (i, att) in attestations.iter().enumerate() {
        assert_eq!(att.commit_sha.as_deref(), Some(shas[i]));
        let expected_msg = format!("Commit {}", shas[i]);
        assert_eq!(att.commit_message.as_deref(), Some(expected_msg.as_str()));
    }
}
*/
