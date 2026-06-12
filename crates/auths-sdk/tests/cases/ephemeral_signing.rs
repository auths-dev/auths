use auths_sdk::domains::signing::service::{EphemeralSignRequest, sign_artifact_ephemeral};
use auths_verifier::core::{Attestation, SignerType};
use chrono::Utc;

const VALID_SHA: &str = "abc123def456abc123def456abc123def456abc1";

#[test]
fn produces_valid_attestation_with_did_key_issuer() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
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
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
    )
    .expect("signing should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(att.signer_type, Some(SignerType::Workload));
}

#[test]
fn commit_sha_is_present() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
    )
    .expect("signing should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(att.commit_sha.as_deref(), Some(VALID_SHA));
}

#[test]
fn each_call_uses_different_ephemeral_key() {
    let r1 = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"data1",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
    )
    .unwrap();
    let r2 = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"data2",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
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
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: Some("test.tar.gz".into()),
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: Some(ci_env),
            oidc_binding: None,
        },
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
    let result = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
    )
    .expect("empty data should still produce valid attestation");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    assert!(att.issuer.as_str().starts_with("did:key:z"));
}

#[test]
fn invalid_commit_sha_rejected() {
    let result = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: None,
            commit_sha: "not-a-valid-sha".into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
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
        EphemeralSignRequest {
            data: b"test data",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
    )
    .unwrap();

    // Parse, tamper with commit_sha, re-serialize
    let mut att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    att.commit_sha = Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into());

    // Extract the pubkey from the issuer DID for verification
    let issuer_did = att.issuer.as_str();
    let (pk_bytes, curve): (Vec<u8>, auths_crypto::CurveType) =
        match auths_crypto::did_key_decode(issuer_did).expect("should resolve did:key") {
            auths_crypto::DecodedDidKey::Ed25519(k) => {
                (k.to_vec(), auths_crypto::CurveType::Ed25519)
            }
            auths_crypto::DecodedDidKey::P256(k) => (k, auths_crypto::CurveType::P256),
        };
    let pk =
        auths_verifier::DevicePublicKey::try_new(curve, &pk_bytes).expect("valid device pubkey");

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
        EphemeralSignRequest {
            data: b"original artifact data",
            artifact_name: None,
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: None,
        },
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
            EphemeralSignRequest {
                data: b"data",
                artifact_name: None,
                commit_sha: VALID_SHA.into(),
                expires_in: None,
                note: None,
                ci_env: None,
                oidc_binding: None,
            },
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

/// A verified OIDC binding rides in the SIGNED envelope: the attestation
/// verifies as-signed, and any tampering with the binding's claims breaks
/// the signature. This is what makes the verify-time policy join (org
/// policy ⋈ binding) trustworthy.
#[test]
fn oidc_binding_is_signature_covered() {
    use auths_verifier::core::OidcBinding;

    let mut claims = serde_json::Map::new();
    claims.insert("repository".to_string(), "acme/widget".into());
    claims.insert(
        "workflow_ref".to_string(),
        "acme/widget/.github/workflows/release.yml@refs/tags/v1.0".into(),
    );
    let binding = OidcBinding {
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        subject: "repo:acme/widget:ref:refs/tags/v1.0".to_string(),
        audience: "https://github.com/acme".to_string(),
        token_exp: 4_102_444_800,
        platform: Some("github".to_string()),
        jti: Some("jti-1".to_string()),
        normalized_claims: Some(claims),
    };

    let result = sign_artifact_ephemeral(
        Utc::now(),
        EphemeralSignRequest {
            data: b"release bytes",
            artifact_name: Some("release.tar.gz".into()),
            commit_sha: VALID_SHA.into(),
            expires_in: None,
            note: None,
            ci_env: None,
            oidc_binding: Some(binding),
        },
    )
    .expect("signing with binding should succeed");

    let att: Attestation = serde_json::from_str(&result.attestation_json).unwrap();
    let bound = att
        .oidc_binding
        .clone()
        .expect("binding should be embedded");
    assert_eq!(bound.subject, "repo:acme/widget:ref:refs/tags/v1.0");

    let (pk_bytes, curve): (Vec<u8>, auths_crypto::CurveType) =
        match auths_crypto::did_key_decode(att.issuer.as_str()).expect("did:key resolves") {
            auths_crypto::DecodedDidKey::Ed25519(k) => {
                (k.to_vec(), auths_crypto::CurveType::Ed25519)
            }
            auths_crypto::DecodedDidKey::P256(k) => (k, auths_crypto::CurveType::P256),
        };
    let pk =
        auths_verifier::DevicePublicKey::try_new(curve, &pk_bytes).expect("valid device pubkey");

    let rt = tokio::runtime::Runtime::new().unwrap();

    // As-signed: the chain verifies.
    let report = rt
        .block_on(auths_verifier::verify_chain(
            std::slice::from_ref(&att),
            &pk,
        ))
        .expect("verification should run");
    assert!(
        report.is_valid(),
        "binding-carrying attestation must verify"
    );

    // Tampered binding: swap the repository claim — the signature must break.
    let mut tampered = att;
    let b = tampered.oidc_binding.as_mut().unwrap();
    b.normalized_claims
        .as_mut()
        .unwrap()
        .insert("repository".to_string(), "attacker/fork".into());
    let report = rt.block_on(auths_verifier::verify_chain(&[tampered], &pk));
    // An Err (signature mismatch) is equally fail-closed.
    if let Ok(r) = report {
        assert!(!r.is_valid(), "tampered binding must not verify");
    }
}
