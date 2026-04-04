use auths_core::crypto::ssh::SecureSeed;
use auths_core::storage::keychain::IdentityDID;
use auths_sdk::domains::signing::service::{
    ArtifactSigningError, ArtifactSigningParams, SigningKeyMaterial, sign_artifact,
    sign_artifact_raw,
};
use auths_sdk::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactMetadata, ArtifactSource};
use auths_sdk::testing::fakes::FakeArtifactSource;
use auths_sdk::workflows::artifact::compute_digest;
use chrono::Utc;
use std::sync::Arc;

use crate::cases::helpers::{build_empty_test_context, setup_signed_artifact_context};

#[test]
fn fake_artifact_from_data_digest_is_deterministic() {
    let artifact = FakeArtifactSource::from_data("test.bin", b"hello world");

    let d1 = artifact.digest().unwrap();
    let d2 = artifact.digest().unwrap();

    assert_eq!(d1, d2);
    assert_eq!(d1.algorithm, "sha256");
    assert_eq!(
        d1.hex,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn fake_artifact_from_data_metadata_includes_name_and_size() {
    let artifact = FakeArtifactSource::from_data("payload.tar.gz", b"some content");

    let meta = artifact.metadata().unwrap();

    assert_eq!(meta.artifact_type, "memory");
    assert_eq!(meta.name, Some("payload.tar.gz".to_string()));
    assert_eq!(meta.size, Some(12));
    assert_eq!(meta.digest.algorithm, "sha256");
}

#[test]
fn compute_digest_delegates_to_source() {
    let artifact = FakeArtifactSource::from_data("test.bin", b"test data");

    let direct = artifact.digest().unwrap();
    let via_workflow = compute_digest(&artifact).unwrap();

    assert_eq!(direct, via_workflow);
}

#[test]
fn failing_artifact_returns_io_error() {
    let artifact = FakeArtifactSource::digest_fails_with("simulated read failure");
    let result = artifact.digest();

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ArtifactError::Io(_)),
        "Expected Io error, got: {:?}",
        err
    );
}

#[test]
fn failing_artifact_metadata_returns_error() {
    let artifact = FakeArtifactSource::metadata_fails_with("no metadata available");
    let result = artifact.metadata();

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ArtifactError::Metadata(_)));
}

#[test]
fn artifact_digest_equality() {
    let d1 = ArtifactDigest {
        algorithm: "sha256".to_string(),
        hex: "abc123".to_string(),
    };
    let d2 = ArtifactDigest {
        algorithm: "sha256".to_string(),
        hex: "abc123".to_string(),
    };
    let d3 = ArtifactDigest {
        algorithm: "sha256".to_string(),
        hex: "def456".to_string(),
    };

    assert_eq!(d1, d2);
    assert_ne!(d1, d3);
}

#[test]
fn artifact_metadata_serialization_roundtrip() {
    let meta = ArtifactMetadata {
        artifact_type: "file".to_string(),
        digest: ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: "abc123".to_string(),
        },
        name: Some("test.bin".to_string()),
        size: Some(1024),
    };

    let json = serde_json::to_string(&meta).unwrap();
    let deserialized: ArtifactMetadata = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.artifact_type, "file");
    assert_eq!(deserialized.digest.hex, "abc123");
    assert_eq!(deserialized.name, Some("test.bin".to_string()));
    assert_eq!(deserialized.size, Some(1024));
}

// ---------------------------------------------------------------------------
// sign_artifact integration tests
// ---------------------------------------------------------------------------

#[test]
fn sign_artifact_with_alias_keys_produces_valid_json() {
    let (_tmp, key_alias, ctx) = setup_signed_artifact_context();

    let artifact = Arc::new(FakeArtifactSource::from_data(
        "release.bin",
        b"release binary content",
    ));

    let params = ArtifactSigningParams {
        artifact,
        identity_key: Some(SigningKeyMaterial::Alias(key_alias.clone())),
        device_key: SigningKeyMaterial::Alias(key_alias),
        expires_in: Some(31_536_000),
        note: Some("integration test".into()),
        commit_sha: None,
    };

    let result = sign_artifact(params, &ctx).unwrap();

    assert!(!result.attestation_json.is_empty());
    assert!(result.rid.starts_with("sha256:"));
    assert!(!result.digest.is_empty());

    let parsed: serde_json::Value = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(result.rid, parsed["rid"].as_str().unwrap());
    assert!(parsed.get("identity_signature").is_some());
    assert!(parsed.get("device_signature").is_some());
}

#[test]
fn sign_artifact_with_direct_device_key_produces_valid_json() {
    let (_tmp, key_alias, ctx) = setup_signed_artifact_context();

    let device_seed = SecureSeed::new([42u8; 32]);
    let artifact = Arc::new(FakeArtifactSource::from_data(
        "release-v2.bin",
        b"release binary content v2",
    ));

    let params = ArtifactSigningParams {
        artifact,
        identity_key: Some(SigningKeyMaterial::Alias(key_alias)),
        device_key: SigningKeyMaterial::Direct(device_seed),
        expires_in: None,
        note: None,
        commit_sha: None,
    };

    let result = sign_artifact(params, &ctx).unwrap();

    assert!(result.rid.starts_with("sha256:"));
    let parsed: serde_json::Value = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(result.rid, parsed["rid"].as_str().unwrap());
}

#[test]
fn sign_artifact_identity_not_found_returns_error() {
    let (_tmp, empty_ctx) = build_empty_test_context();

    let device_seed = SecureSeed::new([1u8; 32]);
    let artifact = Arc::new(FakeArtifactSource::from_data("file.bin", b"data"));

    let params = ArtifactSigningParams {
        artifact,
        identity_key: None,
        device_key: SigningKeyMaterial::Direct(device_seed),
        expires_in: None,
        note: None,
        commit_sha: None,
    };

    let result = sign_artifact(params, &empty_ctx);
    assert!(
        matches!(result, Err(ArtifactSigningError::IdentityNotFound)),
        "Expected IdentityNotFound, got: {:?}",
        result.unwrap_err()
    );
}

// ---------------------------------------------------------------------------
// sign_artifact_raw tests
// ---------------------------------------------------------------------------

#[test]
fn sign_artifact_raw_produces_valid_attestation_json() {
    let seed = SecureSeed::new([42u8; 32]);
    let identity_did = IdentityDID::new_unchecked("did:keri:Etest1234");
    let data = b"release binary content";
    let now = Utc::now();

    let result = sign_artifact_raw(
        now,
        &seed,
        &identity_did,
        data,
        Some(86400),
        Some("test note".into()),
        None,
    )
    .unwrap();

    assert!(!result.attestation_json.is_empty());
    assert!(result.rid.starts_with("sha256:"));
    assert!(!result.digest.is_empty());

    let parsed: serde_json::Value = serde_json::from_str(&result.attestation_json).unwrap();
    assert_eq!(parsed["issuer"].as_str().unwrap(), "did:keri:Etest1234");
    assert!(parsed.get("identity_signature").is_some());
    assert!(parsed.get("device_signature").is_some());
    assert!(parsed.get("payload").is_some());
    assert!(parsed.get("expires_at").is_some());
    assert_eq!(parsed["note"].as_str().unwrap(), "test note");

    let payload = &parsed["payload"];
    assert_eq!(payload["artifact_type"].as_str().unwrap(), "bytes");
    assert_eq!(payload["digest"]["algorithm"].as_str().unwrap(), "sha256");
    assert_eq!(payload["size"].as_u64().unwrap(), data.len() as u64);
}

#[test]
fn sign_artifact_raw_without_optional_fields() {
    let seed = SecureSeed::new([7u8; 32]);
    let identity_did = IdentityDID::new_unchecked("did:keri:Eminimal");
    let now = Utc::now();

    let result = sign_artifact_raw(now, &seed, &identity_did, b"data", None, None, None).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&result.attestation_json).unwrap();
    assert!(parsed.get("expires_at").is_none() || parsed["expires_at"].is_null());
    assert!(parsed.get("note").is_none() || parsed["note"].is_null());
}

#[test]
fn sign_artifact_raw_digest_matches_sha256_of_data() {
    let seed = SecureSeed::new([1u8; 32]);
    let identity_did = IdentityDID::new_unchecked("did:keri:Edigest");
    let data = b"hello world";
    let now = Utc::now();

    let result = sign_artifact_raw(now, &seed, &identity_did, data, None, None, None).unwrap();

    let expected_digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    assert_eq!(result.digest, expected_digest);
    assert_eq!(result.rid.as_str(), format!("sha256:{expected_digest}"));
}
