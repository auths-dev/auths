use auths_crypto::testing::create_test_keypair;
use auths_verifier::AttestationBuilder;
use auths_verifier::DevicePublicKey;
use auths_verifier::core::{
    Attestation, Ed25519PublicKey, Ed25519Signature, canonicalize_attestation_data,
};
use auths_verifier::verifier::Verifier;
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Wrap a raw 32-byte Ed25519 key into a `DevicePublicKey` for tests.
fn ed(pk: &[u8; 32]) -> DevicePublicKey {
    DevicePublicKey::try_new(auths_crypto::CurveType::Ed25519, pk).unwrap()
}

fn create_signed_attestation(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    timestamp: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let mut att = AttestationBuilder::default()
        .rid("test-rid")
        .issuer(issuer_did)
        .subject(subject_did)
        .device_public_key(Ed25519PublicKey::from_bytes(device_pk))
        .expires_at(expires_at)
        .timestamp(timestamp)
        .build();

    let canonical_bytes = canonicalize_attestation_data(&att.canonical_data()).unwrap();

    att.identity_signature =
        Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();
    att.device_signature =
        Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();
    att
}

fn test_keypairs() -> (Ed25519KeyPair, [u8; 32], Ed25519KeyPair, String, String) {
    let (issuer_kp, issuer_pk) = create_test_keypair(&[10u8; 32]);
    let issuer_did = auths_crypto::ed25519_pubkey_to_did_key(&issuer_pk);
    let (device_kp, device_pk) = create_test_keypair(&[11u8; 32]);
    let device_did = auths_crypto::ed25519_pubkey_to_did_key(&device_pk);
    (issuer_kp, issuer_pk, device_kp, issuer_did, device_did)
}

// =========================================================================
// Expiration boundary tests (using verify_at_time to control reference time)
// =========================================================================

#[tokio::test]
async fn attestation_exactly_at_expiration_boundary_is_rejected() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = DateTime::UNIX_EPOCH + Duration::days(1000);
    let expires_at = now;

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(now - Duration::hours(1)),
        Some(expires_at),
    );

    // reference_time == expires_at: the check is `reference_time > exp`, so equal should pass
    let verifier = Verifier::native();
    let result = verifier.verify_at_time(&att, &ed(&issuer_pk), now).await;
    assert!(
        result.is_ok(),
        "Attestation at exact expiration should still be valid (not strictly past)"
    );
}

#[tokio::test]
async fn attestation_one_second_past_expiration_is_rejected() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = DateTime::UNIX_EPOCH + Duration::days(1000);
    let expires_at = now;

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(now - Duration::hours(1)),
        Some(expires_at),
    );

    let verifier = Verifier::native();
    let result = verifier
        .verify_at_time(&att, &ed(&issuer_pk), now + Duration::seconds(1))
        .await;
    assert!(
        result.is_err(),
        "Attestation 1 second past expiration must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expired"),
        "Error should mention expiration, got: {err}"
    );
}

#[tokio::test]
async fn attestation_well_before_expiration_is_valid() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = DateTime::UNIX_EPOCH + Duration::days(1000);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(now - Duration::hours(1)),
        Some(now + Duration::days(30)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_at_time(&att, &ed(&issuer_pk), now).await;
    assert!(
        result.is_ok(),
        "Attestation well before expiration should be valid"
    );
}

// =========================================================================
// Timestamp skew tests (using verify_with_keys which checks skew against Utc::now())
// =========================================================================

#[tokio::test]
async fn timestamp_within_skew_window_is_valid() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = Utc::now();
    // Timestamp 2 minutes in the future (within 5-minute skew)
    let future_ts = now + Duration::minutes(2);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(future_ts),
        Some(now + Duration::days(365)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_with_keys(&att, &ed(&issuer_pk)).await;
    assert!(
        result.is_ok(),
        "Timestamp 2 minutes in the future (within 5min skew) should be valid"
    );
}

#[tokio::test]
async fn timestamp_beyond_skew_window_is_rejected() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = Utc::now();
    // Timestamp 10 minutes in the future (beyond 5-minute skew)
    let future_ts = now + Duration::minutes(10);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(future_ts),
        Some(now + Duration::days(365)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_with_keys(&att, &ed(&issuer_pk)).await;
    assert!(
        result.is_err(),
        "Timestamp 10 minutes in the future (beyond 5min skew) must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("future"),
        "Error should mention future timestamp, got: {err}"
    );
}

#[tokio::test]
async fn timestamp_exactly_at_skew_boundary_is_valid() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = Utc::now();
    // Timestamp exactly 5 minutes in the future (at the boundary)
    // The check is `ts > reference_time + 5min`, so equal should pass
    let boundary_ts = now + Duration::minutes(5);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(boundary_ts),
        Some(now + Duration::days(365)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_with_keys(&att, &ed(&issuer_pk)).await;
    assert!(
        result.is_ok(),
        "Timestamp exactly at 5-minute skew boundary should be valid (not strictly beyond)"
    );
}

#[tokio::test]
async fn past_timestamp_is_always_valid() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = Utc::now();
    let past_ts = now - Duration::days(30);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(past_ts),
        Some(now + Duration::days(365)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_with_keys(&att, &ed(&issuer_pk)).await;
    assert!(
        result.is_ok(),
        "Past timestamps should always be valid (Git attestations are verified later)"
    );
}

#[tokio::test]
async fn no_timestamp_skips_skew_check() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = Utc::now();

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        None,
        Some(now + Duration::days(365)),
    );

    let verifier = Verifier::native();
    let result = verifier.verify_with_keys(&att, &ed(&issuer_pk)).await;
    assert!(
        result.is_ok(),
        "Missing timestamp should skip skew check entirely"
    );
}

#[tokio::test]
async fn no_expiration_skips_expiry_check() {
    let (issuer_kp, issuer_pk, device_kp, issuer_did, device_did) = test_keypairs();
    let now = DateTime::UNIX_EPOCH + Duration::days(1000);

    let att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(now - Duration::hours(1)),
        None,
    );

    let verifier = Verifier::native();
    let result = verifier.verify_at_time(&att, &ed(&issuer_pk), now).await;
    assert!(
        result.is_ok(),
        "Missing expires_at should skip expiry check entirely"
    );
}
