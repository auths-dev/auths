use auths_test_utils::crypto::create_test_keypair;
use auths_verifier::core::{
    Attestation, CanonicalAttestationData, Ed25519PublicKey, Ed25519Signature, ResourceId,
    canonicalize_attestation_data,
};
use auths_verifier::types::{DeviceDID, IdentityDID};
use auths_verifier::verify::verify_with_keys;
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

const FIXED_TS: fn() -> DateTime<Utc> = || DateTime::UNIX_EPOCH + Duration::days(1000);

fn create_signed_attestation(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    timestamp: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let mut att = Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: IdentityDID::new(issuer_did),
        subject: DeviceDID::new(subject_did),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at,
        expires_at: Some(expires_at),
        timestamp: Some(timestamp),
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
    };

    let data = CanonicalAttestationData {
        version: att.version,
        rid: &att.rid,
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_bytes(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: None,
        capabilities: None,
        delegated_by: None,
        signer_type: None,
    };
    let canonical_bytes = canonicalize_attestation_data(&data).unwrap();

    att.identity_signature =
        Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();
    att.device_signature =
        Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();
    att
}

#[tokio::test]
async fn tamper_revoked_at_to_null_is_rejected() {
    let (issuer_kp, issuer_pk) = create_test_keypair(&[1u8; 32]);
    let issuer_did = auths_crypto::ed25519_pubkey_to_did_key(&issuer_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = auths_crypto::ed25519_pubkey_to_did_key(&device_pk);

    let fixed_ts = FIXED_TS();
    let far_future = Utc::now() + Duration::days(365);
    let mut att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(fixed_ts),
        fixed_ts,
        far_future,
    );

    att.revoked_at = None;

    let result = verify_with_keys(&att, &issuer_pk).await;
    assert!(
        result.is_err(),
        "Stripping revoked_at must invalidate the attestation"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("signature"),
        "Error should mention signature failure, got: {err}"
    );
}

#[tokio::test]
async fn tamper_revoked_at_to_different_time_is_rejected() {
    let (issuer_kp, issuer_pk) = create_test_keypair(&[3u8; 32]);
    let issuer_did = auths_crypto::ed25519_pubkey_to_did_key(&issuer_pk);
    let (device_kp, device_pk) = create_test_keypair(&[4u8; 32]);
    let device_did = auths_crypto::ed25519_pubkey_to_did_key(&device_pk);

    let fixed_ts = FIXED_TS();
    let original_revoked_at = fixed_ts - Duration::hours(1);
    let mut att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        Some(original_revoked_at),
        fixed_ts,
        fixed_ts + Duration::days(365),
    );

    att.revoked_at = Some(fixed_ts + Duration::days(30));

    let result = verify_with_keys(&att, &issuer_pk).await;
    assert!(
        result.is_err(),
        "Changing revoked_at timestamp must invalidate the attestation"
    );
}

#[tokio::test]
async fn inject_revoked_at_into_unrevoked_is_rejected() {
    let (issuer_kp, issuer_pk) = create_test_keypair(&[5u8; 32]);
    let issuer_did = auths_crypto::ed25519_pubkey_to_did_key(&issuer_pk);
    let (device_kp, device_pk) = create_test_keypair(&[6u8; 32]);
    let device_did = auths_crypto::ed25519_pubkey_to_did_key(&device_pk);

    let fixed_ts = FIXED_TS();
    let mut att = create_signed_attestation(
        &issuer_kp,
        &device_kp,
        &issuer_did,
        &device_did,
        None,
        fixed_ts,
        fixed_ts + Duration::days(365),
    );

    att.revoked_at = Some(fixed_ts + Duration::days(1));

    let result = verify_with_keys(&att, &issuer_pk).await;
    assert!(
        result.is_err(),
        "Injecting revoked_at must invalidate the attestation"
    );
}
