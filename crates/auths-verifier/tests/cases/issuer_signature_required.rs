use auths_crypto::testing::create_test_keypair;
use auths_verifier::AttestationBuilder;
use auths_verifier::DevicePublicKey;
use auths_verifier::core::{Ed25519PublicKey, Ed25519Signature, canonicalize_attestation_data};
use auths_verifier::verify::verify_with_keys;
use chrono::{DateTime, Duration, Utc};

fn ed(pk: &[u8; 32]) -> DevicePublicKey {
    DevicePublicKey::try_new(auths_crypto::CurveType::Ed25519, pk).unwrap()
}

fn ed25519_did(pk: &[u8; 32]) -> String {
    auths_verifier::CanonicalDid::from_public_key_did_key(pk, auths_crypto::CurveType::Ed25519)
        .to_string()
}

/// An attacker holding only their own device key forges an attestation that
/// names a victim root as the issuer but leaves the issuer signature absent.
/// Verifying against the victim root must reject it: an absent issuer signature
/// is not authorization, so "root vouches for this device" cannot be claimed
/// without the root actually signing it.
#[tokio::test]
async fn absent_issuer_signature_does_not_authorize_a_device() {
    // The root the verifier trusts. The attacker never holds its private key.
    let (_victim_root_kp, victim_root_pk) = create_test_keypair(&[1u8; 32]);
    let victim_root_did = ed25519_did(&victim_root_pk);

    // The attacker's own device key.
    let (attacker_kp, attacker_pk) = create_test_keypair(&[2u8; 32]);
    let attacker_did = ed25519_did(&attacker_pk);

    let timestamp = DateTime::UNIX_EPOCH + Duration::days(1000);
    let expires = Utc::now() + Duration::days(365);

    // issuer = victim root, subject + device = attacker, issuer signature absent.
    let mut att = AttestationBuilder::default()
        .rid("forged")
        .issuer(&victim_root_did)
        .subject(&attacker_did)
        .device_public_key(Ed25519PublicKey::from_bytes(attacker_pk))
        .expires_at(Some(expires))
        .timestamp(Some(timestamp))
        .build();

    let canonical = canonicalize_attestation_data(&att.canonical_data()).unwrap();
    // The attacker can sign the device slot (it is their own key); the issuer
    // slot stays empty because they cannot produce the root's signature.
    att.device_signature =
        Ed25519Signature::try_from_slice(attacker_kp.sign(&canonical).as_ref()).unwrap();
    assert!(
        att.identity_signature.is_empty(),
        "this test requires the issuer signature to be absent"
    );

    let result = verify_with_keys(&att, &ed(&victim_root_pk)).await;

    assert!(
        result.is_err(),
        "an attestation with no issuer signature must not verify against the root it names as issuer; got {result:?}"
    );
}

/// A device may assert about its own key, but such a self-assertion carries no
/// authorization from anyone else. Passing an unrelated trusted root key as the
/// issuer must not turn "I vouch for my own key" into "the root vouches for me":
/// an attestation with no issuer signature is rejected on the authority path.
#[tokio::test]
async fn self_assertion_does_not_verify_against_an_unrelated_root() {
    let (_victim_root_kp, victim_root_pk) = create_test_keypair(&[1u8; 32]);

    let (attacker_kp, attacker_pk) = create_test_keypair(&[2u8; 32]);
    let attacker_did = ed25519_did(&attacker_pk);

    let timestamp = DateTime::UNIX_EPOCH + Duration::days(1000);
    let expires = Utc::now() + Duration::days(365);

    // issuer == subject == the attacker's own device, with no issuer signature.
    let mut att = AttestationBuilder::default()
        .rid("self")
        .issuer(&attacker_did)
        .subject(&attacker_did)
        .device_public_key(Ed25519PublicKey::from_bytes(attacker_pk))
        .expires_at(Some(expires))
        .timestamp(Some(timestamp))
        .build();

    let canonical = canonicalize_attestation_data(&att.canonical_data()).unwrap();
    att.device_signature =
        Ed25519Signature::try_from_slice(attacker_kp.sign(&canonical).as_ref()).unwrap();

    let result = verify_with_keys(&att, &ed(&victim_root_pk)).await;

    assert!(
        result.is_err(),
        "a self-assertion with no issuer signature must not verify against an unrelated root key; got {result:?}"
    );
}
