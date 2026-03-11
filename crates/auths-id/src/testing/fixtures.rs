use auths_core::crypto::said::compute_next_commitment;
use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
use auths_verifier::types::{CanonicalDid, DeviceDID};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::keri::event::{Event, IcpEvent, KeriSequence};
use crate::keri::types::{Prefix, Said};
use crate::keri::{KERI_VERSION, finalize_icp_event, serialize_for_signing};

/// Minimal signed inception event for registry contract tests.
///
/// The SAID is properly computed and the event is signed with a fresh Ed25519
/// keypair so it passes `GitRegistryBackend`'s signature validation.
///
/// Each call produces a different Ed25519 key and thus a different SAID / prefix.
/// Use the returned event's `prefix()` as the first argument to `append_event`.
///
/// Args:
/// * `key_seed`: Ignored — exists only for call-site readability.
///
/// Usage:
/// ```ignore
/// let event = test_inception_event("seed-1");
/// let prefix = event.prefix().to_string();
/// backend.append_event(&prefix, &event).unwrap();
/// ```
pub fn test_inception_event(key_seed: &str) -> Event {
    let _ = key_seed;
    let rng = SystemRandom::new();

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let icp = IcpEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: "1".to_string(),
        k: vec![key_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp).expect("fixture event must finalize");
    let canonical =
        serialize_for_signing(&Event::Icp(finalized.clone())).expect("must serialize for signing");
    let sig = keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Event::Icp(finalized)
}

/// Minimal attestation fixture for registry and org member contract tests.
///
/// Args:
/// * `device_did`: The device DID that is the subject of this attestation.
/// * `issuer`: The issuer DID string (e.g. `"did:keri:ETestOrg"`).
///
/// Usage:
/// ```ignore
/// let did = DeviceDID::new_unchecked("did:key:zTest");
/// let att = test_attestation(&did, "did:keri:ETestOrg");
/// backend.store_attestation(&att).unwrap();
/// ```
pub fn test_attestation(device_did: &DeviceDID, issuer: &str) -> Attestation {
    Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: CanonicalDid::new_unchecked(issuer),
        subject: device_did.clone(),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
    }
}
