//! `DeviceDID::from_typed_pubkey` — curve-dispatching constructor.
//!
//! Verifies that the unified constructor emits the correct multicodec prefix
//! for each curve, replacing the historical split between `from_ed25519` and
//! `auths_crypto::p256_pubkey_to_did_key`.

use auths_crypto::CurveType;
use auths_crypto::testing::{ALL_CURVES, generate_typed_signer};
use auths_verifier::types::DeviceDID;

#[test]
fn from_typed_pubkey_emits_correct_multicodec_prefix() {
    for &curve in ALL_CURVES {
        let signer = generate_typed_signer(curve);
        let did = DeviceDID::from_typed_pubkey(&signer);
        let s = did.as_str();
        assert!(s.starts_with("did:key:z"), "did:key prefix on {curve}");
        let suffix = &s["did:key:z".len()..];
        match curve {
            // Ed25519 multicodec varint 0xED 0x01 → base58btc encoded → "z6Mk…"
            CurveType::Ed25519 => assert!(
                suffix.starts_with("6Mk"),
                "expected Ed25519 did:key prefix `z6Mk…`, got `{s}`"
            ),
            // P-256 multicodec varint 0x80 0x24 → base58btc encoded → "zDna…"
            CurveType::P256 => assert!(
                suffix.starts_with("Dna"),
                "expected P-256 did:key prefix `zDna…`, got `{s}`"
            ),
        }
    }
}

#[test]
fn from_typed_pubkey_matches_from_public_key() {
    for &curve in ALL_CURVES {
        let signer = generate_typed_signer(curve);
        let typed_did = DeviceDID::from_typed_pubkey(&signer);
        let manual_did = DeviceDID::from_public_key(signer.public_key(), curve);
        assert_eq!(typed_did, manual_did, "curve = {curve}");
    }
}
