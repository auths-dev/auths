//! Negative-path coverage for `did:key` decoding (`did_key_decode` /
//! `did_key_to_p256`): wrong multicodec prefixes, truncated/extended
//! payloads, non-z multibase prefixes, and malformed base58.

use auths_crypto::{CurveType, DecodedDidKey, DidKeyError, did_key_decode, did_key_to_p256};

const ED25519_MULTICODEC: [u8; 2] = [0xED, 0x01];
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];
const SECP256K1_MULTICODEC: [u8; 2] = [0xE7, 0x01];
const X25519_MULTICODEC: [u8; 2] = [0xEC, 0x01];

fn did_key_from(multicodec: &[u8], key_bytes: &[u8]) -> String {
    let mut payload = multicodec.to_vec();
    payload.extend_from_slice(key_bytes);
    format!("did:key:z{}", bs58::encode(payload).into_string())
}

// ---------------------------------------------------------------------------
// Positive controls — prove the fixture construction is sound
// ---------------------------------------------------------------------------

#[test]
fn decode_accepts_well_formed_ed25519_did_key() {
    let did = did_key_from(&ED25519_MULTICODEC, &[0x11; 32]);
    let decoded = did_key_decode(&did).unwrap();
    assert_eq!(decoded.curve(), CurveType::Ed25519);
    assert_eq!(decoded.bytes(), &[0x11; 32]);
}

#[test]
fn decode_accepts_well_formed_p256_did_key() {
    let mut key = vec![0x02u8];
    key.extend_from_slice(&[0x22; 32]);
    let did = did_key_from(&P256_MULTICODEC, &key);
    let decoded = did_key_decode(&did).unwrap();
    assert!(matches!(decoded, DecodedDidKey::P256(ref k) if k == &key));
}

// ---------------------------------------------------------------------------
// Wrong multicodec prefix
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_secp256k1_multicodec() {
    let did = did_key_from(&SECP256K1_MULTICODEC, &[0x11; 33]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::UnsupportedMulticodec));
}

#[test]
fn decode_rejects_x25519_multicodec() {
    let did = did_key_from(&X25519_MULTICODEC, &[0x11; 32]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::UnsupportedMulticodec));
}

#[test]
fn did_key_to_p256_rejects_ed25519_multicodec() {
    let did = did_key_from(&ED25519_MULTICODEC, &[0x11; 32]);
    let err = did_key_to_p256(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::UnsupportedMulticodec));
}

// ---------------------------------------------------------------------------
// Truncated / extended key payloads
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_truncated_ed25519_payload() {
    let did = did_key_from(&ED25519_MULTICODEC, &[0x11; 31]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(31)));
}

#[test]
fn decode_rejects_extended_ed25519_payload() {
    let did = did_key_from(&ED25519_MULTICODEC, &[0x11; 33]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(33)));
}

#[test]
fn decode_rejects_truncated_p256_payload() {
    let did = did_key_from(&P256_MULTICODEC, &[0x02; 32]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(32)));
}

#[test]
fn decode_rejects_extended_p256_payload() {
    let did = did_key_from(&P256_MULTICODEC, &[0x02; 34]);
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(34)));
}

#[test]
fn decode_rejects_empty_base58_payload() {
    let err = did_key_decode("did:key:z").unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(0)));
}

#[test]
fn decode_rejects_single_multicodec_byte_payload() {
    let did = format!("did:key:z{}", bs58::encode([0xEDu8]).into_string());
    let err = did_key_decode(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(1)));
}

#[test]
fn decode_rejects_string_truncated_did() {
    let valid = did_key_from(&ED25519_MULTICODEC, &[0x11; 32]);
    let truncated = &valid[..valid.len() - 4];
    assert!(did_key_decode(truncated).is_err());
}

#[test]
fn did_key_to_p256_rejects_truncated_payload() {
    let did = did_key_from(&P256_MULTICODEC, &[0x02; 32]);
    let err = did_key_to_p256(&did).unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidKeyLength(32)));
}

// ---------------------------------------------------------------------------
// Multibase / prefix violations
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_non_z_multibase_prefix() {
    let err =
        did_key_decode("did:key:f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidPrefix(_)));
}

#[test]
fn decode_rejects_missing_multibase_payload() {
    let err = did_key_decode("did:key:").unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidPrefix(_)));
}

#[test]
fn did_key_to_p256_rejects_non_z_prefix() {
    let err =
        did_key_to_p256("did:key:fDnaeUKTWUXc1HDpGfKbEK31nKLN19yX5aunFd7VK1CUMeyJu").unwrap_err();
    assert!(matches!(err, DidKeyError::InvalidPrefix(_)));
}

// ---------------------------------------------------------------------------
// Malformed base58
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_invalid_base58_characters() {
    let err = did_key_decode("did:key:z0OIl").unwrap_err();
    assert!(matches!(err, DidKeyError::Base58DecodeFailed(_)));
}

#[test]
fn did_key_to_p256_rejects_invalid_base58_characters() {
    let err = did_key_to_p256("did:key:z0OIl").unwrap_err();
    assert!(matches!(err, DidKeyError::Base58DecodeFailed(_)));
}
