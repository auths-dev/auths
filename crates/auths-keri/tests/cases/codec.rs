use auths_keri::{CesrCodec, CesrV1Codec, DigestType, KeyType, SigType};

#[test]
fn encode_pubkey_zero_bytes() {
    let codec = CesrV1Codec::new();
    let key_bytes = [0u8; 32];
    let encoded = codec.encode_pubkey(&key_bytes, KeyType::Ed25519).unwrap();
    assert_eq!(
        encoded, "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "32 zero-bytes must encode to the all-A CESR Ed25519 key"
    );
    assert_eq!(encoded.len(), 44);
}

#[test]
fn decode_pubkey_roundtrip() {
    let codec = CesrV1Codec::new();
    let key_bytes = [0u8; 32];
    let encoded = codec.encode_pubkey(&key_bytes, KeyType::Ed25519).unwrap();
    let decoded = codec.decode_qualified(&encoded).unwrap();
    assert_eq!(decoded.raw, key_bytes);
    assert_eq!(decoded.code, "D");
}

#[test]
fn encode_indexed_signature_format() {
    let codec = CesrV1Codec::new();
    let sig_bytes = [0u8; 64];
    let encoded = codec
        .encode_indexed_signature(&sig_bytes, SigType::Ed25519, 0)
        .unwrap();
    assert_eq!(
        encoded.len(),
        88,
        "Ed25519 indexed signature must be 88 chars"
    );
    assert!(
        encoded.starts_with("AA"),
        "Ed25519 indexed sig at index 0 must start with AA"
    );
}

#[test]
fn encode_digest_format() {
    let codec = CesrV1Codec::new();
    let digest_bytes = [0u8; 32];
    let encoded = codec
        .encode_digest(&digest_bytes, DigestType::Blake3_256)
        .unwrap();
    assert_eq!(encoded.len(), 44, "Blake3-256 digest must be 44 chars");
    assert!(
        encoded.starts_with('E'),
        "Blake3-256 digest must start with E"
    );
}

#[test]
fn encode_pubkey_nonzero_bytes() {
    let codec = CesrV1Codec::new();
    let key_bytes: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let encoded = codec.encode_pubkey(&key_bytes, KeyType::Ed25519).unwrap();
    assert_eq!(encoded.len(), 44);
    assert!(encoded.starts_with('D'));
    let decoded = codec.decode_qualified(&encoded).unwrap();
    assert_eq!(decoded.raw, key_bytes);
}

mod proptest_codec {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pubkey_roundtrip(key_bytes in proptest::collection::vec(any::<u8>(), 32)) {
            let codec = CesrV1Codec::new();
            let encoded = codec.encode_pubkey(&key_bytes, KeyType::Ed25519).unwrap();
            assert_eq!(encoded.len(), 44);
            assert!(encoded.starts_with('D'));
            let decoded = codec.decode_qualified(&encoded).unwrap();
            prop_assert_eq!(decoded.raw, key_bytes);
        }

        #[test]
        fn digest_roundtrip(digest_bytes in proptest::collection::vec(any::<u8>(), 32)) {
            let codec = CesrV1Codec::new();
            let encoded = codec.encode_digest(&digest_bytes, DigestType::Blake3_256).unwrap();
            assert_eq!(encoded.len(), 44);
            assert!(encoded.starts_with('E'));
            let decoded = codec.decode_qualified(&encoded).unwrap();
            prop_assert_eq!(decoded.raw, digest_bytes);
        }
    }
}
