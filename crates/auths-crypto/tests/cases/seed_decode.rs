use auths_crypto::{SeedDecodeError, decode_seed_hex};

#[test]
fn decode_valid_64_hex_chars() {
    let hex = "aa".repeat(32);
    let seed = decode_seed_hex(&hex).unwrap();
    assert_eq!(seed.as_bytes(), &[0xaa; 32]);
}

#[test]
fn decode_rejects_invalid_hex() {
    let result = decode_seed_hex("zzzz");
    assert!(matches!(result, Err(SeedDecodeError::InvalidHex(_))));
}

#[test]
fn decode_rejects_too_short() {
    let hex = "aa".repeat(16);
    let result = decode_seed_hex(&hex);
    match result {
        Err(SeedDecodeError::WrongLength {
            expected: 32,
            got: 16,
        }) => {}
        other => panic!("expected WrongLength(32, 16), got {other:?}"),
    }
}

#[test]
fn decode_rejects_too_long() {
    let hex = "aa".repeat(64);
    let result = decode_seed_hex(&hex);
    match result {
        Err(SeedDecodeError::WrongLength {
            expected: 32,
            got: 64,
        }) => {}
        other => panic!("expected WrongLength(32, 64), got {other:?}"),
    }
}

#[test]
fn decode_rejects_empty_string() {
    let result = decode_seed_hex("");
    match result {
        Err(SeedDecodeError::WrongLength {
            expected: 32,
            got: 0,
        }) => {}
        other => panic!("expected WrongLength(32, 0), got {other:?}"),
    }
}

#[test]
fn decode_rejects_odd_length_hex() {
    let result = decode_seed_hex("abc");
    assert!(matches!(result, Err(SeedDecodeError::InvalidHex(_))));
}
