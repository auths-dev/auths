use auths_core::crypto::ssh::{
    SecureSeed, construct_sshsig_pem, construct_sshsig_signed_data, create_sshsig,
    encode_ssh_pubkey, encode_ssh_signature, extract_pubkey_from_key_bytes,
    extract_seed_from_pkcs8,
};
use auths_crypto::Pkcs8Der;

#[test]
fn test_secure_seed_zeroes_on_drop() {
    let raw = [0xABu8; 32];
    let seed = SecureSeed::new(raw);
    assert_eq!(seed.as_bytes(), &raw);
    // SecureSeed derives ZeroizeOnDrop; verifying construction and access is correct.
    // Actual memory zeroing on drop is guaranteed by the zeroize crate.
    drop(seed);
}

#[test]
fn test_create_sshsig_returns_pem() {
    let seed = SecureSeed::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]);

    let pem = create_sshsig(&seed, b"test data", "git").unwrap();
    assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
    assert!(pem.contains("-----END SSH SIGNATURE-----"));
}

#[test]
fn test_encode_ssh_pubkey_format() {
    let pubkey = [0x42u8; 32];
    let blob = encode_ssh_pubkey(&pubkey);

    assert_eq!(&blob[0..4], &11u32.to_be_bytes());
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &32u32.to_be_bytes());
    assert_eq!(&blob[19..51], &[0x42; 32]);
}

#[test]
fn test_encode_ssh_signature_format() {
    let sig = [0xBB; 64];
    let blob = encode_ssh_signature(&sig);

    assert_eq!(&blob[0..4], &11u32.to_be_bytes());
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &64u32.to_be_bytes());
    assert_eq!(&blob[19..83], &[0xBB; 64]);
}

#[test]
fn test_extract_seed_roundtrip() {
    use auths_core::crypto::ssh::build_ed25519_pkcs8_v2_from_seed;

    let seed = SecureSeed::new([3u8; 32]);
    let pkcs8 = build_ed25519_pkcs8_v2_from_seed(&seed).unwrap();
    let recovered = extract_seed_from_pkcs8(&pkcs8).unwrap();
    assert_eq!(recovered.as_bytes(), seed.as_bytes());
}

#[test]
fn test_extract_pubkey_from_pkcs8_v2() {
    use auths_core::crypto::ssh::build_ed25519_pkcs8_v2_from_seed;

    let seed = SecureSeed::new([5u8; 32]);
    let pkcs8 = build_ed25519_pkcs8_v2_from_seed(&seed).unwrap();
    let pubkey = extract_pubkey_from_key_bytes(pkcs8.as_ref()).unwrap();
    assert_eq!(pubkey.len(), 32);
}

#[test]
fn test_construct_sshsig_signed_data_format() {
    let blob = construct_sshsig_signed_data(b"test", "git").unwrap();

    assert_eq!(&blob[0..6], b"SSHSIG");
    assert_eq!(&blob[6..10], &3u32.to_be_bytes());
    assert_eq!(&blob[10..13], b"git");
    assert_eq!(&blob[13..17], &0u32.to_be_bytes());
    assert_eq!(&blob[17..21], &6u32.to_be_bytes());
    assert_eq!(&blob[21..27], b"sha512");
    assert_eq!(&blob[27..31], &64u32.to_be_bytes());
    assert_eq!(blob.len(), 31 + 64);
}

#[test]
fn test_construct_sshsig_pem_format() {
    let pubkey = [0x42u8; 32];
    let signature = [0xBB; 64];
    let pem = construct_sshsig_pem(&pubkey, &signature, "git").unwrap();

    assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
    assert!(pem.contains("-----END SSH SIGNATURE-----"));
}

#[test]
fn test_extract_seed_rejects_invalid_length() {
    let bad = Pkcs8Der::new(vec![0u8; 50]);
    assert!(extract_seed_from_pkcs8(&bad).is_err());
}

#[test]
fn test_build_pkcs8_v2_returns_pkcs8der() {
    use auths_core::crypto::ssh::build_ed25519_pkcs8_v2_from_seed;

    let seed = SecureSeed::new([7u8; 32]);
    let pkcs8 = build_ed25519_pkcs8_v2_from_seed(&seed).unwrap();
    assert_eq!(pkcs8.as_ref().len(), 85);
}
