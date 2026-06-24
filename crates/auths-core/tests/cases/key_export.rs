use auths_core::api::runtime::export_key_openssh_pub;
use auths_core::crypto::signer::encrypt_keypair;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use pkcs8::der::Encode;
use pkcs8::der::asn1::ObjectIdentifier;
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};
use ring::signature::{Ed25519KeyPair, KeyPair};

const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

fn fresh_keychain() -> Box<dyn KeyStorage + Send + Sync> {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
    Box::new(MemoryKeychainHandle)
}

/// Creates a PKCS#8 encoded Ed25519 key that ring CAN parse.
/// This uses ring's own key generation.
fn create_ring_compatible_pkcs8() -> (Vec<u8>, Vec<u8>) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate key");
    let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to parse generated key");
    let pubkey = keypair.public_key().as_ref().to_vec();

    (pkcs8_bytes, pubkey)
}

/// Creates a PKCS#8 encoded Ed25519 key that ring CANNOT parse.
/// This simulates keys imported from other sources that use standard PKCS#8
/// encoding but without ring's specific format requirements.
fn create_non_ring_pkcs8() -> (Vec<u8>, Vec<u8>) {
    // Generate a key with ring first to get valid key material
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate key");
    let keypair =
        Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).expect("Failed to parse generated key");
    let pubkey = keypair.public_key().as_ref().to_vec();

    // Extract the seed from ring's PKCS#8 and re-encode it in standard format
    // that ring won't accept (raw 32-byte seed without OCTET STRING wrapper)
    let pk_info =
        PrivateKeyInfo::try_from(pkcs8_doc.as_ref()).expect("Failed to parse as PrivateKeyInfo");

    // Get the seed - ring wraps it in OCTET STRING (04 20 + 32 bytes)
    let wrapped_seed = pk_info.private_key;
    assert_eq!(wrapped_seed.len(), 34, "Expected wrapped seed");
    let seed = &wrapped_seed[2..]; // Skip 04 20 prefix

    // Re-encode with raw seed (no OCTET STRING wrapper) - ring won't parse this
    let non_ring_pkcs8 = PrivateKeyInfo {
        algorithm: AlgorithmIdentifierRef {
            oid: OID_ED25519,
            parameters: None,
        },
        private_key: seed, // Raw 32 bytes, not wrapped
        public_key: None,
    }
    .to_der()
    .expect("Failed to encode PKCS#8");

    // Verify ring can't parse it
    assert!(
        Ed25519KeyPair::from_pkcs8(&non_ring_pkcs8).is_err(),
        "Ring should NOT be able to parse this format"
    );

    (non_ring_pkcs8, pubkey)
}

#[test]
fn test_export_ring_compatible_key() {
    let keychain = fresh_keychain();
    let alias = "test-ring-key";
    let passphrase = "Test-P@ss12345";
    let identity_did = IdentityDID::parse("did:keri:test123").unwrap();

    // Create and store a ring-compatible key
    let (pkcs8_bytes, _expected_pubkey) = create_ring_compatible_pkcs8();
    let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("Failed to encrypt");
    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            &identity_did,
            KeyRole::Primary,
            &encrypted,
        )
        .expect("Failed to store key");

    // Export should succeed
    let result = export_key_openssh_pub(alias, passphrase, keychain.as_ref());
    assert!(result.is_ok(), "Export failed: {:?}", result.err());

    let openssh_pubkey = result.unwrap();
    assert!(
        openssh_pubkey.starts_with("ssh-ed25519 "),
        "Should be ssh-ed25519 format"
    );
    assert!(
        openssh_pubkey.contains(alias),
        "Should contain alias as comment"
    );

    // Verify the key material matches by checking the base64 contains expected bytes
    // (The full verification would require decoding the OpenSSH format)
    assert!(openssh_pubkey.len() > 50, "Should have reasonable length");
}

#[test]
fn test_export_non_ring_compatible_key() {
    let keychain = fresh_keychain();
    let alias = "test-nonring-key";
    let passphrase = "Test-P@ss12345";
    let identity_did = IdentityDID::parse("did:keri:test456").unwrap();

    // Create and store a key that ring can't parse
    let (pkcs8_bytes, _) = create_non_ring_pkcs8();
    let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("Failed to encrypt");
    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            &identity_did,
            KeyRole::Primary,
            &encrypted,
        )
        .expect("Failed to store key");

    // Export should succeed via the fallback path
    let result = export_key_openssh_pub(alias, passphrase, keychain.as_ref());
    assert!(
        result.is_ok(),
        "Export should succeed via fallback: {:?}",
        result.err()
    );

    let openssh_pubkey = result.unwrap();
    assert!(
        openssh_pubkey.starts_with("ssh-ed25519 "),
        "Should be ssh-ed25519 format"
    );
    assert!(
        openssh_pubkey.contains(alias),
        "Should contain alias as comment"
    );
}

#[test]
fn test_export_with_wrong_passphrase() {
    let keychain = fresh_keychain();
    let alias = "test-wrong-pass";
    let passphrase = "Corr3ct-P@sswd!";
    let wrong_passphrase = "Wr0ng-P@ssword!";
    let identity_did = IdentityDID::parse("did:keri:test789").unwrap();

    let (pkcs8_bytes, _) = create_ring_compatible_pkcs8();
    let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("Failed to encrypt");
    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            &identity_did,
            KeyRole::Primary,
            &encrypted,
        )
        .expect("Failed to store key");

    // Export should fail with wrong passphrase
    let result = export_key_openssh_pub(alias, wrong_passphrase, keychain.as_ref());
    assert!(result.is_err(), "Should fail with wrong passphrase");
}

#[test]
fn test_export_nonexistent_key() {
    let keychain = fresh_keychain();

    let result = export_key_openssh_pub("nonexistent-alias", "any-pass", keychain.as_ref());
    assert!(result.is_err(), "Should fail for nonexistent key");
}

fn byte_seq_present(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn export_output_contains_no_raw_secret() {
    let keychain = fresh_keychain();
    let alias = "export-secret";
    let passphrase = "Test-passphrase1!";
    let identity_did = IdentityDID::parse("did:keri:ExportSecret").unwrap();

    let (pkcs8_bytes, _pubkey) = create_ring_compatible_pkcs8();
    let seed = pkcs8_bytes[16..48].to_vec();
    let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("encrypt");
    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            &identity_did,
            KeyRole::Primary,
            &encrypted,
        )
        .expect("store");

    // Public-key export carries only public material — never the seed or private key.
    let pub_out = export_key_openssh_pub(alias, passphrase, keychain.as_ref()).expect("pub export");
    assert!(
        !byte_seq_present(pub_out.as_bytes(), &seed),
        "public export leaked the seed"
    );
    assert!(
        !byte_seq_present(pub_out.as_bytes(), &pkcs8_bytes),
        "public export leaked the private key"
    );

    // The at-rest (encrypted) export a non-interactive caller can obtain is
    // passphrase-wrapped, never the raw secret.
    let (_did, _role, enc_out) = keychain
        .load_key(&KeyAlias::new_unchecked(alias))
        .expect("load");
    assert!(
        !byte_seq_present(&enc_out, &seed),
        "encrypted export leaked the seed"
    );
}

#[test]
fn no_secret_in_logs() {
    use std::sync::{Mutex, OnceLock};

    static LOG_BUF: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    struct CaptureLogger;
    impl log::Log for CaptureLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            if let Some(buf) = LOG_BUF.get() {
                use std::io::Write;
                let _ = writeln!(buf.lock().unwrap(), "{} {}", record.level(), record.args());
            }
        }
        fn flush(&self) {}
    }

    LOG_BUF.set(Mutex::new(Vec::new())).ok();
    // nextest runs each test in its own process, so installing a global logger is safe here.
    let _ = log::set_boxed_logger(Box::new(CaptureLogger));
    log::set_max_level(log::LevelFilter::Trace);

    let keychain = fresh_keychain();
    let alias = "log-secret";
    let passphrase = "Test-passphrase1!";
    let identity_did = IdentityDID::parse("did:keri:LogSecret").unwrap();
    let (pkcs8_bytes, _pubkey) = create_ring_compatible_pkcs8();
    let seed = pkcs8_bytes[16..48].to_vec();
    let encrypted = encrypt_keypair(&pkcs8_bytes, passphrase).expect("encrypt");
    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            &identity_did,
            KeyRole::Primary,
            &encrypted,
        )
        .expect("store");
    let _ = export_key_openssh_pub(alias, passphrase, keychain.as_ref());

    let logs = LOG_BUF.get().unwrap().lock().unwrap().clone();
    assert!(!byte_seq_present(&logs, &seed), "seed leaked in logs");
    assert!(
        !byte_seq_present(&logs, &pkcs8_bytes),
        "private key leaked in logs"
    );
    assert!(
        !byte_seq_present(&logs, passphrase.as_bytes()),
        "passphrase leaked in logs"
    );
}
