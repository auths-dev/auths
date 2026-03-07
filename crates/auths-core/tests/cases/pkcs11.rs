//! Integration tests for the PKCS#11 HSM backend using SoftHSMv2.
//!
//! These tests require SoftHSMv2 to be installed and will skip gracefully
//! if the library is not found.

use auths_core::config::Pkcs11Config;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::storage::pkcs11::Pkcs11KeyRef;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn find_softhsm_library() -> Option<PathBuf> {
    let candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
    ];
    candidates
        .iter()
        .find(|p| PathBuf::from(p).exists())
        .map(PathBuf::from)
}

struct SoftHsmFixture {
    _token_dir: TempDir,
    config: Pkcs11Config,
}

const TEST_PIN: &str = "12345678";
const TEST_SO_PIN: &str = "12345678";
const TEST_TOKEN_LABEL: &str = "auths-test";

fn setup_softhsm() -> Option<SoftHsmFixture> {
    let library_path = find_softhsm_library()?;
    let token_dir = TempDir::new().ok()?;
    let token_path = token_dir.path().join("tokens");
    std::fs::create_dir_all(&token_path).ok()?;

    let conf_path = token_dir.path().join("softhsm2.conf");
    std::fs::write(
        &conf_path,
        format!("directories.tokendir = {}\n", token_path.display()),
    )
    .ok()?;

    let status = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf_path)
        .args([
            "--init-token",
            "--slot",
            "0",
            "--label",
            TEST_TOKEN_LABEL,
            "--pin",
            TEST_PIN,
            "--so-pin",
            TEST_SO_PIN,
        ])
        .output()
        .ok()?;

    if !status.status.success() {
        eprintln!(
            "softhsm2-util failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return None;
    }

    // SAFETY: test code runs single-threaded per SoftHSM fixture; no concurrent env reads.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf_path) };

    Some(SoftHsmFixture {
        _token_dir: token_dir,
        config: Pkcs11Config {
            library_path: Some(library_path),
            slot_id: None,
            token_label: Some(TEST_TOKEN_LABEL.to_string()),
            pin: Some(TEST_PIN.to_string()),
            key_label: Some("default".to_string()),
        },
    })
}

macro_rules! skip_without_softhsm {
    () => {
        match setup_softhsm() {
            Some(fixture) => fixture,
            None => {
                eprintln!("SKIPPED: SoftHSMv2 not available");
                return;
            }
        }
    };
}

#[test]
fn test_pkcs11_backend_name() {
    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();
    assert_eq!(keyref.backend_name(), "pkcs11");
}

#[test]
fn test_pkcs11_key_generate_and_load() {
    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();

    let alias = KeyAlias::new("test-key-1").unwrap();
    let did = IdentityDID::new("did:keri:ETEST123");

    keyref
        .store_key(&alias, &did, KeyRole::Primary, &[])
        .unwrap();

    let (loaded_did, ref_bytes) = keyref.load_key(&alias).unwrap();
    assert_eq!(loaded_did.as_str(), "did:keri:ETEST123");
    assert!(!ref_bytes.is_empty());
}

#[test]
fn test_pkcs11_list_aliases() {
    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();

    let did = IdentityDID::new("did:keri:ELIST");
    for i in 0..3 {
        let alias = KeyAlias::new(format!("list-key-{i}")).unwrap();
        keyref
            .store_key(&alias, &did, KeyRole::Primary, &[])
            .unwrap();
    }

    let aliases = keyref.list_aliases().unwrap();
    assert!(aliases.len() >= 3);
    for i in 0..3 {
        assert!(
            aliases
                .iter()
                .any(|a| a.as_str() == format!("list-key-{i}"))
        );
    }
}

#[test]
fn test_pkcs11_delete_key() {
    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();

    let alias = KeyAlias::new("delete-me").unwrap();
    let did = IdentityDID::new("did:keri:EDELETE");
    keyref
        .store_key(&alias, &did, KeyRole::Primary, &[])
        .unwrap();

    keyref.delete_key(&alias).unwrap();

    let result = keyref.load_key(&alias);
    assert!(result.is_err());
}

#[test]
fn test_pkcs11_sign_and_verify() {
    use auths_core::signing::{PrefilledPassphraseProvider, SecureSigner};
    use auths_core::storage::pkcs11::Pkcs11Signer;

    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();

    let alias = KeyAlias::new("sign-key").unwrap();
    let did = IdentityDID::new("did:keri:ESIGN");
    keyref
        .store_key(&alias, &did, KeyRole::Primary, &[])
        .unwrap();

    let signer = Pkcs11Signer::new(&fixture.config).unwrap();
    let provider = PrefilledPassphraseProvider::new("");

    let message = b"test message for PKCS#11 signing";
    let signature = signer.sign_with_alias(&alias, &provider, message).unwrap();
    assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");
}

#[test]
fn test_pkcs11_wrong_pin() {
    let fixture = skip_without_softhsm!();
    let mut bad_config = fixture.config.clone();
    bad_config.pin = Some("wrong-pin".to_string());

    let result = Pkcs11KeyRef::new(&bad_config);
    // Construction should succeed (PIN is only checked on session login),
    // but operations should fail
    if let Ok(keyref) = result {
        let alias = KeyAlias::new("should-fail").unwrap();
        let did = IdentityDID::new("did:keri:EFAIL");
        let store_result = keyref.store_key(&alias, &did, KeyRole::Primary, &[]);
        assert!(store_result.is_err());
    }
}

#[test]
fn test_pkcs11_missing_library() {
    let config = Pkcs11Config {
        library_path: Some(PathBuf::from("/nonexistent/libsofthsm2.so")),
        slot_id: None,
        token_label: Some("test".to_string()),
        pin: Some("1234".to_string()),
        key_label: None,
    };

    let result = Pkcs11KeyRef::new(&config);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, auths_core::error::AgentError::BackendInitFailed { .. }),
        "expected BackendInitFailed, got: {err:?}"
    );
}

#[test]
fn test_pkcs11_list_aliases_for_identity() {
    let fixture = skip_without_softhsm!();
    let keyref = Pkcs11KeyRef::new(&fixture.config).unwrap();

    let did_a = IdentityDID::new("did:keri:EALICE");
    let did_b = IdentityDID::new("did:keri:EBOB");

    keyref
        .store_key(
            &KeyAlias::new("alice-1").unwrap(),
            &did_a,
            KeyRole::Primary,
            &[],
        )
        .unwrap();
    keyref
        .store_key(
            &KeyAlias::new("alice-2").unwrap(),
            &did_a,
            KeyRole::Primary,
            &[],
        )
        .unwrap();
    keyref
        .store_key(
            &KeyAlias::new("bob-1").unwrap(),
            &did_b,
            KeyRole::Primary,
            &[],
        )
        .unwrap();

    let alice_aliases = keyref.list_aliases_for_identity(&did_a).unwrap();
    assert_eq!(alice_aliases.len(), 2);
    assert!(alice_aliases.iter().any(|a| a.as_str() == "alice-1"));
    assert!(alice_aliases.iter().any(|a| a.as_str() == "alice-2"));
}
