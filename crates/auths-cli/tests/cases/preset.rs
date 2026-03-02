use auths_id::storage::attestation::{AttestationSource, GitAttestationStorage};
use auths_id::storage::identity::{GitIdentityStorage, IdentityStorage};
use auths_id::storage::layout::StorageLayoutConfig;
use auths_id::storage::layout::{attestation_ref_for_device, identity_ref};
use auths_verifier::types::DeviceDID;
use tempfile::tempdir;

/// Default is now the RIP-X (Radicle) layout.
#[test]
fn test_default_is_radicle() {
    let config = StorageLayoutConfig::default();

    assert_eq!(identity_ref(&config), "refs/rad/id");

    let device_did = DeviceDID::new("did:key:z6MkTest123");
    let attestation_ref = attestation_ref_for_device(&config, &device_did);
    assert!(
        attestation_ref.starts_with("refs/keys/"),
        "Default attestation ref should start with refs/keys/"
    );
    assert!(
        attestation_ref.ends_with("/signatures"),
        "Attestation ref should end with /signatures"
    );

    assert_eq!(config.attestation_blob_name, "link-attestation.json");
    assert_eq!(config.identity_blob_name, "radicle-identity.json");
}

/// `radicle()` is an alias for `default()`.
#[test]
fn test_radicle_equals_default() {
    assert_eq!(
        StorageLayoutConfig::radicle(),
        StorageLayoutConfig::default()
    );
}

/// Gitoxide preset produces gitoxide-compatible ref paths.
#[test]
fn test_gitoxide_preset_ref_paths() {
    let config = StorageLayoutConfig::gitoxide();

    assert_eq!(identity_ref(&config), "refs/auths/id");

    let device_did = DeviceDID::new("did:key:z6MkTest789");
    let attestation_ref = attestation_ref_for_device(&config, &device_did);
    assert!(
        attestation_ref.starts_with("refs/auths/devices/"),
        "Gitoxide preset attestation ref should start with refs/auths/devices/"
    );
    assert!(
        attestation_ref.ends_with("/signatures"),
        "Attestation ref should end with /signatures"
    );

    assert_eq!(config.attestation_blob_name, "attestation.json");
    assert_eq!(config.identity_blob_name, "identity.json");
}

/// Presets can be overridden with explicit values.
#[test]
fn test_preset_override() {
    let mut config = StorageLayoutConfig::default();
    assert_eq!(config.identity_ref, "refs/rad/id");

    config.identity_ref = "refs/custom/identity".to_string();
    assert_eq!(
        identity_ref(&config),
        "refs/custom/identity",
        "Override should take precedence over preset"
    );

    assert_eq!(
        config.attestation_blob_name, "link-attestation.json",
        "Non-overridden fields should retain preset values"
    );
}

/// Storage layer respects preset configuration.
#[test]
fn test_preset_storage_layer_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = temp_dir.path();

    git2::Repository::init(repo_path).expect("Failed to init Git repo");

    let config = StorageLayoutConfig::default();
    let identity_storage = GitIdentityStorage::new(repo_path, config.clone());
    let attestation_storage = GitAttestationStorage::new(repo_path, config.clone());

    let identity_ref_result = identity_storage.get_identity_ref();
    assert!(identity_ref_result.is_ok());
    assert_eq!(identity_ref_result.unwrap(), "refs/rad/id");

    let discovered = attestation_storage.discover_device_dids();
    assert!(discovered.is_ok());
    assert!(discovered.unwrap().is_empty());
}

/// Default and gitoxide are distinct presets.
#[test]
fn test_default_and_gitoxide_are_distinct() {
    let default = StorageLayoutConfig::default();
    let gitoxide = StorageLayoutConfig::gitoxide();

    assert_ne!(
        default.identity_ref, gitoxide.identity_ref,
        "Default and Gitoxide should have different identity refs"
    );
    assert_ne!(
        default.device_attestation_prefix, gitoxide.device_attestation_prefix,
        "Default and Gitoxide should have different attestation prefixes"
    );
}
