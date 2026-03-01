use auths_id::storage::attestation::{AttestationSource, GitAttestationStorage};
use auths_id::storage::identity::{GitIdentityStorage, IdentityStorage};
use auths_id::storage::layout::StorageLayoutConfig;
use auths_id::storage::layout::{attestation_ref_for_device, identity_ref};
use auths_verifier::types::DeviceDID;
use tempfile::tempdir;

/// Test that the default preset produces the expected ref paths.
#[test]
fn test_default_preset_ref_paths() {
    let config = StorageLayoutConfig::default();

    // Verify identity ref
    assert_eq!(
        identity_ref(&config),
        "refs/auths/identity",
        "Default preset should use refs/auths/identity"
    );

    // Verify attestation ref path
    let device_did = DeviceDID::new("did:key:z6MkTest123");
    let attestation_ref = attestation_ref_for_device(&config, &device_did);
    assert!(
        attestation_ref.starts_with("refs/auths/devices/nodes/"),
        "Default preset attestation ref should start with refs/auths/devices/nodes/"
    );
    assert!(
        attestation_ref.ends_with("/signatures"),
        "Attestation ref should end with /signatures"
    );

    // Verify blob names
    assert_eq!(
        config.attestation_blob_name, "attestation.json",
        "Default preset should use attestation.json"
    );
    assert_eq!(
        config.identity_blob_name, "identity.json",
        "Default preset should use identity.json"
    );
}

/// Test that the radicle preset produces Radicle-compatible ref paths.
#[test]
fn test_radicle_preset_ref_paths() {
    let config = StorageLayoutConfig::radicle();

    // Verify identity ref
    assert_eq!(
        identity_ref(&config),
        "refs/rad/id",
        "Radicle preset should use refs/rad/id"
    );

    // Verify attestation ref path
    let device_did = DeviceDID::new("did:key:z6MkTest456");
    let attestation_ref = attestation_ref_for_device(&config, &device_did);
    assert!(
        attestation_ref.starts_with("refs/rad/multidevice/nodes/"),
        "Radicle preset attestation ref should start with refs/rad/multidevice/nodes/"
    );
    assert!(
        attestation_ref.ends_with("/signatures"),
        "Attestation ref should end with /signatures"
    );

    // Verify blob names
    assert_eq!(
        config.attestation_blob_name, "link-attestation.json",
        "Radicle preset should use link-attestation.json"
    );
    assert_eq!(
        config.identity_blob_name, "radicle-identity.json",
        "Radicle preset should use radicle-identity.json"
    );
}

/// Test that the gitoxide preset produces gitoxide-compatible ref paths.
#[test]
fn test_gitoxide_preset_ref_paths() {
    let config = StorageLayoutConfig::gitoxide();

    // Verify identity ref
    assert_eq!(
        identity_ref(&config),
        "refs/auths/id",
        "Gitoxide preset should use refs/auths/id"
    );

    // Verify attestation ref path
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

    // Verify blob names (standard names for gitoxide)
    assert_eq!(
        config.attestation_blob_name, "attestation.json",
        "Gitoxide preset should use attestation.json"
    );
    assert_eq!(
        config.identity_blob_name, "identity.json",
        "Gitoxide preset should use identity.json"
    );
}

/// Test that presets can be overridden with explicit values.
#[test]
fn test_preset_override() {
    // Start with radicle preset
    let mut config = StorageLayoutConfig::radicle();
    assert_eq!(config.identity_ref, "refs/rad/id");

    // Override identity ref
    config.identity_ref = "refs/custom/identity".to_string();
    assert_eq!(
        identity_ref(&config),
        "refs/custom/identity",
        "Override should take precedence over preset"
    );

    // Verify other fields still have preset values
    assert_eq!(
        config.attestation_blob_name, "link-attestation.json",
        "Non-overridden fields should retain preset values"
    );
}

/// Test that storage layer respects preset configuration.
#[test]
fn test_preset_storage_layer_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = temp_dir.path();

    // Initialize Git repo
    git2::Repository::init(repo_path).expect("Failed to init Git repo");

    // Test with radicle preset
    let radicle_config = StorageLayoutConfig::radicle();
    let identity_storage = GitIdentityStorage::new(repo_path, radicle_config.clone());
    let attestation_storage = GitAttestationStorage::new(repo_path, radicle_config.clone());

    // Verify the storage uses the correct ref path
    let identity_ref_result = identity_storage.get_identity_ref();
    assert!(
        identity_ref_result.is_ok(),
        "Should be able to get identity ref"
    );
    assert_eq!(
        identity_ref_result.unwrap(),
        "refs/rad/id",
        "Identity storage should use radicle identity ref"
    );

    // Verify attestation storage is initialized with radicle config
    // (the storage won't have any attestations yet, but it should be configured correctly)
    let discovered = attestation_storage.discover_device_dids();
    // Should return empty vec (no attestations yet) but not error
    assert!(
        discovered.is_ok(),
        "Discovery should succeed even with no attestations"
    );
    assert!(
        discovered.unwrap().is_empty(),
        "Should have no attestations initially"
    );
}

/// Test all presets produce unique configurations.
#[test]
fn test_presets_are_distinct() {
    let default = StorageLayoutConfig::default();
    let radicle = StorageLayoutConfig::radicle();
    let gitoxide = StorageLayoutConfig::gitoxide();

    // Identity refs should all be different
    assert_ne!(
        default.identity_ref, radicle.identity_ref,
        "Default and Radicle should have different identity refs"
    );
    assert_ne!(
        default.identity_ref, gitoxide.identity_ref,
        "Default and Gitoxide should have different identity refs"
    );
    assert_ne!(
        radicle.identity_ref, gitoxide.identity_ref,
        "Radicle and Gitoxide should have different identity refs"
    );

    // Attestation prefixes should differ between presets
    assert_ne!(
        default.device_attestation_prefix, radicle.device_attestation_prefix,
        "Default and Radicle should have different attestation prefixes"
    );
}
