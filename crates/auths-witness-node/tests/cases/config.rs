//! WitnessState construction and disk-persistence behaviour, plus the deploy
//! manifest's registry-mount default.

use auths_witness_node::cosign_role::WitnessState;
use axum::http::StatusCode;

use super::support::{make_checkpoint, post_checkpoint, test_config, tofu_request};

/// The deploy Compose file must default the registry mount, not hard-fail on an
/// unset var: `${WITNESS_REGISTRY:?…}` is evaluated during local YAML
/// interpolation, so it exits before Docker is even contacted — every first-run
/// operator's `docker compose up` fails on paste. A `:-` default plus the node's
/// readiness gate turns an empty default into a loud refusal, not that failure.
#[test]
fn compose_default_registry_interpolates_without_env() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let compose =
        std::fs::read_to_string(workspace_root.join("deploy/witness/docker-compose.yml")).unwrap();
    let registry_line = compose
        .lines()
        .find(|line| line.contains(":/registry:ro"))
        .expect("registry volume line present");
    assert!(
        registry_line.contains("${WITNESS_REGISTRY:-"),
        "registry mount must interpolate a default, got: {registry_line}"
    );
    assert!(
        !registry_line.contains(":?"),
        "registry mount must not hard-fail on an unset var, got: {registry_line}"
    );
}

#[test]
fn rejects_invalid_hex_signing_key() {
    let (mut config, _dir) = test_config();
    config.signing_key_hex = "not-hex-at-all".into();
    assert!(WitnessState::new(&config).is_err());
}

#[test]
fn rejects_garbage_pkcs8_signing_key() {
    let (mut config, _dir) = test_config();
    config.signing_key_hex = hex::encode([0u8; 40]);
    assert!(WitnessState::new(&config).is_err());
}

#[test]
fn rejects_raw_seed_signing_key() {
    let (mut config, _dir) = test_config();
    config.signing_key_hex = hex::encode([7u8; 32]);
    assert!(WitnessState::new(&config).is_err());
}

#[test]
fn rejects_empty_signing_key() {
    let (mut config, _dir) = test_config();
    config.signing_key_hex = String::new();
    assert!(WitnessState::new(&config).is_err());
}

#[test]
fn accepts_generated_pkcs8_signing_key() {
    let (config, _dir) = test_config();
    assert!(WitnessState::new(&config).is_ok());
}

#[tokio::test]
async fn restores_last_checkpoint_from_disk_and_enforces_no_rollback() {
    let (config, _dir) = test_config();

    let state = WitnessState::new(&config).unwrap();
    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(10, [0xaa; 32]))).await;
    assert_eq!(status, StatusCode::OK);

    let restarted = WitnessState::new(&config).unwrap();
    let (status, _) =
        post_checkpoint(restarted, &tofu_request(make_checkpoint(5, [0xbb; 32]))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn detects_equivocation_across_restart() {
    let (config, _dir) = test_config();

    let state = WitnessState::new(&config).unwrap();
    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(10, [0xaa; 32]))).await;
    assert_eq!(status, StatusCode::OK);

    let restarted = WitnessState::new(&config).unwrap();
    let (status, _) =
        post_checkpoint(restarted, &tofu_request(make_checkpoint(10, [0xbb; 32]))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn corrupt_checkpoint_file_falls_back_to_tofu() {
    let (config, _dir) = test_config();
    std::fs::write(&config.checkpoint_path, "not valid json {").unwrap();

    let state = WitnessState::new(&config).unwrap();
    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(7, [0xcc; 32]))).await;
    assert_eq!(status, StatusCode::OK);
}
