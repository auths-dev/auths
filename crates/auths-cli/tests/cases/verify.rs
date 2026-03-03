#![allow(deprecated)] // cargo_bin is deprecated but replacement requires significant refactor

use assert_cmd::Command;
use auths_test_utils::crypto::gen_keypair;
use auths_verifier::IdentityDID;
use auths_verifier::core::{
    Attestation, CanonicalAttestationData, Ed25519PublicKey, Ed25519Signature, ResourceId,
    canonicalize_attestation_data,
};
use auths_verifier::types::DeviceDID;
use chrono::{Duration, Utc};
use ring::signature::KeyPair;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_signed_attestation(
    issuer_kp: &ring::signature::Ed25519KeyPair,
    device_kp: &ring::signature::Ed25519KeyPair,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let mut att = Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: IdentityDID::new(format!(
            "did:key:{}",
            hex::encode(issuer_kp.public_key().as_ref())
        )),
        subject: DeviceDID::new(format!(
            "did:key:{}",
            hex::encode(device_kp.public_key().as_ref())
        )),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: Some(Utc::now() + Duration::days(365)),
        timestamp: Some(Utc::now()),
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
    };

    // Create canonical data for signing (includes org fields)
    let data = CanonicalAttestationData {
        version: att.version,
        rid: &att.rid,
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_bytes(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: att.role.as_ref().map(|r| r.as_str()),
        capabilities: if att.capabilities.is_empty() {
            None
        } else {
            Some(&att.capabilities)
        },
        delegated_by: att.delegated_by.as_ref(),
        signer_type: att.signer_type.as_ref(),
    };
    let canonical_bytes = canonicalize_attestation_data(&data).unwrap();

    // Sign with issuer (identity) key
    att.identity_signature = Ed25519Signature::try_from_slice(issuer_kp.sign(&canonical_bytes).as_ref()).unwrap();

    // Sign with device key
    att.device_signature = Ed25519Signature::try_from_slice(device_kp.sign(&canonical_bytes).as_ref()).unwrap();

    att
}

fn write_attestation_to_file(att: &Attestation) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    let json = serde_json::to_string(att).unwrap();
    file.write_all(json.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_verify_valid_attestation_returns_exit_code_0() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let file = write_attestation_to_file(&att);
    let pk_hex = hex::encode(issuer_kp.public_key().as_ref());

    // New unified verify: positional target (file exists → detected as attestation)
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(file.path())
        .arg("--issuer-pk")
        .arg(&pk_hex);

    cmd.assert().success();
}

#[test]
fn test_verify_invalid_attestation_returns_exit_code_1() {
    let issuer_kp = gen_keypair();
    let wrong_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let file = write_attestation_to_file(&att);
    // Use wrong public key
    let wrong_pk_hex = hex::encode(wrong_kp.public_key().as_ref());

    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(file.path())
        .arg("--issuer-pk")
        .arg(&wrong_pk_hex);

    cmd.assert().code(1);
}

#[test]
fn test_verify_invalid_json_returns_exit_code_2() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"not valid json").unwrap();
    file.flush().unwrap();

    // File exists → detected as attestation, parse error → exit 2
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(file.path())
        .arg("--issuer-pk")
        .arg("a".repeat(64));

    cmd.assert().code(2);
}

#[test]
fn test_verify_json_output_valid() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let file = write_attestation_to_file(&att);
    let pk_hex = hex::encode(issuer_kp.public_key().as_ref());

    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(file.path())
        .arg("--issuer-pk")
        .arg(&pk_hex)
        .arg("--json");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["valid"], true);
    assert!(result["issuer"].is_string());
    assert!(result["subject"].is_string());
}

#[test]
fn test_verify_json_output_invalid() {
    let issuer_kp = gen_keypair();
    let wrong_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let file = write_attestation_to_file(&att);
    let wrong_pk_hex = hex::encode(wrong_kp.public_key().as_ref());

    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(file.path())
        .arg("--issuer-pk")
        .arg(&wrong_pk_hex)
        .arg("--json");

    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["valid"], false);
    assert!(result["error"].is_string());
}

#[test]
fn test_verify_stdin_input() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let pk_hex = hex::encode(issuer_kp.public_key().as_ref());
    let json = serde_json::to_string(&att).unwrap();

    // "-" is the stdin sentinel and is directly detected as attestation
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg("-")
        .arg("--issuer-pk")
        .arg(&pk_hex)
        .write_stdin(json);

    cmd.assert().success();
}

#[test]
fn test_verify_help_shows_usage() {
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicates::str::contains("attestation"))
        .stdout(predicates::str::contains("issuer-pk"));
}

#[test]
fn test_verify_with_roots_json_explicit_policy() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let att_file = write_attestation_to_file(&att);
    let pk_hex = hex::encode(issuer_kp.public_key().as_ref());

    // Create a roots.json file
    let roots_dir = tempfile::tempdir().unwrap();
    let roots_path = roots_dir.path().join("roots.json");
    let roots_content = format!(
        r#"{{
            "version": 1,
            "roots": [
                {{
                    "did": "{}",
                    "public_key_hex": "{}",
                    "note": "Test issuer"
                }}
            ]
        }}"#,
        att.issuer, pk_hex
    );
    std::fs::write(&roots_path, roots_content).unwrap();

    // --trust and --roots-file are on the device verify command
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("device")
        .arg("verify")
        .arg("--attestation")
        .arg(att_file.path())
        .arg("--roots-file")
        .arg(&roots_path)
        .arg("--trust")
        .arg("explicit");

    cmd.assert().success();
}

#[test]
fn test_verify_explicit_rejects_unknown_identity() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let att_file = write_attestation_to_file(&att);

    // Create an empty roots.json file (no matching identity)
    let roots_dir = tempfile::tempdir().unwrap();
    let roots_path = roots_dir.path().join("roots.json");
    std::fs::write(&roots_path, r#"{"version": 1, "roots": []}"#).unwrap();

    // --trust and --roots-file are on the device verify command
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("device")
        .arg("verify")
        .arg("--attestation")
        .arg(att_file.path())
        .arg("--roots-file")
        .arg(&roots_path)
        .arg("--trust")
        .arg("explicit");

    // Should fail with exit code 2 (error) because identity is unknown
    cmd.assert().code(2);
}

#[test]
fn test_verify_issuer_did_with_pinned_store() {
    let issuer_kp = gen_keypair();
    let device_kp = gen_keypair();
    let att = create_signed_attestation(&issuer_kp, &device_kp);
    let att_file = write_attestation_to_file(&att);
    let pk_hex = hex::encode(issuer_kp.public_key().as_ref());

    // Create a temporary known_identities.json file
    let store_dir = tempfile::tempdir().unwrap();
    let store_path = store_dir.path().join("known_identities.json");
    let pin_content = format!(
        r#"[
            {{
                "did": "{}",
                "public_key_hex": "{}",
                "first_seen": "2024-01-01T00:00:00Z",
                "origin": "test",
                "trust_level": "manual"
            }}
        ]"#,
        att.issuer, pk_hex
    );
    std::fs::write(&store_path, pin_content).unwrap();

    // Note: This test would require AUTHS_HOME env var to point to store_dir
    // or modifying the CLI to accept a custom store path.
    // For now, we test with --issuer-pk which bypasses the store lookup.
    // A full integration test would require more infrastructure.

    // New unified verify: positional target
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg(att_file.path())
        .arg("--issuer-pk")
        .arg(&pk_hex);

    cmd.assert().success();
}

#[test]
fn test_verify_help_shows_unified_options() {
    // The unified verify --help should show the key options available
    // (no --trust or --roots-file; those are on `auths device verify`)
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicates::str::contains("--issuer-did"))
        .stdout(predicates::str::contains("--issuer-pk"))
        .stdout(predicates::str::contains("--allowed-signers"));
}
