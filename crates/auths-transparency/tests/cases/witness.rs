use async_trait::async_trait;
use auths_transparency::TransparencyError;
use auths_transparency::checkpoint::{Checkpoint, SignedCheckpoint, WitnessCosignature};
use auths_transparency::types::{LogOrigin, MerkleHash};
use auths_transparency::witness::{
    ALG_COSIGNATURE_V1, CosignRequest, CosignResponse, DEFAULT_WITNESS_TIMEOUT, WitnessClient,
    WitnessResult, build_cosignature_line, collect_witness_cosignatures, compute_witness_key_id,
    cosignature_signed_message, extract_cosignatures, parse_cosignature, serialize_cosignature,
};
use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
use chrono::{DateTime, Utc};
use std::time::Duration;

fn fixed_ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn make_test_checkpoint() -> SignedCheckpoint {
    SignedCheckpoint {
        checkpoint: Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size: 10,
            root: MerkleHash::from_bytes([0x01; 32]),
            timestamp: fixed_ts(),
        },
        log_signature: Ed25519Signature::from_bytes([0xcc; 64]),
        log_public_key: Ed25519PublicKey::from_bytes([0xdd; 32]),
        witnesses: vec![],
        ecdsa_checkpoint_signature: None,
        ecdsa_checkpoint_key: None,
    }
}

struct MockWitness {
    name: String,
    should_fail: bool,
    delay: Option<Duration>,
}

#[async_trait]
impl WitnessClient for MockWitness {
    async fn submit_checkpoint(
        &self,
        _request: CosignRequest,
    ) -> Result<CosignResponse, TransparencyError> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        if self.should_fail {
            return Err(TransparencyError::ConsistencyError("mock failure".into()));
        }
        Ok(CosignResponse {
            cosignature: WitnessCosignature {
                witness_name: self.name.clone(),
                witness_public_key: Ed25519PublicKey::from_bytes([0xaa; 32]),
                signature: Ed25519Signature::from_bytes([0xbb; 64]),
                timestamp: fixed_ts(),
            },
        })
    }
}

#[test]
fn cosignature_serialization_roundtrip() {
    let cosig = WitnessCosignature {
        witness_name: "witness-alpha".into(),
        witness_public_key: Ed25519PublicKey::from_bytes([0x11; 32]),
        signature: Ed25519Signature::from_bytes([0x22; 64]),
        timestamp: fixed_ts(),
    };

    let raw = serialize_cosignature(&cosig);
    assert_eq!(raw.len(), 72);

    let parsed = parse_cosignature(
        "witness-alpha",
        Ed25519PublicKey::from_bytes([0x11; 32]),
        &raw,
    )
    .unwrap();
    assert_eq!(parsed.witness_name, "witness-alpha");
    assert_eq!(parsed.timestamp, fixed_ts());
    assert_eq!(parsed.signature.as_bytes(), cosig.signature.as_bytes());
    assert_eq!(
        parsed.witness_public_key.as_bytes(),
        cosig.witness_public_key.as_bytes()
    );
}

#[test]
fn witness_key_id_uses_algorithm_byte_0x04() {
    let pubkey = [0xab; 32];
    let witness_id = compute_witness_key_id("w1", &pubkey);
    let note_id = auths_transparency::note::compute_key_id("w1", &pubkey);
    assert_ne!(
        witness_id, note_id,
        "witness key ID (alg 0x04) must differ from note key ID (alg 0x01)"
    );
}

#[test]
fn cosignature_signed_message_follows_spec() {
    let body = "auths.dev/log\n100\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    let ts = 1_700_000_000u64;
    let msg = cosignature_signed_message(body, ts);
    let msg_str = String::from_utf8(msg).unwrap();

    let expected_prefix = "cosignature/v1\ntime 1700000000\n";
    assert!(msg_str.starts_with(expected_prefix));
    assert!(msg_str.ends_with(body));
    assert_eq!(msg_str.len(), expected_prefix.len() + body.len());
}

#[test]
fn cosignature_line_encodes_timestamp_in_payload() {
    let key_id = [0x01, 0x02, 0x03, 0x04];
    let sig = [0xff; 64];
    let ts = 1_700_000_000u64;
    let line = build_cosignature_line("w1", &key_id, ts, &sig);

    use base64::{Engine, engine::general_purpose::STANDARD};
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    let decoded = STANDARD.decode(parts[2]).unwrap();

    assert_eq!(decoded[0], ALG_COSIGNATURE_V1);
    assert_eq!(&decoded[1..5], &key_id);
    // 8-byte timestamp
    let ts_bytes: [u8; 8] = decoded[5..13].try_into().unwrap();
    assert_eq!(u64::from_be_bytes(ts_bytes), ts);
    // 64-byte signature
    assert_eq!(&decoded[13..], &sig);
    // Total: 1 + 4 + 8 + 64 = 77 bytes
    assert_eq!(decoded.len(), 77);
}

#[tokio::test]
async fn collect_cosignatures_quorum_met() {
    let witnesses: Vec<Box<dyn WitnessClient>> = vec![
        Box::new(MockWitness {
            name: "w1".into(),
            should_fail: false,
            delay: None,
        }),
        Box::new(MockWitness {
            name: "w2".into(),
            should_fail: false,
            delay: None,
        }),
        Box::new(MockWitness {
            name: "w3".into(),
            should_fail: true,
            delay: None,
        }),
    ];

    let request = CosignRequest {
        old_size: 0,
        consistency_proof: None,
        signed_checkpoint: make_test_checkpoint(),
    };

    let results =
        collect_witness_cosignatures(&witnesses, request, 2, DEFAULT_WITNESS_TIMEOUT).await;
    let (cosigs, met) = extract_cosignatures(&results, 2);
    assert!(met);
    assert_eq!(cosigs.len(), 2);
}

#[tokio::test]
async fn collect_cosignatures_quorum_not_met() {
    let witnesses: Vec<Box<dyn WitnessClient>> = vec![
        Box::new(MockWitness {
            name: "w1".into(),
            should_fail: true,
            delay: None,
        }),
        Box::new(MockWitness {
            name: "w2".into(),
            should_fail: true,
            delay: None,
        }),
        Box::new(MockWitness {
            name: "w3".into(),
            should_fail: false,
            delay: None,
        }),
    ];

    let request = CosignRequest {
        old_size: 0,
        consistency_proof: None,
        signed_checkpoint: make_test_checkpoint(),
    };

    let results =
        collect_witness_cosignatures(&witnesses, request, 2, DEFAULT_WITNESS_TIMEOUT).await;
    let (cosigs, met) = extract_cosignatures(&results, 2);
    assert!(!met);
    assert_eq!(cosigs.len(), 1);
}

#[tokio::test]
async fn collect_cosignatures_handles_timeout() {
    let witnesses: Vec<Box<dyn WitnessClient>> = vec![
        Box::new(MockWitness {
            name: "w1".into(),
            should_fail: false,
            delay: None,
        }),
        Box::new(MockWitness {
            name: "slow".into(),
            should_fail: false,
            delay: Some(Duration::from_secs(10)),
        }),
    ];

    let request = CosignRequest {
        old_size: 0,
        consistency_proof: None,
        signed_checkpoint: make_test_checkpoint(),
    };

    // quorum=2 forces waiting for both; slow witness times out
    let results =
        collect_witness_cosignatures(&witnesses, request, 2, Duration::from_millis(100)).await;

    let successes = results
        .iter()
        .filter(|r| matches!(r, WitnessResult::Success(_)))
        .count();
    let failures = results
        .iter()
        .filter(|r| matches!(r, WitnessResult::Failed { .. }))
        .count();

    assert_eq!(successes, 1);
    assert_eq!(failures, 1);

    let (_, met) = extract_cosignatures(&results, 2);
    assert!(!met);
}
