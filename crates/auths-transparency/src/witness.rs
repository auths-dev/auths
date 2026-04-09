//! Witness protocol for transparency log split-view protection.
//!
//! Implements the C2SP tlog-witness cosignature protocol. Witnesses
//! independently verify checkpoint consistency and produce timestamped
//! Ed25519 cosignatures (algorithm byte `0x04`).

use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use tokio::time::timeout;

use crate::checkpoint::{SignedCheckpoint, WitnessCosignature};
use crate::error::TransparencyError;
use crate::proof::ConsistencyProof;
use crate::types::MerkleHash;
use auths_verifier::Ed25519PublicKey;

/// C2SP timestamped Ed25519 algorithm byte for witness cosignatures.
pub const ALG_COSIGNATURE_V1: u8 = 0x04;

/// Default timeout for each witness cosigning request.
pub const DEFAULT_WITNESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Request sent to a witness to cosign a checkpoint.
///
/// Args:
/// * `old_size` — The size of the checkpoint the witness last cosigned (0 if first).
/// * `consistency_proof` — Proof that the old tree is a prefix of the new tree.
/// * `signed_checkpoint` — The new checkpoint to cosign.
///
/// Usage:
/// ```ignore
/// let req = CosignRequest {
///     old_size: 0,
///     consistency_proof: None,
///     signed_checkpoint: checkpoint.clone(),
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CosignRequest {
    /// The tree size the witness last saw (0 for fresh witnesses).
    pub old_size: u64,
    /// Consistency proof from `old_size` to the new checkpoint size.
    /// `None` when `old_size == 0` (first checkpoint).
    pub consistency_proof: Option<ConsistencyProof>,
    /// The signed checkpoint to cosign.
    pub signed_checkpoint: SignedCheckpoint,
}

/// Response from a witness after cosigning.
///
/// Args:
/// * `cosignature` — The witness's cosignature on the checkpoint.
///
/// Usage:
/// ```ignore
/// let resp = client.submit_checkpoint(req).await?;
/// let cosig = resp.cosignature;
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CosignResponse {
    /// The witness's cosignature.
    pub cosignature: WitnessCosignature,
}

/// Async trait for submitting checkpoints to a witness for cosigning.
///
/// Implementors handle the HTTP transport to a specific witness endpoint.
///
/// Args:
/// * `submit_checkpoint` — Sends a cosign request and returns the cosignature.
///
/// Usage:
/// ```ignore
/// let response = witness_client.submit_checkpoint(request).await?;
/// ```
#[async_trait]
pub trait WitnessClient: Send + Sync {
    /// Submit a checkpoint to the witness for cosigning.
    ///
    /// Args:
    /// * `request` — The cosign request containing the checkpoint and consistency proof.
    ///
    /// Usage:
    /// ```ignore
    /// let resp = client.submit_checkpoint(req).await?;
    /// ```
    async fn submit_checkpoint(
        &self,
        request: CosignRequest,
    ) -> Result<CosignResponse, TransparencyError>;
}

/// Result of a witness cosigning attempt.
#[derive(Debug)]
pub enum WitnessResult {
    /// Witness returned a valid cosignature.
    Success(WitnessCosignature),
    /// Witness timed out or returned an error.
    Failed {
        /// Name of the witness that failed.
        witness_name: String,
        /// Reason for the failure.
        reason: String,
    },
}

/// Fan out cosign requests to multiple witnesses and collect cosignatures.
///
/// Returns once `quorum` cosignatures are collected, or all witnesses
/// have responded/timed out. Each witness gets `timeout_per_witness`
/// to respond.
///
/// Args:
/// * `witnesses` — List of witness clients to contact.
/// * `request` — The cosign request to send to each witness.
/// * `quorum` — Number of cosignatures required.
/// * `timeout_per_witness` — Maximum time to wait for each witness.
///
/// Usage:
/// ```ignore
/// let cosigs = collect_witness_cosignatures(
///     &witnesses,
///     request,
///     2,
///     Duration::from_secs(5),
/// ).await;
/// ```
pub async fn collect_witness_cosignatures(
    witnesses: &[Box<dyn WitnessClient>],
    request: CosignRequest,
    quorum: usize,
    timeout_per_witness: Duration,
) -> Vec<WitnessResult> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut futures = FuturesUnordered::new();
    for (i, witness) in witnesses.iter().enumerate() {
        let req = request.clone();
        futures.push(async move {
            let result = timeout(timeout_per_witness, witness.submit_checkpoint(req)).await;
            (i, result)
        });
    }

    let mut results = Vec::with_capacity(witnesses.len());
    let mut success_count = 0usize;

    while let Some((i, result)) = futures.next().await {
        let witness_result = match result {
            Ok(Ok(resp)) => {
                success_count += 1;
                WitnessResult::Success(resp.cosignature)
            }
            Ok(Err(e)) => WitnessResult::Failed {
                witness_name: format!("witness-{i}"),
                reason: e.to_string(),
            },
            Err(_elapsed) => WitnessResult::Failed {
                witness_name: format!("witness-{i}"),
                reason: "timeout".into(),
            },
        };
        results.push(witness_result);

        if success_count >= quorum {
            break;
        }
    }

    results
}

/// Extract successful cosignatures from witness results, checking if quorum is met.
///
/// Args:
/// * `results` — Results from [`collect_witness_cosignatures`].
/// * `quorum` — Number of cosignatures required for quorum.
///
/// Usage:
/// ```ignore
/// let (cosigs, met) = extract_cosignatures(&results, 2);
/// ```
pub fn extract_cosignatures(
    results: &[WitnessResult],
    quorum: usize,
) -> (Vec<WitnessCosignature>, bool) {
    let cosigs: Vec<WitnessCosignature> = results
        .iter()
        .filter_map(|r| match r {
            WitnessResult::Success(c) => Some(c.clone()),
            WitnessResult::Failed { .. } => None,
        })
        .collect();
    let met = cosigs.len() >= quorum;
    (cosigs, met)
}

/// Build the C2SP cosignature signed message.
///
/// Per C2SP tlog-cosignature spec, the signed message is:
/// `"cosignature/v1\ntime <timestamp>\n" + checkpoint_body`
///
/// Args:
/// * `checkpoint_body` — The C2SP checkpoint body (from `Checkpoint::to_note_body()`).
/// * `timestamp` — Seconds since epoch for the cosignature timestamp.
///
/// Usage:
/// ```ignore
/// let msg = cosignature_signed_message(&checkpoint.to_note_body(), timestamp_secs);
/// ```
pub fn cosignature_signed_message(checkpoint_body: &str, timestamp: u64) -> Vec<u8> {
    let header = format!("cosignature/v1\ntime {timestamp}\n");
    let mut msg = Vec::with_capacity(header.len() + checkpoint_body.len());
    msg.extend_from_slice(header.as_bytes());
    msg.extend_from_slice(checkpoint_body.as_bytes());
    msg
}

/// Compute a C2SP witness key ID using algorithm byte 0x04 (timestamped Ed25519).
///
/// `key_id = SHA-256(witness_name + "\n" + 0x04 + pubkey)[0..4]`
///
/// Args:
/// * `witness_name` — The witness's key name.
/// * `pubkey` — 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let key_id = compute_witness_key_id("witness-1", &pubkey_bytes);
/// ```
pub fn compute_witness_key_id(witness_name: &str, pubkey: &[u8; 32]) -> [u8; 4] {
    let mut data = Vec::with_capacity(witness_name.len() + 1 + 1 + 32);
    data.extend_from_slice(witness_name.as_bytes());
    data.push(b'\n');
    data.push(ALG_COSIGNATURE_V1);
    data.extend_from_slice(pubkey);

    let hash = MerkleHash::sha256(&data);
    let mut id = [0u8; 4];
    id.copy_from_slice(&hash.as_bytes()[..4]);
    id
}

/// Build a C2SP cosignature note signature line.
///
/// Uses algorithm byte 0x04 (timestamped Ed25519). The encoded payload is:
/// `base64(0x04 + key_id + timestamp_bytes + signature)`
///
/// Args:
/// * `witness_name` — The witness's key name.
/// * `key_id` — 4-byte key ID from [`compute_witness_key_id`].
/// * `timestamp` — Seconds since epoch.
/// * `signature` — 64-byte Ed25519 signature.
///
/// Usage:
/// ```ignore
/// let line = build_cosignature_line("witness-1", &key_id, timestamp, &sig);
/// ```
pub fn build_cosignature_line(
    witness_name: &str,
    key_id: &[u8; 4],
    timestamp: u64,
    signature: &[u8; 64],
) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // C2SP format: alg_byte + key_id + 8-byte timestamp + 64-byte signature
    let mut sig_data = Vec::with_capacity(1 + 4 + 8 + 64);
    sig_data.push(ALG_COSIGNATURE_V1);
    sig_data.extend_from_slice(key_id);
    sig_data.extend_from_slice(&timestamp.to_be_bytes());
    sig_data.extend_from_slice(signature);
    let encoded = STANDARD.encode(&sig_data);
    format!("\u{2014} {witness_name} {encoded}\n")
}

/// Parse a C2SP cosignature from raw bytes.
///
/// Expected format: 8-byte big-endian timestamp + 64-byte Ed25519 signature.
///
/// Args:
/// * `witness_name` — Name of the witness.
/// * `witness_public_key` — The witness's Ed25519 public key.
/// * `raw` — 72 bytes: 8-byte timestamp + 64-byte signature.
///
/// Usage:
/// ```ignore
/// let cosig = parse_cosignature("w1", &pk, &raw_bytes)?;
/// ```
pub fn parse_cosignature(
    witness_name: &str,
    witness_public_key: Ed25519PublicKey,
    raw: &[u8],
) -> Result<WitnessCosignature, TransparencyError> {
    if raw.len() != 72 {
        return Err(TransparencyError::InvalidNote(format!(
            "cosignature must be 72 bytes (8 timestamp + 64 signature), got {}",
            raw.len()
        )));
    }

    let timestamp_secs = u64::from_be_bytes(
        raw[..8]
            .try_into()
            .map_err(|_| TransparencyError::InvalidNote("invalid timestamp bytes".into()))?,
    );

    let sig_bytes: [u8; 64] = raw[8..72]
        .try_into()
        .map_err(|_| TransparencyError::InvalidNote("invalid signature bytes".into()))?;

    let timestamp = DateTime::from_timestamp(timestamp_secs as i64, 0).ok_or_else(|| {
        TransparencyError::InvalidNote(format!("invalid timestamp: {timestamp_secs}"))
    })?;

    Ok(WitnessCosignature {
        witness_name: witness_name.to_string(),
        witness_public_key,
        signature: auths_verifier::Ed25519Signature::from_bytes(sig_bytes),
        timestamp,
    })
}

/// Serialize a cosignature to its raw wire format.
///
/// Output: 8-byte big-endian timestamp + 64-byte Ed25519 signature.
///
/// Args:
/// * `cosig` — The witness cosignature to serialize.
///
/// Usage:
/// ```ignore
/// let raw = serialize_cosignature(&cosig);
/// assert_eq!(raw.len(), 72);
/// ```
pub fn serialize_cosignature(cosig: &WitnessCosignature) -> [u8; 72] {
    let mut out = [0u8; 72];
    let timestamp_secs = cosig.timestamp.timestamp() as u64;
    out[..8].copy_from_slice(&timestamp_secs.to_be_bytes());
    out[8..72].copy_from_slice(cosig.signature.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::Ed25519Signature;
    use chrono::Utc;

    fn fixed_ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn cosignature_signed_message_format() {
        let body = "auths.dev/log\n42\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n";
        let msg = cosignature_signed_message(body, 1_700_000_000);
        let msg_str = String::from_utf8(msg).unwrap();
        assert!(msg_str.starts_with("cosignature/v1\ntime 1700000000\n"));
        assert!(msg_str.ends_with(body));
    }

    #[test]
    fn witness_key_id_uses_alg_0x04() {
        let pubkey = [0xab; 32];
        let key_id = compute_witness_key_id("witness-1", &pubkey);
        assert_eq!(key_id.len(), 4);

        // Different from regular note key ID (which uses 0x01)
        let regular_key_id = crate::note::compute_key_id("witness-1", &pubkey);
        assert_ne!(key_id, regular_key_id);
    }

    #[test]
    fn witness_key_id_deterministic() {
        let pubkey = [0xab; 32];
        let id1 = compute_witness_key_id("w1", &pubkey);
        let id2 = compute_witness_key_id("w1", &pubkey);
        assert_eq!(id1, id2);
    }

    #[test]
    fn witness_key_id_differs_by_name() {
        let pubkey = [0xab; 32];
        let id1 = compute_witness_key_id("w1", &pubkey);
        let id2 = compute_witness_key_id("w2", &pubkey);
        assert_ne!(id1, id2);
    }

    #[test]
    fn cosignature_roundtrip() {
        let pk = Ed25519PublicKey::from_bytes([0xaa; 32]);
        let sig = Ed25519Signature::from_bytes([0xbb; 64]);
        let cosig = WitnessCosignature {
            witness_name: "w1".into(),
            witness_public_key: pk,
            signature: sig,
            timestamp: fixed_ts(),
        };

        let raw = serialize_cosignature(&cosig);
        assert_eq!(raw.len(), 72);

        let parsed =
            parse_cosignature("w1", Ed25519PublicKey::from_bytes([0xaa; 32]), &raw).unwrap();
        assert_eq!(parsed.witness_name, "w1");
        assert_eq!(parsed.timestamp, fixed_ts());
        assert_eq!(parsed.signature.as_bytes(), cosig.signature.as_bytes());
    }

    #[test]
    fn parse_cosignature_rejects_short_input() {
        let pk = Ed25519PublicKey::from_bytes([0xaa; 32]);
        let result = parse_cosignature("w1", pk, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn cosignature_line_format() {
        let key_id = [0x01, 0x02, 0x03, 0x04];
        let sig = [0xcc; 64];
        let line = build_cosignature_line("witness-1", &key_id, 1_700_000_000, &sig);

        assert!(line.starts_with("\u{2014} witness-1 "));
        assert!(line.ends_with('\n'));

        // Decode and verify structure
        use base64::{Engine, engine::general_purpose::STANDARD};
        let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
        let decoded = STANDARD.decode(parts[2]).unwrap();
        assert_eq!(decoded[0], ALG_COSIGNATURE_V1);
        assert_eq!(&decoded[1..5], &key_id);
        let ts_bytes: [u8; 8] = decoded[5..13].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(ts_bytes), 1_700_000_000);
        assert_eq!(&decoded[13..], &sig);
    }

    #[test]
    fn extract_cosignatures_quorum_met() {
        let pk = Ed25519PublicKey::from_bytes([0xaa; 32]);
        let results = vec![
            WitnessResult::Success(WitnessCosignature {
                witness_name: "w1".into(),
                witness_public_key: pk,
                signature: Ed25519Signature::from_bytes([0xbb; 64]),
                timestamp: fixed_ts(),
            }),
            WitnessResult::Failed {
                witness_name: "w2".into(),
                reason: "timeout".into(),
            },
            WitnessResult::Success(WitnessCosignature {
                witness_name: "w3".into(),
                witness_public_key: Ed25519PublicKey::from_bytes([0xcc; 32]),
                signature: Ed25519Signature::from_bytes([0xdd; 64]),
                timestamp: fixed_ts(),
            }),
        ];

        let (cosigs, met) = extract_cosignatures(&results, 2);
        assert!(met);
        assert_eq!(cosigs.len(), 2);
    }

    #[test]
    fn extract_cosignatures_quorum_not_met() {
        let results = vec![
            WitnessResult::Failed {
                witness_name: "w1".into(),
                reason: "timeout".into(),
            },
            WitnessResult::Failed {
                witness_name: "w2".into(),
                reason: "error".into(),
            },
        ];

        let (cosigs, met) = extract_cosignatures(&results, 2);
        assert!(!met);
        assert_eq!(cosigs.len(), 0);
    }

    #[tokio::test]
    async fn collect_cosignatures_with_mock_witnesses() {
        use crate::checkpoint::Checkpoint;
        use crate::types::LogOrigin;

        struct MockWitness {
            name: String,
            should_fail: bool,
        }

        #[async_trait]
        impl WitnessClient for MockWitness {
            async fn submit_checkpoint(
                &self,
                _request: CosignRequest,
            ) -> Result<CosignResponse, TransparencyError> {
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

        let witnesses: Vec<Box<dyn WitnessClient>> = vec![
            Box::new(MockWitness {
                name: "w1".into(),
                should_fail: false,
            }),
            Box::new(MockWitness {
                name: "w2".into(),
                should_fail: true,
            }),
            Box::new(MockWitness {
                name: "w3".into(),
                should_fail: false,
            }),
        ];

        let checkpoint = Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size: 10,
            root: MerkleHash::from_bytes([0x01; 32]),
            timestamp: fixed_ts(),
        };

        let request = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: SignedCheckpoint {
                checkpoint,
                log_signature: Ed25519Signature::from_bytes([0xcc; 64]),
                log_public_key: Ed25519PublicKey::from_bytes([0xdd; 32]),
                witnesses: vec![],
                ecdsa_checkpoint_signature: None,
                ecdsa_checkpoint_key: None,
            },
        };

        let results =
            collect_witness_cosignatures(&witnesses, request, 2, DEFAULT_WITNESS_TIMEOUT).await;

        let (cosigs, met) = extract_cosignatures(&results, 2);
        assert!(met);
        assert!(cosigs.len() >= 2);
    }
}
