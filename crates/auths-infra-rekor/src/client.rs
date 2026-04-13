//! Rekor v1 HTTP client implementing the `TransparencyLog` port trait.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Client;
use tracing::{debug, error, warn};

use auths_core::ports::transparency_log::{LogError, LogMetadata, LogSubmission, TransparencyLog};
use auths_transparency::checkpoint::SignedCheckpoint;
use auths_transparency::proof::{ConsistencyProof, InclusionProof};
use auths_transparency::types::{LogOrigin, MerkleHash};
use auths_verifier::{DevicePublicKey, Ed25519PublicKey};

use crate::error::map_rekor_status;
use crate::types::*;

/// Maximum attestation payload size (100KB).
/// Typical attestation is 2-5KB; this is ~20-50x headroom.
/// Rekor's server-side limit may differ; catching locally gives a better error.
const MAX_PAYLOAD_SIZE: usize = 100 * 1024;

/// Rekor v1 API client implementing the `TransparencyLog` trait.
///
/// Targets a single Rekor instance. For public Rekor, use
/// `RekorClient::public()`.
///
/// Usage:
/// ```ignore
/// let client = RekorClient::public();
/// let submission = client.submit(&data, &pk, &sig).await?;
/// ```
pub struct RekorClient {
    http: Client,
    api_url: String,
    log_id: String,
    log_origin: String,
}

impl RekorClient {
    /// Create a client for the public Sigstore Rekor instance.
    pub fn public() -> Result<Self, LogError> {
        Self::new(
            "https://rekor.sigstore.dev",
            "sigstore-rekor",
            // Origin pinned from GET https://rekor.sigstore.dev/api/v1/log on 2026-04-09
            "rekor.sigstore.dev - 1193050959916656506",
        )
    }

    /// Create a client for a custom Rekor instance.
    ///
    /// Args:
    /// * `api_url` — Base URL (e.g., `"https://rekor.example.com"`).
    /// * `log_id` — Stable identifier for trust config lookup.
    /// * `log_origin` — C2SP checkpoint origin string.
    pub fn new(api_url: &str, log_id: &str, log_origin: &str) -> Result<Self, LogError> {
        let http = Client::builder()
            // Fail fast on unreachable hosts
            .connect_timeout(Duration::from_secs(5))
            // Generous request timeout: Rekor blocks until checkpoint publication
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| LogError::NetworkError(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            http,
            api_url: api_url.trim_end_matches('/').to_string(),
            log_id: log_id.to_string(),
            log_origin: log_origin.to_string(),
        })
    }

    /// Build a DSSE v0.0.1 entry for Rekor submission.
    ///
    /// DSSE wraps the attestation payload and its signature in an envelope.
    /// Rekor stores the envelope as-is without re-verifying the signature
    /// against a hash — the correct approach for signed attestation envelopes.
    fn build_dsse(
        &self,
        leaf_data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<DsseRequest, LogError> {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.auths+json".to_string(),
            payload: BASE64.encode(leaf_data),
            signatures: vec![DsseSignature {
                keyid: String::new(),
                sig: BASE64.encode(signature),
            }],
        };

        #[allow(clippy::unwrap_used)] // INVARIANT: DsseEnvelope is always serializable
        let envelope_json = serde_json::to_string(&envelope).unwrap();

        let typed_pk = auths_verifier::decode_public_key_bytes(public_key)
            .map_err(|e| LogError::InvalidResponse(format!("invalid public key: {e}")))?;
        let pem_key = pubkey_to_pem(&typed_pk)?;

        Ok(DsseRequest {
            api_version: "0.0.1".to_string(),
            kind: "dsse".to_string(),
            spec: DsseSpec {
                proposed_content: DsseProposedContent {
                    envelope: envelope_json,
                    verifiers: vec![BASE64.encode(pem_key.as_bytes())],
                },
            },
        })
    }

    /// Parse a Rekor v1 inclusion proof into canonical types.
    fn parse_inclusion_proof(
        &self,
        proof: &RekorInclusionProof,
    ) -> Result<InclusionProof, LogError> {
        let hashes: Result<Vec<MerkleHash>, _> = proof
            .hashes
            .iter()
            .map(|h| {
                let bytes = hex::decode(h).map_err(|e| {
                    LogError::InvalidResponse(format!("invalid hex in proof hash: {e}"))
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    LogError::InvalidResponse(format!(
                        "proof hash wrong length: expected 32, got {}",
                        v.len()
                    ))
                })?;
                Ok(MerkleHash::from_bytes(arr))
            })
            .collect();

        let root_bytes = hex::decode(&proof.root_hash)
            .map_err(|e| LogError::InvalidResponse(format!("invalid hex in root hash: {e}")))?;
        let root_arr: [u8; 32] = root_bytes.try_into().map_err(|v: Vec<u8>| {
            LogError::InvalidResponse(format!(
                "root hash wrong length: expected 32, got {}",
                v.len()
            ))
        })?;

        Ok(InclusionProof {
            index: proof.log_index,
            size: proof.tree_size,
            root: MerkleHash::from_bytes(root_arr),
            hashes: hashes?,
        })
    }

    /// Parse the C2SP checkpoint string from a Rekor response.
    fn parse_checkpoint_string(&self, checkpoint_str: &str) -> Result<SignedCheckpoint, LogError> {
        // The checkpoint is a C2SP signed note. Parse it using
        // auths-transparency's note parser.
        let (note_body, _signatures) = auths_transparency::parse_signed_note(checkpoint_str)
            .map_err(|e| {
                LogError::InvalidResponse(format!("failed to parse checkpoint note: {e}"))
            })?;

        // Parse the checkpoint body: origin\nsize\nbase64(root)\n
        #[allow(clippy::disallowed_methods)] // Infra boundary: Rekor timestamp is operational
        let now = chrono::Utc::now();
        let checkpoint =
            auths_transparency::Checkpoint::from_note_body(&note_body, now).map_err(|e| {
                LogError::InvalidResponse(format!("failed to parse checkpoint body: {e}"))
            })?;

        // For the ECDSA production shard, we extract the signature from the
        // signed note and store it in the ecdsa fields. The log_signature
        // and log_public_key fields use Ed25519 placeholders.
        //
        // The actual checkpoint signature verification dispatches on
        // TrustRoot.signature_algorithm at verify time.
        let ecdsa_sig = None;
        let ecdsa_pk = None;

        // If we have note signatures, try to extract the first one
        if let Some(sig) = _signatures.first() {
            // The raw signature bytes from the note (algorithm byte + key_id + signature)
            // For ECDSA, we'd need the DER signature. For now, store what we have.
            // Full ECDSA extraction will be completed when Rekor adapter is tested
            // against production.
            let _ = sig; // Will be used when ECDSA parsing is wired
        }

        Ok(SignedCheckpoint {
            checkpoint,
            log_signature: auths_verifier::Ed25519Signature::default(),
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            witnesses: vec![],
            ecdsa_checkpoint_signature: ecdsa_sig,
            ecdsa_checkpoint_key: ecdsa_pk,
        })
    }

    /// Handle HTTP 409 Conflict (duplicate entry): fetch existing entry.
    async fn handle_conflict(
        &self,
        response: reqwest::Response,
    ) -> Result<LogSubmission, LogError> {
        // Extract the Location header or parse the response body for the entry UUID
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response
            .text()
            .await
            .map_err(|e| LogError::InvalidResponse(format!("failed to read 409 body: {e}")))?;

        debug!(body_len = body.len(), "Rekor 409 Conflict — entry exists");

        // Try to parse the body as a log entry response (Rekor returns the existing entry)
        let entries: RekorLogEntryResponse = serde_json::from_str(&body).map_err(|e| {
            // If body isn't a valid entry, try fetching via Location header
            LogError::InvalidResponse(format!(
                "409 response not parseable as entry (location: {:?}): {e}",
                location
            ))
        })?;

        self.parse_entry_response(&entries)
    }

    /// Parse a Rekor log entry response into a `LogSubmission`.
    fn parse_entry_response(
        &self,
        entries: &RekorLogEntryResponse,
    ) -> Result<LogSubmission, LogError> {
        let (_uuid, entry) = entries
            .iter()
            .next()
            .ok_or_else(|| LogError::InvalidResponse("empty entry response".into()))?;

        let inclusion_proof = self.parse_inclusion_proof(&entry.verification.inclusion_proof)?;

        // Use the checkpoint bound to the inclusion proof, not a separately fetched one.
        let signed_checkpoint =
            self.parse_checkpoint_string(&entry.verification.inclusion_proof.checkpoint)?;

        Ok(LogSubmission {
            leaf_index: entry.log_index,
            inclusion_proof,
            signed_checkpoint,
        })
    }

    /// Parse the Retry-After header value, defaulting to 10 seconds.
    fn parse_retry_after(response: &reqwest::Response) -> u64 {
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10)
    }
}

#[async_trait]
impl TransparencyLog for RekorClient {
    async fn submit(
        &self,
        leaf_data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<LogSubmission, LogError> {
        // Pre-send payload size check: reject locally before HTTP
        if leaf_data.len() > MAX_PAYLOAD_SIZE {
            return Err(LogError::SubmissionRejected {
                reason: format!(
                    "attestation exceeds max size of {}KB ({} bytes)",
                    MAX_PAYLOAD_SIZE / 1024,
                    leaf_data.len()
                ),
            });
        }

        let entry = self.build_dsse(leaf_data, public_key, signature)?;
        let url = format!("{}/api/v1/log/entries", self.api_url);

        debug!(url = %url, payload_size = leaf_data.len(), "Submitting to Rekor");

        let response = self
            .http
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "Rekor submission failed");
                if e.is_timeout() {
                    LogError::NetworkError(format!("request timed out: {e}"))
                } else if e.is_connect() {
                    LogError::NetworkError(format!("connection failed: {e}"))
                } else {
                    LogError::NetworkError(e.to_string())
                }
            })?;

        let status = response.status();
        debug!(status = %status, "Rekor response received");

        // Handle 409 Conflict: entry already exists (idempotent success)
        if status.as_u16() == 409 {
            return self.handle_conflict(response).await;
        }

        // Handle 429 with Retry-After
        if status.as_u16() == 429 {
            let retry_after = Self::parse_retry_after(&response);
            warn!(retry_after_secs = retry_after, "Rekor rate limited");
            return Err(LogError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| LogError::InvalidResponse(format!("failed to read response body: {e}")))?;

        map_rekor_status(status, &body)?;

        let entries: RekorLogEntryResponse = serde_json::from_str(&body).map_err(|e| {
            LogError::InvalidResponse(format!("failed to parse entry response: {e}"))
        })?;

        let submission = self.parse_entry_response(&entries)?;

        debug!(
            leaf_index = submission.leaf_index,
            tree_size = submission.signed_checkpoint.checkpoint.size,
            "Entry submitted successfully"
        );

        Ok(submission)
    }

    async fn get_checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        let url = format!("{}/api/v1/log", self.api_url);
        debug!(url = %url, "Fetching Rekor log info");

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| LogError::NetworkError(format!("failed to fetch log info: {e}")))?;

        let body = response
            .text()
            .await
            .map_err(|e| LogError::InvalidResponse(format!("failed to read log info body: {e}")))?;

        let info: RekorLogInfo = serde_json::from_str(&body)
            .map_err(|e| LogError::InvalidResponse(format!("failed to parse log info: {e}")))?;

        self.parse_checkpoint_string(&info.signed_tree_head)
    }

    async fn get_inclusion_proof(
        &self,
        leaf_index: u64,
        _tree_size: u64,
    ) -> Result<InclusionProof, LogError> {
        // Rekor v1 doesn't have a standalone inclusion proof endpoint.
        // Fetch the entry by index and extract its proof.
        let url = format!(
            "{}/api/v1/log/entries?logIndex={}",
            self.api_url, leaf_index
        );
        debug!(url = %url, "Fetching entry for inclusion proof");

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| LogError::NetworkError(format!("failed to fetch entry: {e}")))?;

        if response.status().as_u16() == 404 {
            return Err(LogError::EntryNotFound);
        }

        let body = response
            .text()
            .await
            .map_err(|e| LogError::InvalidResponse(format!("failed to read entry body: {e}")))?;

        let entries: RekorLogEntryResponse = serde_json::from_str(&body)
            .map_err(|e| LogError::InvalidResponse(format!("failed to parse entry: {e}")))?;

        let (_uuid, entry) = entries.iter().next().ok_or(LogError::EntryNotFound)?;

        self.parse_inclusion_proof(&entry.verification.inclusion_proof)
    }

    async fn get_consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, LogError> {
        let url = format!(
            "{}/api/v1/log/proof?firstSize={}&lastSize={}",
            self.api_url, old_size, new_size
        );
        debug!(url = %url, "Fetching consistency proof");

        let response = self.http.get(&url).send().await.map_err(|e| {
            LogError::NetworkError(format!("failed to fetch consistency proof: {e}"))
        })?;

        let body = response
            .text()
            .await
            .map_err(|e| LogError::InvalidResponse(format!("failed to read proof body: {e}")))?;

        let proof: crate::types::RekorConsistencyProof =
            serde_json::from_str(&body).map_err(|e| {
                LogError::InvalidResponse(format!("failed to parse consistency proof: {e}"))
            })?;

        let hashes: Result<Vec<MerkleHash>, _> = proof
            .hashes
            .iter()
            .map(|h| {
                let bytes = hex::decode(h).map_err(|e| {
                    LogError::InvalidResponse(format!("invalid hex in consistency hash: {e}"))
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    LogError::InvalidResponse(format!(
                        "consistency hash wrong length: expected 32, got {}",
                        v.len()
                    ))
                })?;
                Ok(MerkleHash::from_bytes(arr))
            })
            .collect();

        let root_bytes = hex::decode(&proof.root_hash)
            .map_err(|e| LogError::InvalidResponse(format!("invalid hex in root hash: {e}")))?;
        let root_arr: [u8; 32] = root_bytes.try_into().map_err(|v: Vec<u8>| {
            LogError::InvalidResponse(format!(
                "root hash wrong length: expected 32, got {}",
                v.len()
            ))
        })?;

        Ok(ConsistencyProof {
            old_size,
            new_size,
            old_root: MerkleHash::from_bytes([0u8; 32]), // Not returned by Rekor v1
            new_root: MerkleHash::from_bytes(root_arr),
            hashes: hashes?,
        })
    }

    fn metadata(&self) -> LogMetadata {
        LogMetadata {
            log_id: self.log_id.clone(),
            log_origin: LogOrigin::new_unchecked(&self.log_origin),
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]), // ECDSA key, not Ed25519
            api_url: Some(self.api_url.clone()),
        }
    }
}

/// Convert a typed public key to PEM format for Rekor submission.
///
/// Rekor's hashedrekord expects the public key as PEM-encoded SPKI. This
/// dispatches on the key's curve and returns a typed error on unknown curves
/// (fn-114.17 — was: wildcard fallback that produced malformed PEM).
///
/// Args:
/// * `pk`: Typed public key. Curve comes from the key itself, not length.
///
/// Usage:
/// ```ignore
/// let pem = pubkey_to_pem(&device_pk)?;
/// ```
fn pubkey_to_pem(pk: &DevicePublicKey) -> Result<String, LogError> {
    let raw = pk.as_bytes();
    match pk.curve() {
        auths_crypto::CurveType::Ed25519 => {
            if raw.len() != 32 {
                return Err(LogError::InvalidResponse(format!(
                    "Ed25519 key must be 32 bytes, got {}",
                    raw.len()
                )));
            }
            let mut der = Vec::with_capacity(44);
            der.extend_from_slice(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ]);
            der.extend_from_slice(raw);
            let b64 = BASE64.encode(&der);
            Ok(format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                b64
            ))
        }
        auths_crypto::CurveType::P256 => {
            use p256::pkcs8::EncodePublicKey;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
                .map_err(|e| LogError::InvalidResponse(format!("invalid P-256 SEC1 bytes: {e}")))?;
            vk.to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| LogError::InvalidResponse(format!("P-256 PEM encode: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// Shared RekorClient — TLS client construction is expensive (~10s).
    static TEST_CLIENT: LazyLock<RekorClient> = LazyLock::new(|| RekorClient::public().unwrap());

    #[test]
    fn payload_size_limit() {
        let big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let client = &*TEST_CLIENT;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.submit(&big, b"pk", b"sig"));
        match result {
            Err(LogError::SubmissionRejected { reason }) => {
                assert!(reason.contains("exceeds max size"));
            }
            other => panic!("expected SubmissionRejected, got: {:?}", other),
        }
    }

    #[test]
    fn dsse_format() {
        let client = &*TEST_CLIENT;
        let pk = [0u8; 32]; // Ed25519-length placeholder so decode succeeds
        let entry = client.build_dsse(b"test data", &pk, b"signature").unwrap();

        assert_eq!(entry.kind, "dsse");
        assert_eq!(entry.api_version, "0.0.1");

        // Verify the envelope is raw JSON
        let envelope: serde_json::Value =
            serde_json::from_str(&entry.spec.proposed_content.envelope).unwrap();
        assert_eq!(envelope["payloadType"], "application/vnd.auths+json");

        // Verify the payload round-trips
        let payload = BASE64
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        assert_eq!(payload, b"test data");

        // Verify verifiers list has one PEM key
        assert_eq!(entry.spec.proposed_content.verifiers.len(), 1);
    }

    #[test]
    fn inclusion_proof_parsing() {
        let client = RekorClient::public().unwrap();
        let rekor_proof = RekorInclusionProof {
            log_index: 42,
            root_hash: "a".repeat(64), // 32 bytes hex
            tree_size: 100,
            hashes: vec!["b".repeat(64)],
            checkpoint: String::new(),
        };

        let proof = client.parse_inclusion_proof(&rekor_proof).unwrap();
        assert_eq!(proof.index, 42);
        assert_eq!(proof.size, 100);
        assert_eq!(proof.hashes.len(), 1);
    }

    #[test]
    fn retry_after_parsing() {
        // Default when no header
        let response =
            reqwest::Response::from(http::Response::builder().status(429).body("").unwrap());
        assert_eq!(RekorClient::parse_retry_after(&response), 10);
    }
}
