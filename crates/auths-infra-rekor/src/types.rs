//! Rekor v1 API request/response types.
//!
//! These are the wire-format types for Rekor's REST API. They are
//! translated to canonical `auths-transparency` types at the adapter boundary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rekor v1 DSSE entry for submission.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseRequest {
    /// API version string.
    pub api_version: String,
    /// Entry kind.
    pub kind: String,
    /// Entry specification.
    pub spec: DsseSpec,
}

/// DSSE v0.0.1 spec.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSpec {
    /// Proposed content for the DSSE entry.
    pub proposed_content: DsseProposedContent,
}

/// Proposed content block in a DSSE entry.
#[derive(Debug, Serialize)]
pub struct DsseProposedContent {
    /// Base64-encoded DSSE envelope JSON.
    pub envelope: String,
    /// PEM-encoded public keys that can verify the signatures.
    pub verifiers: Vec<String>,
}

/// DSSE envelope (the inner JSON that gets base64-encoded).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Payload type URI.
    pub payload_type: String,
    /// Base64-encoded payload.
    pub payload: String,
    /// Signatures over the payload.
    pub signatures: Vec<DsseSignature>,
}

/// A single signature in a DSSE envelope.
#[derive(Debug, Serialize)]
pub struct DsseSignature {
    /// Key identifier (empty string if not used).
    pub keyid: String,
    /// Base64-encoded signature bytes.
    pub sig: String,
}

/// Rekor v1 log entry response (keyed by UUID).
pub type RekorLogEntryResponse = HashMap<String, RekorLogEntry>;

/// A single Rekor log entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // API response fields — deserialized but not all read yet
pub struct RekorLogEntry {
    /// Hex-encoded log ID.
    pub log_i_d: String,
    /// Monotonically increasing log index.
    pub log_index: u64,
    /// Base64-encoded canonicalized entry body.
    pub body: String,
    /// Unix timestamp of integration.
    pub integrated_time: i64,
    /// Verification data.
    pub verification: RekorVerification,
}

/// Verification block in a Rekor log entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct RekorVerification {
    /// Inclusion proof with checkpoint.
    pub inclusion_proof: RekorInclusionProof,
    /// Base64-encoded Signed Entry Timestamp.
    pub signed_entry_timestamp: String,
}

/// Rekor's inclusion proof structure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RekorInclusionProof {
    /// Leaf index in the log.
    pub log_index: u64,
    /// Hex-encoded root hash.
    pub root_hash: String,
    /// Tree size at proof time.
    pub tree_size: u64,
    /// Hex-encoded sibling hashes from leaf to root.
    pub hashes: Vec<String>,
    /// C2SP signed note checkpoint string.
    pub checkpoint: String,
}

/// Rekor v1 log info response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct RekorLogInfo {
    /// Hex-encoded root hash.
    pub root_hash: String,
    /// Current tree size.
    pub tree_size: u64,
    /// C2SP signed note checkpoint.
    pub signed_tree_head: String,
    /// Numeric tree ID string.
    pub tree_i_d: String,
}

/// Rekor v1 consistency proof response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RekorConsistencyProof {
    /// Hex-encoded root hash of the new tree.
    pub root_hash: String,
    /// Hex-encoded consistency proof hashes.
    pub hashes: Vec<String>,
}
