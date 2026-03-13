use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{LogOrigin, MerkleHash};

/// An unsigned transparency log checkpoint.
///
/// Args:
/// * `origin` — Log origin string (e.g., "auths.dev/log").
/// * `size` — Number of entries in the log at this checkpoint.
/// * `root` — Merkle root hash of the log at this size.
/// * `timestamp` — When the checkpoint was created.
///
/// Usage:
/// ```ignore
/// let cp = Checkpoint {
///     origin: LogOrigin::new("auths.dev/log")?,
///     size: 42,
///     root: merkle_root,
///     timestamp: Utc::now(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct Checkpoint {
    pub origin: LogOrigin,
    pub size: u64,
    pub root: MerkleHash,
    pub timestamp: DateTime<Utc>,
}

impl Checkpoint {
    /// Serialize to the C2SP checkpoint body format (three lines: origin, size, base64 hash).
    pub fn to_note_body(&self) -> String {
        format!("{}\n{}\n{}\n", self.origin, self.size, self.root.to_base64())
    }

    /// Parse from C2SP checkpoint body lines.
    pub fn from_note_body(
        body: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<Self, crate::error::TransparencyError> {
        let lines: Vec<&str> = body.lines().collect();
        if lines.len() < 3 {
            return Err(crate::error::TransparencyError::InvalidNote(
                "checkpoint body must have at least 3 lines".into(),
            ));
        }
        let origin = LogOrigin::new(lines[0])?;
        let size: u64 = lines[1].parse().map_err(|e: std::num::ParseIntError| {
            crate::error::TransparencyError::InvalidNote(e.to_string())
        })?;
        let root = MerkleHash::from_base64(lines[2])?;
        Ok(Self {
            origin,
            size,
            root,
            timestamp,
        })
    }
}

/// A checkpoint signed by the log operator (and optionally witnesses).
///
/// Args:
/// * `checkpoint` — The unsigned checkpoint data.
/// * `log_signature` — Ed25519 signature from the log's signing key.
/// * `log_public_key` — The log operator's public key.
/// * `witnesses` — Optional witness cosignatures.
///
/// Usage:
/// ```ignore
/// let signed = SignedCheckpoint {
///     checkpoint,
///     log_signature: sig,
///     log_public_key: log_pk,
///     witnesses: vec![],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub log_signature: Ed25519Signature,
    pub log_public_key: Ed25519PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<WitnessCosignature>,
}

/// A witness cosignature on a checkpoint.
///
/// Witnesses independently verify the checkpoint and add their signature
/// to increase trust in the log's consistency claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct WitnessCosignature {
    pub witness_name: String,
    pub witness_public_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_note_body_roundtrip() {
        let ts = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let cp = Checkpoint {
            origin: LogOrigin::new("auths.dev/log").unwrap(),
            size: 42,
            root: MerkleHash::from_bytes([0xab; 32]),
            timestamp: ts,
        };
        let body = cp.to_note_body();
        let parsed = Checkpoint::from_note_body(&body, ts).unwrap();
        assert_eq!(cp.origin, parsed.origin);
        assert_eq!(cp.size, parsed.size);
        assert_eq!(cp.root, parsed.root);
    }

    #[test]
    fn checkpoint_json_roundtrip() {
        let ts = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let cp = Checkpoint {
            origin: LogOrigin::new("auths.dev/log").unwrap(),
            size: 100,
            root: MerkleHash::from_bytes([0x01; 32]),
            timestamp: ts,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, back);
    }
}
