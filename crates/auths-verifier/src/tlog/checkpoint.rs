//! Log checkpoints (signed tree heads) and witness cosignatures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::TransparencyError;
use super::types::{LogOrigin, MerkleHash};
use crate::core::{EcdsaP256PublicKey, EcdsaP256Signature, Ed25519PublicKey, Ed25519Signature};

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
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            self.root.to_base64()
        )
    }

    /// Parse from C2SP checkpoint body lines.
    pub fn from_note_body(body: &str, timestamp: DateTime<Utc>) -> Result<Self, TransparencyError> {
        let lines: Vec<&str> = body.lines().collect();
        if lines.len() < 3 {
            return Err(TransparencyError::InvalidNote(
                "checkpoint body must have at least 3 lines".into(),
            ));
        }
        let origin = LogOrigin::new(lines[0])?;
        let size: u64 = lines[1]
            .parse()
            .map_err(|e: std::num::ParseIntError| TransparencyError::InvalidNote(e.to_string()))?;
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
    /// ECDSA P-256 checkpoint signature (DER-encoded). Present when the log
    /// uses ECDSA instead of Ed25519 (e.g., Rekor production shard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecdsa_checkpoint_signature: Option<EcdsaP256Signature>,
    /// ECDSA P-256 public key for checkpoint verification (PKIX DER).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecdsa_checkpoint_key: Option<EcdsaP256PublicKey>,
}

impl SignedCheckpoint {
    /// Verify the log operator's Ed25519 signature over this checkpoint's C2SP
    /// note body against a **pinned** log key — never against the key the
    /// checkpoint itself carries (a self-chosen key verifying its own forged
    /// signature is the classic "trust the key I sent you" anti-pattern).
    ///
    /// Two checks, both fail-closed:
    /// 1. the embedded `log_public_key` must BE the pinned key (constant-time
    ///    compare) — a checkpoint from a different operator is not this log's,
    ///    even if its own signature is internally consistent;
    /// 2. `log_signature` must verify over [`Checkpoint::to_note_body`] under
    ///    the pinned key.
    ///
    /// Pure and synchronous (`ed25519-dalek`), so every surface — native, FFI,
    /// browser WASM — shares this one implementation.
    ///
    /// Args:
    /// * `pinned_log_key`: The log operator's Ed25519 key, obtained out of band.
    ///
    /// Usage:
    /// ```ignore
    /// signed.verify_log_signature(&pinned_log_key)?;
    /// ```
    pub fn verify_log_signature(
        &self,
        pinned_log_key: &Ed25519PublicKey,
    ) -> Result<(), TransparencyError> {
        use subtle::ConstantTimeEq;
        let key_is_pinned: bool = self
            .log_public_key
            .as_bytes()
            .ct_eq(pinned_log_key.as_bytes())
            .into();
        if !key_is_pinned {
            return Err(TransparencyError::InvalidCheckpointSignature);
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(pinned_log_key.as_bytes())
            .map_err(|_| TransparencyError::InvalidCheckpointSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(self.log_signature.as_bytes());
        verifying_key
            .verify_strict(self.checkpoint.to_note_body().as_bytes(), &signature)
            .map_err(|_| TransparencyError::InvalidCheckpointSignature)
    }
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

    fn signed_by(signing_key: &ed25519_dalek::SigningKey) -> SignedCheckpoint {
        use ed25519_dalek::Signer;
        let ts = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let checkpoint = Checkpoint {
            origin: LogOrigin::new("auths.dev/log").unwrap(),
            size: 42,
            root: MerkleHash::from_bytes([0xab; 32]),
            timestamp: ts,
        };
        let signature = signing_key.sign(checkpoint.to_note_body().as_bytes());
        SignedCheckpoint {
            checkpoint,
            log_signature: Ed25519Signature::from_bytes(signature.to_bytes()),
            log_public_key: Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes()),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        }
    }

    #[test]
    fn log_signature_verifies_under_the_pinned_key() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signed = signed_by(&signing_key);
        let pinned = Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        signed
            .verify_log_signature(&pinned)
            .expect("operator-signed checkpoint verifies under its pinned key");
    }

    #[test]
    fn log_signature_rejects_a_different_pinned_operator() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signed = signed_by(&signing_key);
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pinned = Ed25519PublicKey::from_bytes(other.verifying_key().to_bytes());
        assert!(
            signed.verify_log_signature(&pinned).is_err(),
            "a checkpoint from a different operator must fail the pinned-key check"
        );
    }

    #[test]
    fn log_signature_rejects_a_forged_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = signed_by(&signing_key);
        // Forge: same pinned key claimed, but the signature bytes are garbage.
        signed.log_signature = Ed25519Signature::from_bytes([0x42; 64]);
        let pinned = Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        assert!(
            signed.verify_log_signature(&pinned).is_err(),
            "a forged checkpoint signature must fail closed"
        );
    }

    #[test]
    fn log_signature_rejects_a_tampered_checkpoint_body() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = signed_by(&signing_key);
        // Backdate/rewrite: the root changes but the old signature is replayed.
        signed.checkpoint.root = MerkleHash::from_bytes([0xcd; 32]);
        let pinned = Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        assert!(
            signed.verify_log_signature(&pinned).is_err(),
            "a rewritten checkpoint body must not verify under the old signature"
        );
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
