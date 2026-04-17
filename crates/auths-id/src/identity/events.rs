//! Event structures for KERI identity operations.
//!
//! This module provides high-level event types that abstract over the
//! low-level KERI event formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a key rotation event in the KERI Key Event Log (KEL).
///
/// This is a high-level representation of a key rotation that can be
/// serialized to JSON for storage and transmission. The actual KERI
/// event format (CESR) is handled at the storage layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRotationEvent {
    /// Sequence number in the KEL (incrementing from 0)
    pub sequence: u128,

    /// Hash of the previous event for backward chain verification.
    /// Empty string for inception events (sequence 0).
    pub previous_hash: String,

    /// Old public key being rotated from (32 bytes for Ed25519).
    #[serde(with = "base64_bytes")]
    pub old_public_key: Vec<u8>,

    /// New public key being rotated to (32 bytes for Ed25519).
    #[serde(with = "base64_bytes")]
    pub new_public_key: Vec<u8>,

    /// ISO 8601 timestamp of the rotation event.
    pub timestamp: DateTime<Utc>,

    /// Signature proving authority to rotate (signed by the old key).
    /// This proves the holder of the old key authorized the rotation.
    #[serde(with = "base64_bytes")]
    pub rotation_signature: Vec<u8>,
}

impl KeyRotationEvent {
    /// Creates a new KeyRotationEvent.
    pub fn new(
        sequence: u128,
        previous_hash: String,
        old_public_key: Vec<u8>,
        new_public_key: Vec<u8>,
        timestamp: DateTime<Utc>,
        rotation_signature: Vec<u8>,
    ) -> Self {
        Self {
            sequence,
            previous_hash,
            old_public_key,
            new_public_key,
            timestamp,
            rotation_signature,
        }
    }

    /// Returns the canonical bytes for signing this event.
    ///
    /// The canonical form includes all fields except the rotation_signature,
    /// serialized deterministically.
    pub fn canonical_bytes_for_signing(&self) -> Vec<u8> {
        // Create a deterministic representation for signing
        let mut data = Vec::new();
        data.extend_from_slice(&self.sequence.to_be_bytes());
        data.extend_from_slice(self.previous_hash.as_bytes());
        data.extend_from_slice(&self.old_public_key);
        data.extend_from_slice(&self.new_public_key);
        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        data
    }
}

/// Base64 serialization helper for `Vec<u8>` fields.
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_key_rotation_event_serialization() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let event = KeyRotationEvent::new(
            1,
            "abc123hash".to_string(),
            vec![1u8; 32], // old public key
            vec![2u8; 32], // new public key
            timestamp,
            vec![3u8; 64], // signature
        );

        let json = serde_json::to_string(&event).expect("Failed to serialize");
        let deserialized: KeyRotationEvent =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(event, deserialized);
        assert_eq!(deserialized.sequence, 1);
        assert_eq!(deserialized.previous_hash, "abc123hash");
        assert_eq!(deserialized.old_public_key, vec![1u8; 32]);
        assert_eq!(deserialized.new_public_key, vec![2u8; 32]);
        assert_eq!(deserialized.rotation_signature, vec![3u8; 64]);
    }

    #[test]
    fn test_canonical_bytes_for_signing() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let event = KeyRotationEvent::new(
            1,
            "prevhash".to_string(),
            vec![0u8; 32],
            vec![1u8; 32],
            timestamp,
            vec![],
        );

        let bytes = event.canonical_bytes_for_signing();
        assert!(!bytes.is_empty());

        // Verify determinism - same event produces same bytes
        let bytes2 = event.canonical_bytes_for_signing();
        assert_eq!(bytes, bytes2);
    }
}
