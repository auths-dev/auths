//! Seal types for anchoring data in KERI events.
//!
//! A seal is a cryptographic commitment (digest) to external data that is
//! anchored in a KERI event. This creates a verifiable link between the
//! KEL and external artifacts like attestations.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::Said;

/// Type of data anchored by a seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SealType {
    DeviceAttestation,
    Revocation,
    Delegation,
}

impl fmt::Display for SealType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealType::DeviceAttestation => write!(f, "device-attestation"),
            SealType::Revocation => write!(f, "revocation"),
            SealType::Delegation => write!(f, "delegation"),
        }
    }
}

/// A seal anchors external data in a KERI event.
///
/// Seals are included in the `a` (anchors) field of KERI events.
/// They contain a digest of the anchored data and a type indicator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seal {
    /// SAID (digest) of the anchored data
    pub d: Said,

    /// Type of anchored data
    #[serde(rename = "type")]
    pub seal_type: SealType,
}

impl Seal {
    /// Create a new seal with the given digest and type.
    pub fn new(digest: impl Into<String>, seal_type: SealType) -> Self {
        Self {
            d: Said::new_unchecked(digest.into()),
            seal_type,
        }
    }

    /// Create a seal for a device attestation.
    ///
    /// # Arguments
    /// * `attestation_digest` - The SAID of the attestation JSON
    pub fn device_attestation(attestation_digest: impl Into<String>) -> Self {
        Self::new(attestation_digest, SealType::DeviceAttestation)
    }

    /// Create a seal for a revocation.
    pub fn revocation(revocation_digest: impl Into<String>) -> Self {
        Self::new(revocation_digest, SealType::Revocation)
    }

    /// Create a seal for capability delegation.
    pub fn delegation(delegation_digest: impl Into<String>) -> Self {
        Self::new(delegation_digest, SealType::Delegation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_creates_device_attestation() {
        let seal = Seal::device_attestation("EDigest123");
        assert_eq!(seal.seal_type, SealType::DeviceAttestation);
        assert_eq!(seal.d, "EDigest123");
    }

    #[test]
    fn seal_serializes_with_type_field() {
        let seal = Seal::new("ETest", SealType::Revocation);
        let json = serde_json::to_string(&seal).unwrap();
        assert!(json.contains(r#""type":"revocation""#));
        assert!(json.contains(r#""d":"ETest""#));
    }

    #[test]
    fn seal_deserializes_correctly() {
        let json = r#"{"d":"EDigest","type":"device-attestation"}"#;
        let seal: Seal = serde_json::from_str(json).unwrap();
        assert_eq!(seal.d, "EDigest");
        assert_eq!(seal.seal_type, SealType::DeviceAttestation);
    }

    #[test]
    fn seal_roundtrips() {
        let original = Seal::device_attestation("ETest123");
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }
}
