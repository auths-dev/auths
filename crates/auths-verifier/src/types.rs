//! Verification types: reports, statuses, and device DIDs.

use crate::witness::WitnessQuorum;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Verification Report Types
// ============================================================================

/// Machine-readable verification result containing status, chain details, and warnings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    /// The overall verification status
    pub status: VerificationStatus,
    /// Details of each link in the verification chain
    pub chain: Vec<ChainLink>,
    /// Non-fatal warnings encountered during verification
    pub warnings: Vec<String>,
    /// Optional witness quorum result (present when witness verification was performed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_quorum: Option<WitnessQuorum>,
}

impl VerificationReport {
    /// Returns true only when the verification status is Valid.
    pub fn is_valid(&self) -> bool {
        matches!(self.status, VerificationStatus::Valid)
    }

    /// Creates a new valid VerificationReport with the given chain.
    pub fn valid(chain: Vec<ChainLink>) -> Self {
        Self {
            status: VerificationStatus::Valid,
            chain,
            warnings: Vec::new(),
            witness_quorum: None,
        }
    }

    /// Creates a new VerificationReport with the given status and chain.
    pub fn with_status(status: VerificationStatus, chain: Vec<ChainLink>) -> Self {
        Self {
            status,
            chain,
            warnings: Vec::new(),
            witness_quorum: None,
        }
    }
}

/// Verification outcome indicating success or the type of failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum VerificationStatus {
    /// The attestation(s) are valid
    Valid,
    /// The attestation has expired
    Expired {
        /// When the attestation expired
        at: DateTime<Utc>,
    },
    /// The attestation has been revoked
    Revoked {
        /// When the attestation was revoked (if known)
        at: Option<DateTime<Utc>>,
    },
    /// A signature in the chain is invalid
    InvalidSignature {
        /// The step in the chain where the invalid signature was found (0-indexed)
        step: usize,
    },
    /// The chain has a broken link (issuer→subject mismatch or missing attestation)
    BrokenChain {
        /// Description of the missing link
        missing_link: String,
    },
    /// Insufficient witness receipts to meet quorum threshold
    InsufficientWitnesses {
        /// Number of witnesses required
        required: usize,
        /// Number of witnesses that verified successfully
        verified: usize,
    },
}

/// A single link in a verification chain, representing one attestation's verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainLink {
    /// The issuer DID of this attestation
    pub issuer: String,
    /// The subject DID of this attestation
    pub subject: String,
    /// Whether this link's signature is valid
    pub valid: bool,
    /// Error message if verification failed
    pub error: Option<String>,
}

impl ChainLink {
    /// Creates a new valid chain link.
    pub fn valid(issuer: String, subject: String) -> Self {
        Self {
            issuer,
            subject,
            valid: true,
            error: None,
        }
    }

    /// Creates a new invalid chain link with an error message.
    pub fn invalid(issuer: String, subject: String, error: String) -> Self {
        Self {
            issuer,
            subject,
            valid: false,
            error: Some(error),
        }
    }
}

// ============================================================================
// DID Types
// ============================================================================

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

// ============================================================================
// IdentityDID Type
// ============================================================================

/// Strongly-typed wrapper for identity DIDs (e.g., `"did:keri:E..."`).
///
/// Usage:
/// ```ignore
/// let did = IdentityDID::new("did:keri:Eabc123");
/// assert_eq!(did.as_str(), "did:keri:Eabc123");
///
/// let s: String = did.into_inner();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct IdentityDID(pub String);

impl IdentityDID {
    /// Create a new `IdentityDID` from a raw string.
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Wraps a DID string without validation (for trusted internal paths).
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Returns the DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for IdentityDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for IdentityDID {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for IdentityDID {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<IdentityDID> for String {
    fn from(did: IdentityDID) -> String {
        did.0
    }
}

impl Deref for IdentityDID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for IdentityDID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for IdentityDID {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for IdentityDID {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for IdentityDID {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<IdentityDID> for str {
    fn eq(&self, other: &IdentityDID) -> bool {
        self == other.0
    }
}

impl PartialEq<IdentityDID> for &str {
    fn eq(&self, other: &IdentityDID) -> bool {
        *self == other.0
    }
}

// ============================================================================
// DeviceDID Type
// ============================================================================

/// Wrapper around a device DID string that ensures Git-safe ref formatting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DeviceDID(pub String);

impl DeviceDID {
    /// Create a new `DeviceDID` from a raw string.
    pub fn new<S: Into<String>>(s: S) -> Self {
        DeviceDID(s.into())
    }

    /// Constructs a `did:key:z...` identifier from a 32-byte Ed25519 public key.
    ///
    /// This uses the multicodec prefix for Ed25519 (0xED 0x01) and encodes it with base58btc.
    pub fn from_ed25519(pubkey: &[u8; 32]) -> Self {
        let mut prefixed = vec![0xED, 0x01];
        prefixed.extend_from_slice(pubkey);

        let encoded = bs58::encode(prefixed).into_string();
        Self(format!("did:key:z{}", encoded))
    }

    /// Returns a sanitized version of the DID for use in Git refs,
    /// replacing all non-alphanumeric characters with `_`.
    pub fn ref_name(&self) -> String {
        self.0
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    /// Compares a sanitized DID ref name to this real DeviceDID.
    /// Used to match Git refs to known device DIDs.
    pub fn matches_sanitized_ref(&self, ref_name: &str) -> bool {
        self.ref_name() == ref_name
    }

    /// Tries to reverse-lookup a real DID from a sanitized string,
    /// given a list of known real DIDs.
    pub fn from_sanitized<'a>(
        sanitized: &str,
        known_dids: &'a [DeviceDID],
    ) -> Option<&'a DeviceDID> {
        known_dids.iter().find(|did| did.ref_name() == sanitized)
    }

    /// Optionally expose the inner raw DID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Allow `.to_string()` and printing
impl fmt::Display for DeviceDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Allow `DeviceDID::from("did:key:abc")` and vice versa
impl From<&str> for DeviceDID {
    fn from(s: &str) -> Self {
        DeviceDID(s.to_string())
    }
}

impl From<String> for DeviceDID {
    fn from(s: String) -> Self {
        DeviceDID(s)
    }
}

// Optionally deref to &str
impl Deref for DeviceDID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::Said;

    #[test]
    fn report_without_witness_quorum_deserializes() {
        // JSON from before witness_quorum field existed
        let json = r#"{
            "status": {"type": "Valid"},
            "chain": [],
            "warnings": []
        }"#;
        let report: VerificationReport = serde_json::from_str(json).unwrap();
        assert!(report.is_valid());
        assert!(report.witness_quorum.is_none());
    }

    #[test]
    fn insufficient_witnesses_serializes_correctly() {
        let status = VerificationStatus::InsufficientWitnesses {
            required: 3,
            verified: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "InsufficientWitnesses");
        assert_eq!(parsed["required"], 3);
        assert_eq!(parsed["verified"], 1);

        // Roundtrip
        let roundtripped: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, status);
    }

    #[test]
    fn report_with_witness_quorum_roundtrips() {
        use crate::witness::{WitnessQuorum, WitnessReceiptResult};

        let report = VerificationReport {
            status: VerificationStatus::Valid,
            chain: vec![],
            warnings: vec![],
            witness_quorum: Some(WitnessQuorum {
                required: 2,
                verified: 2,
                receipts: vec![
                    WitnessReceiptResult {
                        witness_id: "did:key:w1".into(),
                        receipt_said: Said::new_unchecked("EReceipt1".into()),
                        verified: true,
                    },
                    WitnessReceiptResult {
                        witness_id: "did:key:w2".into(),
                        receipt_said: Said::new_unchecked("EReceipt2".into()),
                        verified: true,
                    },
                ],
            }),
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
        assert!(parsed.witness_quorum.is_some());
        assert_eq!(parsed.witness_quorum.unwrap().verified, 2);
    }

    #[test]
    fn report_without_witness_quorum_skips_in_json() {
        let report = VerificationReport::valid(vec![]);
        let json = serde_json::to_string(&report).unwrap();
        // witness_quorum should be omitted from JSON when None
        assert!(!json.contains("witness_quorum"));
    }
}
