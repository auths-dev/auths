//! Witness receipt type for KERI event witnessing.
//!
//! A receipt is a signed acknowledgment from a witness that it has observed
//! a specific KEL event. Receipts enable duplicity detection by allowing
//! verifiers to check that witnesses agree on the event history.
//!
//! # KERI Receipt Format
//!
//! This implementation follows the KERI `rct` (non-transferable receipt) format:
//!
//! ```json
//! {
//!   "v": "KERI10JSON...",
//!   "t": "rct",
//!   "d": "<receipt SAID>",
//!   "i": "<witness identifier>",
//!   "s": "<event sequence>",
//!   "a": "<event SAID being receipted>",
//!   "sig": "<Ed25519 signature>"
//! }
//! ```

use auths_verifier::keri::Said;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// KERI version string for receipts.
pub const KERI_VERSION: &str = "KERI10JSON000000_";

/// Receipt type identifier.
pub const RECEIPT_TYPE: &str = "rct";

/// A witness receipt for a KEL event.
///
/// The receipt proves that a witness has observed and acknowledged a specific
/// event. It includes the witness's signature over the event SAID, enabling
/// verifiers to check receipt authenticity.
///
/// # Serialization
///
/// The `sig` field uses hex encoding for JSON serialization.
///
/// # Example
///
/// ```rust
/// use auths_core::witness::Receipt;
/// use auths_verifier::keri::Said;
///
/// let receipt = Receipt {
///     v: "KERI10JSON000000_".into(),
///     t: "rct".into(),
///     d: Said::new_unchecked("EReceipt123".into()),
///     i: "did:key:z6MkWitness...".into(),
///     s: 5,
///     a: Said::new_unchecked("EEvent456".into()),
///     sig: vec![0u8; 64],
/// };
///
/// let json = serde_json::to_string(&receipt).unwrap();
/// let parsed: Receipt = serde_json::from_str(&json).unwrap();
/// assert_eq!(receipt.s, parsed.s);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Version string (e.g., "KERI10JSON000000_")
    pub v: String,

    /// Type identifier ("rct" for receipt)
    pub t: String,

    /// Receipt SAID (Self-Addressing Identifier)
    pub d: Said,

    /// Witness identifier (DID)
    pub i: String,

    /// Event sequence number being receipted
    pub s: u64,

    /// Event SAID being receipted
    pub a: Said,

    /// Ed25519 signature over the canonical receipt JSON (excluding sig)
    #[serde(with = "hex")]
    pub sig: Vec<u8>,
}

impl Receipt {
    /// Create a new receipt builder.
    pub fn builder() -> ReceiptBuilder {
        ReceiptBuilder::new()
    }

    /// Check if this receipt is for the given event SAID.
    pub fn is_for_event(&self, event_said: &Said) -> bool {
        self.a == *event_said
    }

    /// Check if this receipt is from the given witness.
    pub fn is_from_witness(&self, witness_id: &str) -> bool {
        self.i == witness_id
    }

    /// Formats this receipt as a Git trailer value (base64url-encoded JSON).
    pub fn to_trailer_value(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Parses a receipt from a Git trailer value (base64url-encoded JSON).
    ///
    /// Strips all whitespace before decoding to handle RFC 822 line folding,
    /// which may introduce spaces between base64url chunks during unfolding.
    pub fn from_trailer_value(value: &str) -> Result<Self, String> {
        let clean: String = value.split_whitespace().collect();
        let bytes = URL_SAFE_NO_PAD
            .decode(&clean)
            .map_err(|e| format!("base64 decode failed: {}", e))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("json parse failed: {}", e))
    }

    /// Get the canonical JSON for signing (without the sig field).
    ///
    /// This produces the JSON that should be signed to create the receipt.
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload = ReceiptSigningPayload {
            v: &self.v,
            t: &self.t,
            d: &self.d,
            i: &self.i,
            s: self.s,
            a: &self.a,
        };
        serde_json::to_vec(&payload)
    }
}

/// Internal type for signing payload (excludes sig).
#[derive(Serialize)]
struct ReceiptSigningPayload<'a> {
    v: &'a str,
    t: &'a str,
    d: &'a Said,
    i: &'a str,
    s: u64,
    a: &'a Said,
}

/// Builder for constructing receipts.
#[derive(Debug, Default)]
pub struct ReceiptBuilder {
    v: Option<String>,
    d: Option<Said>,
    i: Option<String>,
    s: Option<u64>,
    a: Option<Said>,
    sig: Option<Vec<u8>>,
}

impl ReceiptBuilder {
    /// Create a new receipt builder with defaults.
    pub fn new() -> Self {
        Self {
            v: Some(KERI_VERSION.into()),
            ..Default::default()
        }
    }

    /// Set the receipt SAID.
    pub fn said(mut self, said: Said) -> Self {
        self.d = Some(said);
        self
    }

    /// Set the witness identifier.
    pub fn witness(mut self, witness_id: impl Into<String>) -> Self {
        self.i = Some(witness_id.into());
        self
    }

    /// Set the event sequence number.
    pub fn sequence(mut self, seq: u64) -> Self {
        self.s = Some(seq);
        self
    }

    /// Set the event SAID being receipted.
    pub fn event_said(mut self, event_said: Said) -> Self {
        self.a = Some(event_said);
        self
    }

    /// Set the signature.
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.sig = Some(sig);
        self
    }

    /// Build the receipt.
    ///
    /// Returns `None` if required fields are missing.
    pub fn build(self) -> Option<Receipt> {
        Some(Receipt {
            v: self.v?,
            t: RECEIPT_TYPE.into(),
            d: self.d?,
            i: self.i?,
            s: self.s?,
            a: self.a?,
            sig: self.sig?,
        })
    }
}

impl From<Receipt> for auths_verifier::witness::WitnessReceipt {
    fn from(r: Receipt) -> Self {
        Self {
            v: r.v,
            t: r.t,
            d: r.d,
            i: r.i,
            s: r.s,
            a: r.a,
            sig: r.sig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> Receipt {
        Receipt {
            v: KERI_VERSION.into(),
            t: RECEIPT_TYPE.into(),
            d: Said::new_unchecked("EReceipt123".into()),
            i: "did:key:z6MkWitness".into(),
            s: 5,
            a: Said::new_unchecked("EEvent456".into()),
            sig: vec![0xab; 64],
        }
    }

    #[test]
    fn receipt_serialization_roundtrip() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn receipt_sig_hex_encoded() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        // Signature should be hex encoded (64 bytes = 128 hex chars)
        assert!(json.contains(&"ab".repeat(64)));
    }

    #[test]
    fn receipt_is_for_event() {
        let receipt = sample_receipt();
        assert!(receipt.is_for_event(&Said::new_unchecked("EEvent456".into())));
        assert!(!receipt.is_for_event(&Said::new_unchecked("EWrongEvent".into())));
    }

    #[test]
    fn receipt_is_from_witness() {
        let receipt = sample_receipt();
        assert!(receipt.is_from_witness("did:key:z6MkWitness"));
        assert!(!receipt.is_from_witness("did:key:z6MkOther"));
    }

    #[test]
    fn receipt_signing_payload() {
        let receipt = sample_receipt();
        let payload = receipt.signing_payload().unwrap();
        let payload_str = String::from_utf8(payload).unwrap();

        // Payload should NOT contain "sig"
        assert!(!payload_str.contains("sig"));

        // But should contain other fields
        assert!(payload_str.contains("EReceipt123"));
        assert!(payload_str.contains("did:key:z6MkWitness"));
    }

    #[test]
    fn receipt_builder() {
        let receipt = Receipt::builder()
            .said(Said::new_unchecked("EReceipt123".into()))
            .witness("did:key:z6MkWitness")
            .sequence(5)
            .event_said(Said::new_unchecked("EEvent456".into()))
            .signature(vec![0u8; 64])
            .build()
            .unwrap();

        assert_eq!(receipt.v, KERI_VERSION);
        assert_eq!(receipt.t, RECEIPT_TYPE);
        assert_eq!(receipt.d, "EReceipt123");
        assert_eq!(receipt.s, 5);
    }

    #[test]
    fn receipt_builder_missing_fields() {
        // Missing required fields should return None
        let result = Receipt::builder()
            .said(Said::new_unchecked("EReceipt123".into()))
            .build();
        assert!(result.is_none());
    }

    #[test]
    fn receipt_json_structure() {
        let receipt = sample_receipt();
        let json: serde_json::Value = serde_json::to_value(&receipt).unwrap();

        assert_eq!(json["v"], KERI_VERSION);
        assert_eq!(json["t"], RECEIPT_TYPE);
        assert_eq!(json["s"], 5);
    }

    #[test]
    fn from_receipt_to_witness_receipt() {
        let receipt = sample_receipt();
        let verifier_receipt: auths_verifier::witness::WitnessReceipt = receipt.clone().into();

        assert_eq!(verifier_receipt.v, receipt.v);
        assert_eq!(verifier_receipt.t, receipt.t);
        assert_eq!(verifier_receipt.d, receipt.d);
        assert_eq!(verifier_receipt.i, receipt.i);
        assert_eq!(verifier_receipt.s, receipt.s);
        assert_eq!(verifier_receipt.a, receipt.a);
        assert_eq!(verifier_receipt.sig, receipt.sig);
    }

    #[test]
    fn wire_compat_receipt_json_roundtrip() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        // Deserialize the same JSON into verifier's WitnessReceipt
        let verifier_receipt: auths_verifier::witness::WitnessReceipt =
            serde_json::from_str(&json).unwrap();
        assert_eq!(verifier_receipt.v, receipt.v);
        assert_eq!(verifier_receipt.s, receipt.s);
        assert_eq!(verifier_receipt.sig, receipt.sig);
    }

    #[test]
    fn trailer_value_roundtrip() {
        let receipt = sample_receipt();
        let encoded = receipt.to_trailer_value().unwrap();
        let decoded = Receipt::from_trailer_value(&encoded).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn trailer_value_is_base64url() {
        let receipt = sample_receipt();
        let encoded = receipt.to_trailer_value().unwrap();
        // base64url uses no padding and no '+' or '/'
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn from_trailer_value_invalid_base64() {
        let result = Receipt::from_trailer_value("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn from_trailer_value_invalid_json() {
        let encoded = URL_SAFE_NO_PAD.encode(b"not json");
        let result = Receipt::from_trailer_value(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn commit_receipt_payload_signing_bytes_deterministic() {
        let payload = CommitReceiptPayload {
            tree_hash: vec![0xaa; 20],
            parent_hashes: vec![vec![0xbb; 20], vec![0xcc; 20]],
        };
        let bytes1 = payload.signing_bytes();
        let bytes2 = payload.signing_bytes();
        assert_eq!(bytes1, bytes2);
        // 20 (tree) + 4 (count) + 40 (2 parents)
        assert_eq!(bytes1.len(), 64);
    }

    #[test]
    fn commit_receipt_payload_no_parents() {
        let payload = CommitReceiptPayload {
            tree_hash: vec![0xaa; 20],
            parent_hashes: vec![],
        };
        let bytes = payload.signing_bytes();
        assert_eq!(bytes.len(), 24); // 20 + 4
        // num_parents should be 0
        assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
    }
}
