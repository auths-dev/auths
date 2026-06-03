//! Witness receipt type for KERI event witnessing.
//!
//! A receipt is a signed acknowledgment from a witness that it has observed
//! a specific KEL event. Receipts enable duplicity detection by allowing
//! verifiers to check that witnesses agree on the event history.
//!
//! # KERI Receipt Format (spec: `rct` message type)
//!
//! Per the spec, the receipt body contains only `[v, t, d, i, s]`.
//! The `d` field is the SAID of the **referenced key event** (NOT the receipt itself).
//! Signatures are externalized (not in the body).

use crate::Said;
use crate::events::KeriSequence;
use crate::types::{Prefix, VersionString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// Receipt type identifier.
pub const RECEIPT_TYPE: &str = "rct";

/// The receipt message-type tag. Always serializes the constant `"rct"` and
/// rejects any other value on parse, so a `Receipt` can never carry a forged
/// or mistyped `t` (e.g. `"icp"`) that would otherwise serialize and verify
/// locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiptTag;

impl Serialize for ReceiptTag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(RECEIPT_TYPE)
    }
}

impl<'de> Deserialize<'de> for ReceiptTag {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == RECEIPT_TYPE {
            Ok(ReceiptTag)
        } else {
            Err(serde::de::Error::custom(format!(
                "receipt `t` must be {RECEIPT_TYPE:?}, got {s:?}"
            )))
        }
    }
}

impl PartialEq<str> for ReceiptTag {
    fn eq(&self, other: &str) -> bool {
        other == RECEIPT_TYPE
    }
}

impl PartialEq<&str> for ReceiptTag {
    fn eq(&self, other: &&str) -> bool {
        *other == RECEIPT_TYPE
    }
}

/// A witness receipt for a KEL event (spec-compliant `rct` message).
///
/// Per the spec, `d` is the SAID of the **referenced key event** (NOT the receipt's own SAID).
/// Signatures are externalized — use `SignedReceipt` to pair a receipt with its signature.
///
/// Usage:
/// ```
/// use auths_keri::witness::{Receipt, ReceiptTag};
/// use auths_keri::{Said, Prefix, VersionString, KeriSequence};
///
/// let receipt = Receipt {
///     v: VersionString::placeholder(),
///     t: ReceiptTag,
///     d: Said::new_unchecked("EEventSaid123".into()),
///     i: Prefix::new_unchecked("EControllerAid".into()),
///     s: KeriSequence::new(5),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Version string
    pub v: VersionString,

    /// Type identifier — always `"rct"`; rejects other values on parse.
    pub t: ReceiptTag,

    /// SAID of the referenced key event (NOT the receipt's own SAID)
    pub d: Said,

    /// Controller AID of the KEL being receipted
    pub i: Prefix,

    /// Sequence number of the event being receipted
    pub s: KeriSequence,
}

/// A receipt paired with its detached witness signature.
///
/// Per the spec, signatures are not part of the receipt body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The receipt body
    pub receipt: Receipt,
    /// Witness signature (externalized, not in body), hex-encoded for JSON
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
}

/// A signed receipt paired with the **witness AID** that produced it.
///
/// The wire `rct` body (`SignedReceipt.receipt`) carries the *controller* AID in
/// its `i` field, never the witness — so a bare `SignedReceipt` cannot say who
/// attested it. `StoredReceipt` closes that gap: it records the curve-tagged
/// witness AID (the value designated in `b[]` and the KAWA quorum dedupe key)
/// alongside the signature, which is what the verify path checks the signature
/// against. The witness AID is supplied by the collector (which knows each
/// configured witness's pinned AID), not parsed from the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReceipt {
    /// The signed receipt (spec body + detached witness signature).
    pub signed: SignedReceipt,
    /// The attesting witness's AID (curve-tagged CESR verkey prefix).
    pub witness: Prefix,
}

impl Receipt {
    /// Create a new receipt builder.
    pub fn builder() -> ReceiptBuilder {
        ReceiptBuilder::new()
    }

    /// Check if this receipt is for the given event SAID.
    pub fn is_for_event(&self, event_said: &Said) -> bool {
        self.d == *event_said
    }

    /// Check if this receipt is from the given controller.
    pub fn is_for_controller(&self, controller_id: &str) -> bool {
        self.i.as_str() == controller_id
    }
}

impl SignedReceipt {
    /// Formats this signed receipt as a Git trailer value (base64url-encoded JSON).
    ///
    /// Encodes both the receipt body and the hex-encoded signature.
    pub fn to_trailer_value(&self) -> Result<String, serde_json::Error> {
        // Wrap receipt + hex sig for trailer encoding
        let wrapper = serde_json::json!({
            "receipt": serde_json::to_value(&self.receipt)?,
            "sig": hex::encode(&self.signature),
        });
        let json = serde_json::to_string(&wrapper)?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Parses a signed receipt from a Git trailer value (base64url-encoded JSON).
    pub fn from_trailer_value(value: &str) -> Result<Self, String> {
        let clean: String = value.split_whitespace().collect();
        let bytes = URL_SAFE_NO_PAD
            .decode(&clean)
            .map_err(|e| format!("base64 decode failed: {}", e))?;
        let wrapper: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("json parse failed: {}", e))?;
        let receipt: Receipt = serde_json::from_value(
            wrapper
                .get("receipt")
                .cloned()
                .ok_or("missing receipt field")?,
        )
        .map_err(|e| format!("receipt parse failed: {}", e))?;
        let sig_hex = wrapper
            .get("sig")
            .and_then(|v| v.as_str())
            .ok_or("missing sig field")?;
        let signature =
            hex::decode(sig_hex).map_err(|e| format!("sig hex decode failed: {}", e))?;
        Ok(SignedReceipt { receipt, signature })
    }
}

/// Builder for constructing signed receipts.
#[derive(Debug, Default)]
pub struct ReceiptBuilder {
    d: Option<Said>,
    i: Option<Prefix>,
    s: Option<KeriSequence>,
    sig: Option<Vec<u8>>,
}

impl ReceiptBuilder {
    /// Create a new receipt builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the event SAID (the `d` field — SAID of referenced event, NOT the receipt).
    pub fn said(mut self, said: Said) -> Self {
        self.d = Some(said);
        self
    }

    /// Set the controller AID (the `i` field).
    pub fn witness(mut self, witness_id: impl Into<String>) -> Self {
        self.i = Some(Prefix::new_unchecked(witness_id.into()));
        self
    }

    /// Set the event sequence number.
    pub fn sequence(mut self, seq: u128) -> Self {
        self.s = Some(KeriSequence::new(seq));
        self
    }

    /// Set the signature.
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.sig = Some(sig);
        self
    }

    /// Build the signed receipt.
    ///
    /// Returns `None` if required fields are missing.
    /// Computes the version string with the actual serialized byte count.
    pub fn build(self) -> Option<SignedReceipt> {
        let mut receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: self.d?,
            i: self.i?,
            s: self.s?,
        };
        // Compute actual serialized size and set v
        if let Ok(bytes) = serde_json::to_vec(&receipt) {
            receipt.v = VersionString::json(bytes.len() as u32);
        }
        Some(SignedReceipt {
            receipt,
            signature: self.sig?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    fn sample_receipt() -> Receipt {
        Receipt {
            v: VersionString::json(100),
            t: ReceiptTag,
            d: Said::new_unchecked("EEventSaid123".into()),
            i: Prefix::new_unchecked("EControllerAid".into()),
            s: KeriSequence::new(5),
        }
    }

    fn sample_signed_receipt() -> SignedReceipt {
        SignedReceipt {
            receipt: sample_receipt(),
            signature: vec![0xab; 64],
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
    fn receipt_body_has_no_sig_field() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("sig"));
        assert!(!json.contains("\"a\""));
    }

    #[test]
    fn receipt_is_for_event() {
        let receipt = sample_receipt();
        assert!(receipt.is_for_event(&Said::new_unchecked("EEventSaid123".into())));
        assert!(!receipt.is_for_event(&Said::new_unchecked("EWrongEvent".into())));
    }

    #[test]
    fn receipt_is_for_controller() {
        let receipt = sample_receipt();
        assert!(receipt.is_for_controller("EControllerAid"));
        assert!(!receipt.is_for_controller("EOtherAid"));
    }

    #[test]
    fn receipt_builder() {
        let signed = Receipt::builder()
            .said(Said::new_unchecked("EEventSaid123".into()))
            .witness("EControllerAid")
            .sequence(5)
            .signature(vec![0u8; 64])
            .build()
            .unwrap();

        assert_eq!(signed.receipt.t, RECEIPT_TYPE);
        assert_eq!(signed.receipt.d, "EEventSaid123");
        assert_eq!(signed.receipt.s.value(), 5);
        // Version string should have non-zero size (computed by builder)
        assert!(signed.receipt.v.size > 0);
    }

    #[test]
    fn receipt_builder_missing_fields() {
        let result = Receipt::builder()
            .said(Said::new_unchecked("EEventSaid123".into()))
            .build();
        assert!(result.is_none());
    }

    #[test]
    fn receipt_json_structure() {
        let receipt = sample_receipt();
        let json: serde_json::Value = serde_json::to_value(&receipt).unwrap();

        assert_eq!(json["t"], RECEIPT_TYPE);
        assert!(json["v"].as_str().unwrap().starts_with("KERI10JSON"));
        assert_eq!(json["s"], "5");
    }

    #[test]
    fn receipt_t_must_be_rct() {
        let good = serde_json::to_value(sample_receipt()).unwrap();
        assert_eq!(good["t"], RECEIPT_TYPE);
        assert!(serde_json::from_value::<Receipt>(good).is_ok());

        let mut forged = serde_json::to_value(sample_receipt()).unwrap();
        forged["t"] = serde_json::Value::String("icp".into());
        let err = serde_json::from_value::<Receipt>(forged).unwrap_err();
        assert!(err.to_string().contains("rct"));
    }

    #[test]
    fn signed_receipt_trailer_value_roundtrip() {
        let signed = sample_signed_receipt();
        let encoded = signed.to_trailer_value().unwrap();
        let decoded = SignedReceipt::from_trailer_value(&encoded).unwrap();
        assert_eq!(signed, decoded);
    }

    #[test]
    fn trailer_value_is_base64url() {
        let signed = sample_signed_receipt();
        let encoded = signed.to_trailer_value().unwrap();
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn from_trailer_value_invalid_base64() {
        let result = SignedReceipt::from_trailer_value("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn from_trailer_value_invalid_json() {
        let encoded = B64.encode(b"not json");
        let result = SignedReceipt::from_trailer_value(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn stored_receipt_roundtrips_with_witness_aid() {
        let stored = StoredReceipt {
            signed: sample_signed_receipt(),
            witness: Prefix::new_unchecked("BWitnessAid000000000000000000000000000000000".into()),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let parsed: StoredReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(stored, parsed);
        assert_eq!(
            parsed.witness.as_str(),
            "BWitnessAid000000000000000000000000000000000"
        );
        // The controller-AID `i` in the body is distinct from the witness AID.
        assert_ne!(parsed.signed.receipt.i.as_str(), parsed.witness.as_str());
    }
}
