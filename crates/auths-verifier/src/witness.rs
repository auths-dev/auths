//! Witness receipt verification for the auths-verifier crate.
//!
//! This module provides pure verification logic for witness receipts.
//! It defines wire-compatible types that match the `auths_core::witness::Receipt`
//! JSON format, enabling `auths-verifier` to verify witness receipts without
//! depending on `auths-core`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use auths_verifier::witness::{WitnessReceipt, WitnessVerifyConfig, verify_witness_receipts};
//!
//! let config = WitnessVerifyConfig {
//!     receipts: &receipts,
//!     witness_keys: &[("did:key:z6Mk...".into(), pk_bytes.to_vec())],
//!     threshold: 2,
//! };
//! let quorum = verify_witness_receipts(&config);
//! assert!(quorum.verified >= quorum.required);
//! ```

use auths_crypto::CryptoProvider;
use serde::{Deserialize, Serialize};

use crate::keri::Said;

/// Wire-compatible with `auths_core::witness::Receipt`.
/// Same JSON shape: `{ v, t, d, i, s, a, sig }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Version string (e.g., "KERI10JSON000000_")
    pub v: String,
    /// Type identifier ("rct" for receipt)
    pub t: String,
    /// Receipt SAID
    pub d: Said,
    /// Witness identifier (DID)
    pub i: String,
    /// Event sequence number
    pub s: u64,
    /// Event SAID being receipted
    pub a: Said,
    /// Ed25519 signature over the canonical receipt payload (excluding sig)
    #[serde(with = "hex")]
    pub sig: Vec<u8>,
}

impl WitnessReceipt {
    /// Get the canonical JSON for signature verification (without the sig field).
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload = WitnessReceiptSigningPayload {
            v: &self.v,
            t: &self.t,
            d: self.d.as_str(),
            i: &self.i,
            s: self.s,
            a: self.a.as_str(),
        };
        serde_json::to_vec(&payload)
    }
}

/// Internal type for signing payload (excludes sig).
#[derive(Serialize)]
struct WitnessReceiptSigningPayload<'a> {
    v: &'a str,
    t: &'a str,
    d: &'a str,
    i: &'a str,
    s: u64,
    a: &'a str,
}

/// Result of witness quorum verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessQuorum {
    /// Number of witnesses required for quorum
    pub required: usize,
    /// Number of witnesses that produced valid receipts
    pub verified: usize,
    /// Per-receipt verification results
    pub receipts: Vec<WitnessReceiptResult>,
}

/// Verification result for a single witness receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessReceiptResult {
    /// The witness DID that issued this receipt
    pub witness_id: String,
    /// The receipt SAID
    pub receipt_said: Said,
    /// Whether the receipt signature was verified
    pub verified: bool,
}

/// Configuration for witness receipt verification.
pub struct WitnessVerifyConfig<'a> {
    /// The receipts to verify
    pub receipts: &'a [WitnessReceipt],
    /// Known witness keys: (witness_did, ed25519_public_key_bytes)
    pub witness_keys: &'a [(String, Vec<u8>)],
    /// Minimum number of valid receipts required
    pub threshold: usize,
}

/// Verify a single receipt's Ed25519 signature against a public key.
///
/// Returns `true` if the signature over the canonical payload (excluding `sig`)
/// is valid for the given public key.
pub async fn verify_receipt_signature(
    receipt: &WitnessReceipt,
    pk: &[u8],
    provider: &dyn CryptoProvider,
) -> bool {
    let payload = match receipt.signing_payload() {
        Ok(p) => p,
        Err(_) => return false,
    };

    provider
        .verify_ed25519(pk, &payload, &receipt.sig)
        .await
        .is_ok()
}

/// Verify a set of witness receipts against known witness keys.
///
/// Iterates through receipts, matches each against `witness_keys` by DID,
/// and verifies signatures. Returns a `WitnessQuorum` with the count of
/// verified receipts and per-receipt results.
pub async fn verify_witness_receipts(
    config: &WitnessVerifyConfig<'_>,
    provider: &dyn CryptoProvider,
) -> WitnessQuorum {
    let mut results = Vec::with_capacity(config.receipts.len());
    let mut verified_count = 0;

    for receipt in config.receipts {
        let matching_key = config
            .witness_keys
            .iter()
            .find(|(did, _)| *did == receipt.i);

        let verified = match matching_key {
            Some((_, pk)) => verify_receipt_signature(receipt, pk, provider).await,
            None => false,
        };

        if verified {
            verified_count += 1;
        }

        results.push(WitnessReceiptResult {
            witness_id: receipt.i.clone(),
            receipt_said: receipt.d.clone(),
            verified,
        });
    }

    WitnessQuorum {
        required: config.threshold,
        verified: verified_count,
        receipts: results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_crypto::RingCryptoProvider;
    use auths_test_utils::crypto::create_test_keypair;
    use ring::signature::Ed25519KeyPair;

    fn provider() -> RingCryptoProvider {
        RingCryptoProvider
    }

    fn create_signed_receipt(
        kp: &Ed25519KeyPair,
        witness_did: &str,
        event_said: &str,
        seq: u64,
    ) -> WitnessReceipt {
        let mut receipt = WitnessReceipt {
            v: "KERI10JSON000000_".into(),
            t: "rct".into(),
            d: Said::new_unchecked(format!("EReceipt_{}", seq)),
            i: witness_did.into(),
            s: seq,
            a: Said::new_unchecked(event_said.into()),
            sig: vec![],
        };
        let payload = receipt.signing_payload().unwrap();
        receipt.sig = kp.sign(&payload).as_ref().to_vec();
        receipt
    }

    #[test]
    fn receipt_signing_payload_excludes_sig() {
        let receipt = WitnessReceipt {
            v: "KERI10JSON000000_".into(),
            t: "rct".into(),
            d: Said::new_unchecked("EReceipt123".into()),
            i: "did:key:z6MkWitness".into(),
            s: 5,
            a: Said::new_unchecked("EEvent456".into()),
            sig: vec![0xab; 64],
        };
        let payload = receipt.signing_payload().unwrap();
        let payload_str = String::from_utf8(payload).unwrap();
        assert!(!payload_str.contains("sig"));
        assert!(payload_str.contains("EReceipt123"));
        assert!(payload_str.contains("did:key:z6MkWitness"));
    }

    #[tokio::test]
    async fn verify_receipt_valid_signature() {
        let (kp, pk) = create_test_keypair(&[10u8; 32]);
        let receipt = create_signed_receipt(&kp, "did:key:z6MkW1", "EEvent1", 1);
        assert!(verify_receipt_signature(&receipt, &pk, &provider()).await);
    }

    #[tokio::test]
    async fn verify_receipt_invalid_signature() {
        let (kp, _pk) = create_test_keypair(&[10u8; 32]);
        let (_kp2, pk2) = create_test_keypair(&[20u8; 32]);
        let receipt = create_signed_receipt(&kp, "did:key:z6MkW1", "EEvent1", 1);
        assert!(!verify_receipt_signature(&receipt, &pk2, &provider()).await);
    }

    #[tokio::test]
    async fn verify_receipt_tampered_signature() {
        let (kp, pk) = create_test_keypair(&[10u8; 32]);
        let mut receipt = create_signed_receipt(&kp, "did:key:z6MkW1", "EEvent1", 1);
        receipt.sig[0] ^= 0xFF;
        assert!(!verify_receipt_signature(&receipt, &pk, &provider()).await);
    }

    #[tokio::test]
    async fn quorum_met() {
        let (kp1, pk1) = create_test_keypair(&[10u8; 32]);
        let (kp2, pk2) = create_test_keypair(&[20u8; 32]);
        let (_kp3, pk3) = create_test_keypair(&[30u8; 32]);

        let r1 = create_signed_receipt(&kp1, "did:key:w1", "EEvent1", 1);
        let r2 = create_signed_receipt(&kp2, "did:key:w2", "EEvent1", 1);

        let config = WitnessVerifyConfig {
            receipts: &[r1, r2],
            witness_keys: &[
                ("did:key:w1".into(), pk1.to_vec()),
                ("did:key:w2".into(), pk2.to_vec()),
                ("did:key:w3".into(), pk3.to_vec()),
            ],
            threshold: 2,
        };

        let quorum = verify_witness_receipts(&config, &provider()).await;
        assert_eq!(quorum.required, 2);
        assert_eq!(quorum.verified, 2);
        assert_eq!(quorum.receipts.len(), 2);
        assert!(quorum.receipts[0].verified);
        assert!(quorum.receipts[1].verified);
    }

    #[tokio::test]
    async fn quorum_not_met() {
        let (kp1, pk1) = create_test_keypair(&[10u8; 32]);
        let (kp2, _pk2) = create_test_keypair(&[20u8; 32]);
        let (_kp3, pk3) = create_test_keypair(&[30u8; 32]);

        let r1 = create_signed_receipt(&kp1, "did:key:w1", "EEvent1", 1);
        let r2 = create_signed_receipt(&kp2, "did:key:w2", "EEvent1", 1);

        let config = WitnessVerifyConfig {
            receipts: &[r1, r2],
            witness_keys: &[
                ("did:key:w1".into(), pk1.to_vec()),
                ("did:key:w2".into(), pk3.to_vec()),
            ],
            threshold: 2,
        };

        let quorum = verify_witness_receipts(&config, &provider()).await;
        assert_eq!(quorum.required, 2);
        assert_eq!(quorum.verified, 1);
        assert!(quorum.receipts[0].verified);
        assert!(!quorum.receipts[1].verified);
    }

    #[tokio::test]
    async fn unknown_witness_ignored() {
        let (kp1, _pk1) = create_test_keypair(&[10u8; 32]);
        let (kp2, pk2) = create_test_keypair(&[20u8; 32]);

        let r1 = create_signed_receipt(&kp1, "did:key:unknown", "EEvent1", 1);
        let r2 = create_signed_receipt(&kp2, "did:key:w2", "EEvent1", 1);

        let config = WitnessVerifyConfig {
            receipts: &[r1, r2],
            witness_keys: &[("did:key:w2".into(), pk2.to_vec())],
            threshold: 1,
        };

        let quorum = verify_witness_receipts(&config, &provider()).await;
        assert_eq!(quorum.verified, 1);
        assert!(!quorum.receipts[0].verified);
        assert!(quorum.receipts[1].verified);
    }

    #[test]
    fn wire_compat_with_core_receipt() {
        let sig_hex = "ab".repeat(64);
        let json = format!(
            r#"{{"v": "KERI10JSON000000_", "t": "rct", "d": "EReceipt123", "i": "did:key:z6MkWitness", "s": 5, "a": "EEvent456", "sig": "{}"}}"#,
            sig_hex
        );

        let receipt: WitnessReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.v, "KERI10JSON000000_");
        assert_eq!(receipt.t, "rct");
        assert_eq!(receipt.d, "EReceipt123");
        assert_eq!(receipt.i, "did:key:z6MkWitness");
        assert_eq!(receipt.s, 5);
        assert_eq!(receipt.a, "EEvent456");
        assert_eq!(receipt.sig.len(), 64);

        let json_out = serde_json::to_string(&receipt).unwrap();
        let parsed: WitnessReceipt = serde_json::from_str(&json_out).unwrap();
        assert_eq!(receipt, parsed);
    }
}
