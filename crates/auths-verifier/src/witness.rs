//! Witness receipt verification for the auths-verifier crate.
//!
//! This module provides pure verification logic for witness receipts,
//! re-using `auths_keri::witness::Receipt` as the canonical receipt type.
//!
//! # Usage
//!
//! ```rust,ignore
//! use auths_verifier::witness::{Receipt, WitnessVerifyConfig, verify_witness_receipts};
//!
//! let config = WitnessVerifyConfig {
//!     receipts: &receipts,
//!     witness_keys: &[("did:key:z6Mk...".into(), pk_bytes.to_vec())],
//!     threshold: 2,
//! };
//! let quorum = verify_witness_receipts(&config).await;
//! assert!(quorum.verified >= quorum.required);
//! ```

pub use auths_keri::witness::{Receipt, SignedReceipt};

use auths_crypto::CryptoProvider;
use auths_keri::Said;
use serde::{Deserialize, Serialize};

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
    /// The signed receipts to verify
    pub receipts: &'a [SignedReceipt],
    /// Known witness keys: (witness_did, ed25519_public_key_bytes)
    pub witness_keys: &'a [(String, Vec<u8>)],
    /// Minimum number of valid receipts required
    pub threshold: usize,
}

/// Verify a single signed receipt's Ed25519 signature against a public key.
///
/// Returns `true` if the signature over the canonical receipt body
/// is valid for the given public key.
pub async fn verify_receipt_signature(
    signed: &SignedReceipt,
    pk: &[u8],
    provider: &dyn CryptoProvider,
) -> bool {
    let payload = match serde_json::to_vec(&signed.receipt) {
        Ok(p) => p,
        Err(_) => return false,
    };

    provider
        .verify_ed25519(pk, &payload, &signed.signature)
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

    for signed in config.receipts {
        let matching_key = config
            .witness_keys
            .iter()
            .find(|(did, _)| did.as_str() == signed.receipt.i.as_str());

        let verified = match matching_key {
            Some((_, pk)) => verify_receipt_signature(signed, pk, provider).await,
            None => false,
        };

        if verified {
            verified_count += 1;
        }

        results.push(WitnessReceiptResult {
            witness_id: signed.receipt.i.to_string(),
            receipt_said: signed.receipt.d.clone(),
            verified,
        });
    }

    WitnessQuorum {
        required: config.threshold,
        verified: verified_count,
        receipts: results,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_crypto::RingCryptoProvider;
    use auths_crypto::testing::create_test_keypair;
    use ring::signature::Ed25519KeyPair;

    fn provider() -> RingCryptoProvider {
        RingCryptoProvider
    }

    use auths_keri::{KeriSequence, Prefix, VersionString};

    fn create_signed_receipt(
        kp: &Ed25519KeyPair,
        witness_did: &str,
        event_said: &str,
        seq: u128,
    ) -> SignedReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: "rct".into(),
            d: Said::new_unchecked(event_said.to_string()),
            i: Prefix::new_unchecked(witness_did.to_string()),
            s: KeriSequence::new(seq),
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        let sig = kp.sign(&payload).as_ref().to_vec();
        SignedReceipt {
            receipt,
            signature: sig,
        }
    }

    #[test]
    fn receipt_body_has_no_sig_field() {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: "rct".into(),
            d: Said::new_unchecked("EEvent456".into()),
            i: Prefix::new_unchecked("did:key:z6MkWitness".to_string()),
            s: KeriSequence::new(5),
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        let payload_str = String::from_utf8(payload).unwrap();
        assert!(!payload_str.contains("sig"));
        assert!(payload_str.contains("EEvent456"));
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
        receipt.signature[0] ^= 0xFF;
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
        let json = r#"{"v": "KERI10JSON000000_", "t": "rct", "d": "EEvent456", "i": "did:key:z6MkWitness", "s": "5"}"#;

        let receipt: Receipt = serde_json::from_str(json).unwrap();
        assert_eq!(receipt.t, "rct");
        assert_eq!(receipt.d, "EEvent456");
        assert_eq!(receipt.i.as_str(), "did:key:z6MkWitness");
        assert_eq!(receipt.s.value(), 5);

        let json_out = serde_json::to_string(&receipt).unwrap();
        let parsed: Receipt = serde_json::from_str(&json_out).unwrap();
        assert_eq!(receipt, parsed);
    }
}
