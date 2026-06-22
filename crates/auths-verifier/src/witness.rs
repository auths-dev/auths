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

pub use auths_keri::witness::{Receipt, ReceiptTag, SignedReceipt};

use auths_crypto::CryptoProvider;
use auths_crypto::did_key::{DecodedDidKey, did_key_decode};
use auths_keri::{KeriPublicKey, Said};
use serde::{Deserialize, Serialize};

/// The outcome of verifying a single receipt against a witness's published
/// identity, with NO network and NO registry — a stranger holding only the
/// receipt and the identity decides here.
///
/// The verdict is a parsed sum type, not a boolean: the caller can render
/// exactly why a receipt failed (an unreadable identity vs. a signature that
/// did not check) without re-inspecting anything. `Verified` is the only
/// success arm, so a receipt that did not verify can never be mistaken for one
/// that did.
///
/// This is **not** an ADR-009 freshness-bearing trust verdict, by design — so it
/// carries no `freshness` qualifier (and is named on the freshness-honesty
/// allowlist). A receipt *is itself* freshness evidence: it records that a witness
/// observed an event, which is what other verdicts consume as their fresher source.
/// Qualifying a piece of freshness evidence with its own freshness is circular; the
/// relying party grades the freshness of the *authority* verdict the receipt
/// corroborates, not the receipt. Consumed today by `auths witness` and
/// `auths-witness-node` as corroboration, never as a time-bounded authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum OfflineReceiptVerdict {
    /// The signature verifies against the key embedded in the published
    /// identity. The receipt is genuine corroboration.
    Verified {
        /// The published witness identity the signature verified against.
        witness: String,
    },
    /// The published identity is not a readable `did:key` carrying a supported
    /// verification key, so no key could be recovered to check against.
    UnreadableIdentity {
        /// The reason the identity could not be decoded into a key.
        reason: String,
    },
    /// A key was recovered from the identity, but the signature does not verify
    /// over the canonical receipt bytes — a tampered or foreign receipt.
    SignatureFailed {
        /// The published witness identity the signature was checked against.
        witness: String,
    },
}

impl OfflineReceiptVerdict {
    /// Whether the receipt is genuine corroboration (the only success arm).
    pub fn is_verified(&self) -> bool {
        matches!(self, OfflineReceiptVerdict::Verified { .. })
    }
}

/// Verify a witness receipt offline against the witness's PUBLISHED identity
/// alone — no network, no registry, no separately-supplied key table.
///
/// This is the self-contained corroboration check a third party runs on a
/// clean machine: the witness's published `did:key` identity *embeds* its
/// verification key, so `{receipt, signature, identity}` is everything needed
/// to decide. The published identity is the only trust input; the receipt body
/// carries the *controller* AID in `i`, never the witness, so it cannot
/// self-attest.
///
/// The verdict distinguishes an unreadable identity (the wrong string was
/// carried) from a signature that did not check (a tampered or foreign
/// receipt). A single bit flipped anywhere in the signature, the receipt body,
/// or the identity moves the result off [`OfflineReceiptVerdict::Verified`].
///
/// The signed bytes are `serde_json::to_vec(&receipt)`, matching exactly what a
/// witness server signs when it issues the receipt.
///
/// Args:
/// * `signed`: the receipt body paired with the witness's detached signature.
/// * `witness_identity`: the witness's published `did:key:z…` identity (as
///   advertised at its health endpoint).
///
/// Usage:
/// ```ignore
/// let verdict = verify_receipt_offline(&signed, "did:key:z6Mk…");
/// assert!(verdict.is_verified());
/// ```
pub fn verify_receipt_offline(
    signed: &SignedReceipt,
    witness_identity: &str,
) -> OfflineReceiptVerdict {
    let decoded = match did_key_decode(witness_identity) {
        Ok(d) => d,
        Err(e) => {
            return OfflineReceiptVerdict::UnreadableIdentity {
                reason: e.to_string(),
            };
        }
    };

    let key = match &decoded {
        DecodedDidKey::Ed25519(bytes) => KeriPublicKey::from_verkey_bytes(bytes, decoded.curve()),
        DecodedDidKey::P256(bytes) => KeriPublicKey::from_verkey_bytes(bytes, decoded.curve()),
    };
    let key = match key {
        Ok(k) => k,
        Err(e) => {
            return OfflineReceiptVerdict::UnreadableIdentity {
                reason: e.to_string(),
            };
        }
    };

    let payload = match serde_json::to_vec(&signed.receipt) {
        Ok(p) => p,
        Err(e) => {
            // A receipt that cannot be re-serialized to its canonical bytes
            // cannot be checked against any key — it is unusable, not verified.
            return OfflineReceiptVerdict::UnreadableIdentity {
                reason: format!("receipt is not serializable to its signing bytes: {e}"),
            };
        }
    };

    match key.verify_signature(&payload, &signed.signature) {
        Ok(()) => OfflineReceiptVerdict::Verified {
            witness: witness_identity.to_string(),
        },
        Err(_) => OfflineReceiptVerdict::SignatureFailed {
            witness: witness_identity.to_string(),
        },
    }
}

/// The outcome of verifying a node's build attestation offline — does the node
/// prove which binary it runs?
///
/// Two facts must both hold: the attestation's signature verifies against the
/// key its self-describing `did:key` issuer embeds, AND the digest it attests is
/// the digest of the binary actually running (the node's own self-measurement).
/// A forged attestation — one whose attested digest differs from the running
/// binary — fails on the second even when its signature is perfectly valid, so a
/// swapped attestation cannot pass. `Verified` is the only success arm.
///
/// This is **not** an ADR-009 freshness-bearing trust verdict, by design — so it
/// carries no `freshness` qualifier (and is named on the freshness-honesty
/// allowlist). It is a *self-measurement*, not a time-bounded authority claim:
/// `Verified` means the attested digest equals the digest of the binary running
/// right now, a present-tense fact with no "as-of" slice that could go stale.
/// There is no fresher source to compare against — the node measured itself.
/// Consumed today by `auths-witness-node` as a measurement, never as authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum OfflineBuildVerdict {
    /// The attestation's signature verifies AND it attests the running digest:
    /// the node provably runs the binary the attestation was signed over.
    Verified {
        /// The digest both attested and measured (they agree).
        digest: String,
    },
    /// The attestation could not be read as a signed artifact attestation (no
    /// payload, no digest, malformed issuer) — there is nothing to check.
    Unreadable {
        /// Why the attestation could not be interpreted.
        reason: String,
    },
    /// The attestation's signature does not verify against the key its issuer
    /// embeds — it was altered or was not produced by the claimed signer.
    SignatureFailed {
        /// The issuer the signature was checked against.
        issuer: String,
    },
    /// The signature is valid, but the attestation attests a DIFFERENT digest
    /// than the binary actually running — a forged or stale attestation, paired
    /// with a binary it does not describe.
    DigestMismatch {
        /// The digest the attestation attests.
        attested: String,
        /// The digest the node measured of its running binary.
        running: String,
    },
}

impl OfflineBuildVerdict {
    /// Whether the node provably runs the attested binary (the only success arm).
    pub fn is_verified(&self) -> bool {
        matches!(self, OfflineBuildVerdict::Verified { .. })
    }
}

/// Verify a node's build attestation offline against the digest of the binary
/// it is actually running — the "which binary does this node run?" check.
///
/// The attestation is the `auths artifact sign` document the operator produced
/// over the released binary; its self-describing `did:key` issuer embeds the
/// verification key, so `{attestation, running_digest}` is everything a relying
/// party needs. The check is deliberately two-legged and fail-closed:
///
/// 1. the signature verifies against the issuer's embedded key
///    ([`verify_with_keys`](crate::verify_with_keys)); and
/// 2. the digest the attestation attests equals `running_digest` — the digest
///    the node measured of its own executable.
///
/// A valid signature over the WRONG binary fails on leg 2
/// ([`OfflineBuildVerdict::DigestMismatch`]): an operator cannot vouch for a
/// binary they are not running by attaching a correctly-signed attestation for a
/// different one. This is the dogfood of `auths artifact verify --signature-only`
/// bound to a live self-measurement.
///
/// Args:
/// * `attestation`: the parsed signed build attestation (`auths artifact sign`).
/// * `running_digest`: the SHA-256 (hex) the node measured of its own binary.
#[cfg(feature = "native")]
pub async fn verify_build_attestation_offline(
    attestation: &crate::core::Attestation,
    running_digest: &str,
) -> OfflineBuildVerdict {
    // The attested digest lives in the artifact payload the signer covered.
    let attested = match attestation
        .payload
        .as_ref()
        .and_then(|p| p.get("digest"))
        .and_then(|d| d.get("hex"))
        .and_then(|h| h.as_str())
    {
        Some(h) => h.to_string(),
        None => {
            return OfflineBuildVerdict::Unreadable {
                reason:
                    "attestation carries no artifact digest to check against the running binary"
                        .to_string(),
            };
        }
    };

    // The issuer is a self-describing `did:key` that embeds the signing key —
    // recover it so the signature can be checked from the attestation alone.
    let issuer = attestation.issuer.as_str();
    let decoded = match did_key_decode(issuer) {
        Ok(d) => d,
        Err(e) => {
            return OfflineBuildVerdict::Unreadable {
                reason: format!("attestation issuer is not a readable did:key: {e}"),
            };
        }
    };
    let issuer_pk = match crate::core::DevicePublicKey::try_new(decoded.curve(), decoded.bytes()) {
        Ok(pk) => pk,
        Err(e) => {
            return OfflineBuildVerdict::Unreadable {
                reason: format!("attestation issuer key is unusable: {e}"),
            };
        }
    };

    // Leg 1: the signature must verify against the issuer's embedded key.
    if crate::verify_with_keys(attestation, &issuer_pk)
        .await
        .is_err()
    {
        return OfflineBuildVerdict::SignatureFailed {
            issuer: issuer.to_string(),
        };
    }

    // Leg 2: the attested digest must be the digest of the running binary.
    if attested != running_digest {
        return OfflineBuildVerdict::DigestMismatch {
            attested,
            running: running_digest.to_string(),
        };
    }

    OfflineBuildVerdict::Verified { digest: attested }
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
            t: ReceiptTag,
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
            t: ReceiptTag,
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

    /// A signed receipt and the witness's published `did:key` identity, where the
    /// identity embeds the very key that signed — exactly the self-contained
    /// pair a stranger carries to verify offline.
    fn signed_with_published_identity(event_said: &str) -> (SignedReceipt, String) {
        use auths_crypto::CurveType;
        let (kp, pk) = create_test_keypair(&[42u8; 32]);
        let signed = create_signed_receipt(&kp, "EController", event_said, 0);
        let identity = auths_verifier_did_key(&pk, CurveType::Ed25519);
        (signed, identity)
    }

    fn auths_verifier_did_key(pk: &[u8], curve: auths_crypto::CurveType) -> String {
        // Build the published did:key the same way a witness advertises it.
        crate::types::CanonicalDid::from_public_key_did_key(pk, curve).into_inner()
    }

    #[test]
    fn offline_verify_accepts_a_genuine_receipt_with_no_key_table() {
        let (signed, identity) = signed_with_published_identity("EEventOffline");
        let verdict = verify_receipt_offline(&signed, &identity);
        assert!(
            verdict.is_verified(),
            "a genuine receipt must verify against the published identity alone: {verdict:?}"
        );
    }

    #[test]
    fn offline_verify_rejects_a_bit_flipped_signature() {
        let (mut signed, identity) = signed_with_published_identity("EEventOffline");
        signed.signature[0] ^= 0x01;
        let verdict = verify_receipt_offline(&signed, &identity);
        assert_eq!(
            verdict,
            OfflineReceiptVerdict::SignatureFailed {
                witness: identity.clone()
            },
            "a tampered signature must be a distinct SignatureFailed verdict"
        );
        assert!(!verdict.is_verified());
    }

    #[test]
    fn offline_verify_rejects_a_tampered_receipt_body() {
        let (mut signed, identity) = signed_with_published_identity("EEventOffline");
        // Mutate the receipted event SAID — the signature no longer covers it.
        signed.receipt.d = Said::new_unchecked("EEventTampered".into());
        let verdict = verify_receipt_offline(&signed, &identity);
        assert!(matches!(
            verdict,
            OfflineReceiptVerdict::SignatureFailed { .. }
        ));
    }

    #[test]
    fn offline_verify_rejects_a_foreign_identity() {
        // A genuine receipt, but carried with a DIFFERENT witness's identity.
        let (signed, _genuine) = signed_with_published_identity("EEventOffline");
        let (_other_kp, other_pk) = create_test_keypair(&[7u8; 32]);
        let foreign = auths_verifier_did_key(&other_pk, auths_crypto::CurveType::Ed25519);
        let verdict = verify_receipt_offline(&signed, &foreign);
        assert!(matches!(
            verdict,
            OfflineReceiptVerdict::SignatureFailed { .. }
        ));
    }

    #[test]
    fn offline_verify_flags_an_unreadable_identity_distinctly() {
        let (signed, _identity) = signed_with_published_identity("EEventOffline");
        let verdict = verify_receipt_offline(&signed, "not-a-did-key");
        assert!(matches!(
            verdict,
            OfflineReceiptVerdict::UnreadableIdentity { .. }
        ));
    }

    // ── build attestation, offline ───────────────────────────────────────────
    // The signed-and-matching ("Verified") and forged ("DigestMismatch") arms
    // are covered end to end against a real `auths artifact sign --ci` output in
    // the conformance probe (a live node + the dogfooded signer). Here we pin
    // the fail-closed shape arms that do not need a valid signature: an
    // attestation with no digest, and one whose issuer is not a readable
    // did:key, are both Unreadable — never mistaken for a verified build.
    use crate::testing::AttestationBuilder;

    #[tokio::test]
    async fn build_verify_no_digest_is_unreadable() {
        let att = AttestationBuilder::default()
            .issuer("did:key:z6MkfooNoDigest")
            .payload(Some(serde_json::json!({ "artifact_type": "file" })))
            .build();
        let verdict = verify_build_attestation_offline(&att, "deadbeef").await;
        assert!(matches!(verdict, OfflineBuildVerdict::Unreadable { .. }));
    }

    #[tokio::test]
    async fn build_verify_unreadable_issuer_is_unreadable() {
        // A digest is present, but the issuer is not a self-describing did:key,
        // so no key can be recovered to check the signature against.
        let att = AttestationBuilder::default()
            .issuer("did:keri:ENotADidKey")
            .payload(Some(serde_json::json!({
                "digest": { "algorithm": "sha256", "hex": "abc123" }
            })))
            .build();
        let verdict = verify_build_attestation_offline(&att, "abc123").await;
        assert!(matches!(verdict, OfflineBuildVerdict::Unreadable { .. }));
    }

    #[test]
    fn build_verdict_verified_is_the_only_success_arm() {
        assert!(
            OfflineBuildVerdict::Verified {
                digest: "abc".into()
            }
            .is_verified()
        );
        assert!(
            !OfflineBuildVerdict::DigestMismatch {
                attested: "a".into(),
                running: "b".into(),
            }
            .is_verified()
        );
    }
}
