//! Single chokepoint for witness-receipt verification.
//!
//! KAWA quorum must count only receipts whose signatures verify against the
//! *pinned* witness AID. [`verify_receipt`] is the **sole** constructor of
//! [`VerifiedReceipt`], and the collector's quorum counter accepts only
//! `VerifiedReceipt`. Counting an unverified [`StoredReceipt`] is therefore not
//! representable — a forged, foreign, or wrong-event receipt cannot reach the
//! threshold even if a future caller forgets to check it.

use std::ops::Deref;

use auths_keri::{KeriPublicKey, Said};

use super::error::WitnessError;
use super::receipt::StoredReceipt;

/// A [`StoredReceipt`] whose signature has been verified against its pinned
/// witness AID and whose receipted SAID matches the submitted event.
///
/// The only way to obtain one is [`verify_receipt`]. `Deref`s to the underlying
/// [`StoredReceipt`] so existing field access (`.witness`, `.signed`) keeps
/// working at call sites.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt(StoredReceipt);

impl VerifiedReceipt {
    /// Consume the wrapper, yielding the underlying verified [`StoredReceipt`].
    ///
    /// Args:
    /// * `self`: The verified receipt.
    ///
    /// Usage:
    /// ```ignore
    /// let stored: StoredReceipt = verified.into_stored();
    /// ```
    pub fn into_stored(self) -> StoredReceipt {
        self.0
    }

    /// Borrow the underlying verified [`StoredReceipt`].
    ///
    /// Args:
    /// * `self`: The verified receipt.
    ///
    /// Usage:
    /// ```ignore
    /// let aid = verified.as_stored().witness.as_str();
    /// ```
    pub fn as_stored(&self) -> &StoredReceipt {
        &self.0
    }
}

impl Deref for VerifiedReceipt {
    type Target = StoredReceipt;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Verify a collected receipt against its pinned witness AID and the submitted event.
///
/// Returns a [`VerifiedReceipt`] only when ALL of the following hold:
/// 1. the receipt's body `d` equals `expected_said` (the SAID of the event that
///    was submitted) — a receipt for a different event is rejected;
/// 2. the pinned `StoredReceipt.witness` AID parses as a curve-tagged KERI verkey
///    (P-256 `1AAI…`/`1AAJ…` or Ed25519 `D…`; never byte-length dispatch);
/// 3. `SignedReceipt.signature` verifies over the canonical receipt bytes using
///    the *witness* key — never the receipt body's controller `i`.
///
/// The signed bytes are `serde_json::to_vec(&receipt)`, matching exactly what the
/// witness server signs when it issues the receipt.
///
/// Args:
/// * `stored`: The receipt as collected, attributed to its pinned witness AID.
/// * `expected_said`: SAID of the key event that was submitted for receipting.
///
/// Usage:
/// ```ignore
/// let verified = verify_receipt(stored, &event_said)?;
/// quorum.push(verified); // only a VerifiedReceipt can be counted
/// ```
pub fn verify_receipt(
    stored: StoredReceipt,
    expected_said: &Said,
) -> Result<VerifiedReceipt, WitnessError> {
    if stored.signed.receipt.d != *expected_said {
        return Err(WitnessError::SaidMismatch {
            expected: expected_said.clone(),
            got: stored.signed.receipt.d.clone(),
        });
    }

    let witness_id = stored.witness.as_str().to_string();
    let witness_key = KeriPublicKey::parse(stored.witness.as_str()).map_err(|e| {
        WitnessError::InvalidSignature {
            witness_id: format!("{witness_id}: unparseable witness AID: {e}"),
        }
    })?;

    let payload = serde_json::to_vec(&stored.signed.receipt)
        .map_err(|e| WitnessError::Serialization(e.to_string()))?;

    witness_key
        .verify_signature(&payload, &stored.signed.signature)
        .map_err(|_| WitnessError::InvalidSignature { witness_id })?;

    Ok(VerifiedReceipt(stored))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_keri::witness::{Receipt, ReceiptTag, SignedReceipt};
    use auths_keri::{KeriSequence, Prefix, VersionString};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const EVENT_SAID: &str = "EEvent00000000000000000000000000000000000000";
    const OTHER_SAID: &str = "EOther00000000000000000000000000000000000000";
    const CONTROLLER: &str = "EController0000000000000000000000000000000000";

    fn said(s: &str) -> Said {
        Said::new_unchecked(s.to_string())
    }

    /// A fresh Ed25519 keypair and its CESR `D…` verkey AID.
    fn ed25519_keypair() -> (Ed25519KeyPair, Prefix) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let aid = KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        (kp, Prefix::new_unchecked(aid))
    }

    fn receipt_for(event_said: &str) -> Receipt {
        Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: said(event_said),
            i: Prefix::new_unchecked(CONTROLLER.to_string()),
            s: KeriSequence::new(0),
        }
    }

    fn ed25519_signed(kp: &Ed25519KeyPair, event_said: &str) -> SignedReceipt {
        let receipt = receipt_for(event_said);
        let payload = serde_json::to_vec(&receipt).unwrap();
        let signature = kp.sign(&payload).as_ref().to_vec();
        SignedReceipt { receipt, signature }
    }

    #[test]
    fn ed25519_valid_receipt_verifies() {
        let (kp, aid) = ed25519_keypair();
        let stored = StoredReceipt {
            signed: ed25519_signed(&kp, EVENT_SAID),
            witness: aid.clone(),
        };

        let verified = verify_receipt(stored, &said(EVENT_SAID)).unwrap();
        assert_eq!(verified.witness, aid);
    }

    #[test]
    fn forged_signature_rejected() {
        let (kp, aid) = ed25519_keypair();
        let mut signed = ed25519_signed(&kp, EVENT_SAID);
        signed.signature = vec![0u8; 64];
        let stored = StoredReceipt {
            signed,
            witness: aid,
        };

        assert!(matches!(
            verify_receipt(stored, &said(EVENT_SAID)),
            Err(WitnessError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn signature_from_wrong_key_rejected() {
        // Genuinely signed by `signer`, but pinned to a different witness AID.
        let (signer, _signer_aid) = ed25519_keypair();
        let (_pinned_kp, pinned_aid) = ed25519_keypair();
        let stored = StoredReceipt {
            signed: ed25519_signed(&signer, EVENT_SAID),
            witness: pinned_aid,
        };

        assert!(matches!(
            verify_receipt(stored, &said(EVENT_SAID)),
            Err(WitnessError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn wrong_said_rejected() {
        let (kp, aid) = ed25519_keypair();
        let stored = StoredReceipt {
            signed: ed25519_signed(&kp, OTHER_SAID),
            witness: aid,
        };

        assert!(matches!(
            verify_receipt(stored, &said(EVENT_SAID)),
            Err(WitnessError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn unparseable_aid_rejected() {
        let (kp, _aid) = ed25519_keypair();
        let stored = StoredReceipt {
            signed: ed25519_signed(&kp, EVENT_SAID),
            witness: Prefix::new_unchecked("not-a-cesr-verkey".to_string()),
        };

        assert!(matches!(
            verify_receipt(stored, &said(EVENT_SAID)),
            Err(WitnessError::InvalidSignature { .. })
        ));
    }

    /// A P-256 keypair and its CESR `1AAJ…` verkey AID, plus a signer over bytes.
    fn p256_signed(event_said: &str) -> (StoredReceipt, Said) {
        use auths_crypto::CurveType;
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let compressed = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let aid = KeriPublicKey::from_verkey_bytes(&compressed, CurveType::P256)
            .unwrap()
            .to_qb64()
            .unwrap();

        let receipt = receipt_for(event_said);
        let payload = serde_json::to_vec(&receipt).unwrap();
        let sig: Signature = sk.sign(&payload);
        let signed = SignedReceipt {
            receipt,
            signature: sig.to_bytes().to_vec(),
        };
        (
            StoredReceipt {
                signed,
                witness: Prefix::new_unchecked(aid),
            },
            said(event_said),
        )
    }

    #[test]
    fn p256_valid_receipt_verifies() {
        let (stored, expected) = p256_signed(EVENT_SAID);
        assert!(verify_receipt(stored, &expected).is_ok());
    }

    #[test]
    fn p256_wrong_said_rejected() {
        let (stored, _) = p256_signed(OTHER_SAID);
        assert!(matches!(
            verify_receipt(stored, &said(EVENT_SAID)),
            Err(WitnessError::SaidMismatch { .. })
        ));
    }
}
