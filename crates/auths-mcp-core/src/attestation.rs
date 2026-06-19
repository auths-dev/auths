//! Independent rail attestation — the cost a settled call is audited at must be the rail
//! FACILITATOR's own signed statement of what it charged, not a number the operator merely claims.
//!
//! The per-call settlement is signed by the AGENT, and the rail response is held (and forgeable) by
//! the OPERATOR — so a party that is both agent and operator can fabricate a self-consistent
//! (response, settlement) pair and under-report magnitude. The defence is a value the operator cannot
//! mint: [`Attested<Cents>`], obtainable ONLY by verifying a facilitator signature over the charged
//! `{reference, amount}`. The offline audit sums `Attested<Cents>`, so an un-attested number cannot
//! enter the audited total — the trust-the-operator-bytes path is closed at the type level.
//!
//! The facilitator's signature is verified OFFLINE from the recorded attestation (no network); a live
//! on-chain check (decode the transfer value of the settlement's transaction) is a separate opt-in
//! layer that never blocks this offline audit.

use crate::money::Cents;
use serde::{Deserialize, Serialize};

/// A cost the rail's FACILITATOR independently attested. The inner value is private and there is no
/// public constructor: an `Attested<T>` can be obtained only from [`Attested::from_facilitator`],
/// which verifies the facilitator's signature. So a cost no facilitator signed can never become
/// `Attested`, and the audited total — which sums `Attested<Cents>` — cannot admit an operator's bare
/// claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Attested<T>(T);

impl Attested<Cents> {
    /// The independently-attested amount.
    pub fn amount(self) -> Cents {
        self.0
    }
}

/// The rail facilitator's signed statement of one settled charge — the rail's OWN attestation of what
/// it charged, signed by the facilitator's key (independent of the operator and the agent). Stored in
/// the spend log so the offline audit re-verifies it without trusting the operator's response bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailAttestation {
    /// The rail-native charge reference the attestation is over (a payment-id / on-chain tx hash).
    pub reference: String,
    /// The amount, in cents, the facilitator attests was charged.
    pub amount_cents: Cents,
    /// The facilitator's raw signature over the canonical `{reference, amount_cents}` bytes.
    pub facilitator_sig: Vec<u8>,
}

/// Why an attestation failed to verify. Every case fails CLOSED — no [`Attested`] is minted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    /// The facilitator signature did not verify over the canonical `{reference, amount}` — the
    /// recorded amount, reference, or signature was altered, or the wrong facilitator key was used.
    #[error("the facilitator signature did not verify over the attested charge")]
    BadSignature,
    /// The `{reference, amount}` could not be canonicalized into the bytes to verify.
    #[error("the attestation could not be canonicalized: {0}")]
    Canonicalize(String),
}

impl RailAttestation {
    /// The canonical bytes the facilitator signs and the audit verifies — RFC-8785 JSON of
    /// `{reference, amount_cents}`. Altering either field changes these bytes, so the signature no
    /// longer verifies; this is exactly what binds the attested amount to the facilitator's key.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        let body = serde_json::json!({
            "reference": self.reference,
            "amount_cents": self.amount_cents.get(),
        });
        json_canon::to_string(&body)
            .map(String::into_bytes)
            .map_err(|e| AttestationError::Canonicalize(e.to_string()))
    }
}

impl Attested<Cents> {
    /// Mint an [`Attested<Cents>`] by verifying the facilitator's signature over the attested charge.
    /// This is the ONLY constructor — there is no `Attested::new` — so a cost no facilitator signed
    /// can never become `Attested`. `facilitator_pubkey` is the rail facilitator's Ed25519 public key,
    /// known independently of the operator (pinned / configured), never read from the record.
    ///
    /// Args:
    /// * `attestation`: the recorded facilitator attestation to verify.
    /// * `facilitator_pubkey`: the facilitator's 32-byte Ed25519 public key, pinned independently.
    ///
    /// Usage:
    /// ```ignore
    /// let attested = Attested::from_facilitator(&attestation, &facilitator_pubkey)?;
    /// let cents = attested.amount();
    /// ```
    pub fn from_facilitator(
        attestation: &RailAttestation,
        facilitator_pubkey: &[u8],
    ) -> Result<Attested<Cents>, AttestationError> {
        let bytes = attestation.signed_bytes()?;
        auths_crypto::RingCryptoProvider::ed25519_verify(
            facilitator_pubkey,
            &bytes,
            &attestation.facilitator_sig,
        )
        .map_err(|_| AttestationError::BadSignature)?;
        Ok(Attested(attestation.amount_cents))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deterministic test facilitator keypair. In production the facilitator key is the rail's own,
    // independent of the operator; here a fixed seed lets the test sign an attestation and pin the
    // matching public key.
    const FACILITATOR_SEED: [u8; 32] = [7u8; 32];

    fn facilitator_pubkey() -> [u8; 32] {
        auths_crypto::RingCryptoProvider::ed25519_public_key(&FACILITATOR_SEED).unwrap()
    }

    fn signed(reference: &str, cents: u64) -> RailAttestation {
        let unsigned = RailAttestation {
            reference: reference.to_string(),
            amount_cents: Cents::new(cents),
            facilitator_sig: Vec::new(),
        };
        let bytes = unsigned.signed_bytes().unwrap();
        let facilitator_sig =
            auths_crypto::RingCryptoProvider::ed25519_sign(&FACILITATOR_SEED, &bytes).unwrap();
        RailAttestation {
            facilitator_sig,
            ..unsigned
        }
    }

    #[test]
    fn a_facilitator_signed_attestation_mints_attested() {
        let att = signed("ch_test_123", 300);
        let attested = Attested::from_facilitator(&att, &facilitator_pubkey()).unwrap();
        assert_eq!(attested.amount(), Cents::new(300));
    }

    #[test]
    fn lowering_the_attested_amount_is_caught() {
        // An operator that re-writes the recorded amount down to under-report magnitude: the
        // signature is over the ORIGINAL amount, so verification fails and no Attested is minted.
        let mut att = signed("ch_test_123", 5000);
        att.amount_cents = Cents::new(50);
        assert_eq!(
            Attested::from_facilitator(&att, &facilitator_pubkey()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn altering_the_reference_is_caught() {
        let mut att = signed("ch_test_123", 300);
        att.reference = "ch_swapped_999".to_string();
        assert_eq!(
            Attested::from_facilitator(&att, &facilitator_pubkey()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_signature_is_caught() {
        let mut att = signed("ch_test_123", 300);
        att.facilitator_sig[0] ^= 0xff;
        assert_eq!(
            Attested::from_facilitator(&att, &facilitator_pubkey()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn a_different_facilitator_key_is_caught() {
        // A signature from some other key is not the pinned facilitator's — refused.
        let att = signed("ch_test_123", 300);
        let other = auths_crypto::RingCryptoProvider::ed25519_public_key(&[9u8; 32]).unwrap();
        assert_eq!(
            Attested::from_facilitator(&att, &other),
            Err(AttestationError::BadSignature)
        );
    }
}
