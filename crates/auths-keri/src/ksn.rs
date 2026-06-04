//! Key-State Notice (KSN) — a signed snapshot of an identity's current key-state.
//!
//! A KSN lets a thin/CI client trust a key-state without replaying the full KEL.
//! Under `kt=1` with no witnesses (`docs/architecture/multi_device_accepted_risks.md`)
//! a controller-signed KSN is **trust-on-first-sight only**: it proves "a holder
//! of the key this state names as current asserts this state" — circular until
//! Epic D adds witness receipts. It is therefore a *latency optimization*, never
//! a *trust upgrade*: never authoritative when the full KEL is resolvable, and
//! never sufficient for a revocation check (revocation is a root-KEL fact). See
//! `SignedKsn` for the verification rules.
//!
//! Wire shape (auths-only — not keripy/keria byte-interop, see Epic 4):
//! - [`KeyStateNotice`] is the controller-signed body: `{version, t:"ksn", state, dt}`.
//!   Serialized in struct-declaration order (deterministic via serde_json
//!   `preserve_order`) — the bytes the controller signs.
//! - [`SignedKsn`] wraps the body with the detached controller signature and a
//!   **reserved** `receipts` slot for Epic D witness receipts. The receipts are
//!   NOT covered by the controller signature (witnesses receipt the signed
//!   notice after the fact), so populating the slot later does not invalidate it.

use serde::{Deserialize, Serialize};

use crate::witness::StoredReceipt;
use crate::witness::agreement::{AgreementStatus, WitnessAgreement};
use crate::{CesrKey, KeyState};

/// Current KSN schema version.
pub const KSN_VERSION: u32 = 1;

/// The `t` discriminator for a Key-State Notice.
pub const KSN_TYPE: &str = "ksn";

/// Errors building or verifying a KSN.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KsnError {
    /// Serializing the notice to its canonical bytes failed.
    #[error("KSN serialization failed: {0}")]
    Serialize(String),

    /// The provided signer returned an error.
    #[error("KSN signing failed: {0}")]
    Signer(String),

    /// The notice names no current key (abandoned/empty) — nothing to sign or
    /// verify against.
    #[error("KSN names no current key")]
    NoCurrentKey,

    /// The `t` discriminator was not `"ksn"`.
    #[error("not a KSN (t = {0:?})")]
    WrongType(String),

    /// The signature did not verify against the noticed current key.
    #[error("KSN signature is invalid")]
    BadSignature,

    /// The current key could not be decoded / its curve is unsupported.
    #[error("KSN current key is undecodable: {0}")]
    UndecodableKey(String),

    /// The notice is older than a previously-trusted state for this prefix
    /// (rollback).
    #[error("KSN is stale: seq {got} < last-seen {seen}")]
    Stale {
        /// The (rejected) notice sequence.
        got: u128,
        /// The last-seen sequence for this prefix.
        seen: u128,
    },
}

/// The controller-signed body of a Key-State Notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStateNotice {
    /// Schema version.
    pub version: u32,
    /// Message type discriminator (always `"ksn"`).
    pub t: String,
    /// The key-state snapshot being noticed (carries `prefix`, `current_keys`,
    /// `sequence`, `delegator`, thresholds, backers, …).
    pub state: KeyState,
    /// Controller-asserted timestamp (RFC 3339). Injected by the caller — never
    /// `Utc::now()` in core.
    pub dt: String,
}

impl KeyStateNotice {
    /// Build a notice over `state` stamped at `dt`.
    ///
    /// Args:
    /// * `state`: The key-state to notice.
    /// * `dt`: An RFC-3339 timestamp (injected `now`).
    pub fn new(state: KeyState, dt: impl Into<String>) -> Self {
        Self {
            version: KSN_VERSION,
            t: KSN_TYPE.to_string(),
            state,
            dt: dt.into(),
        }
    }

    /// The deterministic canonical bytes the controller signs (struct-order JSON).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KsnError> {
        serde_json::to_vec(self).map_err(|e| KsnError::Serialize(e.to_string()))
    }

    /// The current signing key this notice claims, if any.
    pub fn signing_key(&self) -> Option<&CesrKey> {
        self.state.current_keys.first()
    }

    /// The noticed sequence number.
    pub fn sequence(&self) -> u128 {
        self.state.sequence
    }

    /// Whether this notice describes a *delegated* identity (a device). A
    /// delegated KSN names device state and its delegator (`state.delegator`) but
    /// is **insufficient for a revocation check** — revocation is anchored in the
    /// root KEL, not the device's own key-state.
    pub fn names_delegated_device(&self) -> bool {
        self.state.delegator.is_some()
    }
}

/// A [`KeyStateNotice`] paired with its detached controller signature and the
/// reserved Epic-D witness-receipt slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKsn {
    /// The signed notice body.
    pub notice: KeyStateNotice,
    /// The controller signature over `notice.canonical_bytes()`, hex-encoded for
    /// JSON.
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
    /// Witness receipts over the noticed establishment event (Epic D), each
    /// carrying its **witness AID** ([`StoredReceipt`]). NOT covered by the
    /// controller signature — witnesses receipt the signed notice after the fact,
    /// so populating this slot never invalidates the controller signature. Empty
    /// (and omitted) leaves the verdict at trust-on-first-sight.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<StoredReceipt>,
}

impl SignedKsn {
    /// Build a signed KSN by signing the notice's canonical bytes with `signer`.
    ///
    /// `signer` is a closure that returns the detached signature for the given
    /// bytes — keychain-backed in production, a test key in tests. The reserved
    /// `receipts` slot starts empty.
    ///
    /// Args:
    /// * `notice`: The notice body to sign.
    /// * `signer`: Produces the signature over the canonical bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let signed = SignedKsn::sign_with(notice, |bytes| key_ops_sign(seed, bytes))?;
    /// ```
    pub fn sign_with(
        notice: KeyStateNotice,
        signer: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<Self, KsnError> {
        if notice.signing_key().is_none() {
            return Err(KsnError::NoCurrentKey);
        }
        let bytes = notice.canonical_bytes()?;
        let signature = signer(&bytes).map_err(KsnError::Signer)?;
        Ok(Self {
            notice,
            signature,
            receipts: Vec::new(),
        })
    }

    /// Attach witness receipts to a signed notice, admitting only those that are
    /// cryptographically valid for *this* notice.
    ///
    /// A candidate is kept only if it (a) receipts the noticed establishment event
    /// (`state.last_event_said`), (b) is from a witness in `state.backers`, and
    /// (c) carries a signature that verifies against that witness's pinned key.
    /// The slot is outside the controller-signed bytes, so attaching never
    /// invalidates the controller signature.
    ///
    /// Args:
    /// * `candidates`: Collected receipts to vet and attach.
    ///
    /// Usage:
    /// ```ignore
    /// let published = signed.with_receipts(collected);
    /// ```
    pub fn with_receipts(mut self, candidates: Vec<StoredReceipt>) -> Self {
        let state = &self.notice.state;
        let said = state.last_event_said.clone();
        let valid: Vec<StoredReceipt> = candidates
            .into_iter()
            .filter(|r| {
                r.signed.receipt.d == said
                    && state.backers.iter().any(|b| b == &r.witness)
                    && receipt_signature_valid(r)
            })
            .collect();
        self.receipts = valid;
        self
    }

    /// Verify a KSN and return its (trust-on-first-sight) verdict.
    ///
    /// The full forgery-rejection checklist:
    /// 1. `t` is `"ksn"` (else [`KsnError::WrongType`]).
    /// 2. the notice names a current key (else [`KsnError::NoCurrentKey`]).
    /// 3. that key decodes (curve from its CESR tag; else [`KsnError::UndecodableKey`]).
    /// 4. the signature verifies over the notice's canonical bytes by that key —
    ///    i.e. the signer **is** the key the state names as current (self-attested);
    ///    else [`KsnError::BadSignature`].
    ///
    /// This does NOT check freshness — call [`SignedKsn::check_not_stale`] against
    /// the last-trusted sequence to reject a rollback. A bare KSN is
    /// trust-on-first-sight: see [`VerifiedKsn`].
    pub fn verify(&self) -> Result<VerifiedKsn, KsnError> {
        if self.notice.t != KSN_TYPE {
            return Err(KsnError::WrongType(self.notice.t.clone()));
        }
        let key_cesr = self.notice.signing_key().ok_or(KsnError::NoCurrentKey)?;
        let key = crate::KeriPublicKey::parse(key_cesr.as_str())
            .map_err(|e| KsnError::UndecodableKey(e.to_string()))?;
        let bytes = self.notice.canonical_bytes()?;
        key.verify_signature(&bytes, &self.signature)
            .map_err(|_| KsnError::BadSignature)?;
        Ok(VerifiedKsn {
            state: self.notice.state.clone(),
            trust: self.witness_trust(),
        })
    }

    /// The witness-quorum trust upgrade over the slot's receipts.
    ///
    /// Runs KAWA ([`WitnessAgreement`]) over the receipts that attest the noticed
    /// establishment event (`state.last_event_said`) from witnesses in
    /// `state.backers`, deduped by witness AID. M-of-N (`state.backer_threshold`)
    /// met → [`KsnTrust::Witnessed`]; otherwise [`KsnTrust::TrustOnFirstSight`].
    /// A `bt=0` / backerless KSN stays trust-on-first-sight.
    fn witness_trust(&self) -> KsnTrust {
        let state = &self.notice.state;
        let required = state.backer_threshold.simple_value().unwrap_or(0) as usize;
        if state.backers.is_empty() || required == 0 {
            return KsnTrust::TrustOnFirstSight;
        }

        let said = &state.last_event_said;
        let sn = state.sequence as u64;
        let agreement = WitnessAgreement::new(1);
        agreement.submit_event(
            &state.prefix,
            sn,
            said,
            &state.backer_threshold,
            &state.backers,
        );

        let mut distinct = std::collections::HashSet::new();
        for r in &self.receipts {
            // Only correct-SAID, designated-witness receipts count toward quorum;
            // KAWA additionally dedupes and ignores non-designated witnesses.
            if &r.signed.receipt.d == said && state.backers.iter().any(|b| b == &r.witness) {
                agreement.add_receipt(&state.prefix, sn, said, r.witness.as_str());
                distinct.insert(r.witness.as_str());
            }
        }

        match agreement.status(&state.prefix, sn, said) {
            AgreementStatus::Accepted => KsnTrust::Witnessed {
                receipts: distinct.len(),
                threshold: required,
            },
            AgreementStatus::Pending { .. } => KsnTrust::TrustOnFirstSight,
        }
    }

    /// Monotonicity guard: reject a notice older than a previously-trusted
    /// sequence for this prefix (a rollback / replay of stale state).
    ///
    /// Args:
    /// * `last_seen_seq`: The highest sequence already trusted for this prefix.
    pub fn check_not_stale(&self, last_seen_seq: u128) -> Result<(), KsnError> {
        let got = self.notice.sequence();
        if got < last_seen_seq {
            return Err(KsnError::Stale {
                got,
                seen: last_seen_seq,
            });
        }
        Ok(())
    }
}

/// Verify a stored receipt's detached signature against its pinned witness key
/// (curve-correct via the AID's CESR tag). Reused by attach-time vetting.
fn receipt_signature_valid(stored: &StoredReceipt) -> bool {
    let Ok(key) = crate::KeriPublicKey::parse(stored.witness.as_str()) else {
        return false;
    };
    let Ok(payload) = serde_json::to_vec(&stored.signed.receipt) else {
        return false;
    };
    key.verify_signature(&payload, &stored.signed.signature)
        .is_ok()
}

/// The trust level a verified KSN confers.
///
/// Under `kt=1` with no witnesses, a controller-signed KSN is only
/// trust-on-first-sight — Epic D will add a `Witnessed` level once backer
/// receipts populate the reserved [`SignedKsn::receipts`] slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KsnTrust {
    /// Controller-signed only: proves "a holder of the key this state names as
    /// current asserts this state" — circular under `kt=1`. A latency
    /// optimization, never a trust upgrade.
    TrustOnFirstSight,
    /// Controller-signed **and** witness-receipted: M-of-N designated witnesses
    /// (`state.backers`/`backer_threshold`) receipted the noticed establishment
    /// event. No longer trust-on-first-sight — but still never authoritative over
    /// a resolvable KEL, and a delegated-device KSN still cannot prove
    /// non-revocation (a root-KEL fact). See [`VerifiedKsn`].
    Witnessed {
        /// Distinct, designated, correct-SAID witness receipts counted.
        receipts: usize,
        /// The required backer threshold (`bt`).
        threshold: usize,
    },
}

/// A verified Key-State Notice and the trust it confers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKsn {
    /// The verified key-state.
    pub state: KeyState,
    /// The trust level (TOFU in v1).
    pub trust: KsnTrust,
}

impl VerifiedKsn {
    /// Whether this KSN may be trusted **over** a resolvable full KEL. Always
    /// `false`, even when [`KsnTrust::Witnessed`]: when the KEL is available,
    /// replay it — a KSN (witnessed or not) is only a shortcut for clients that
    /// cannot. Witnessing changes the trust level consumers gate on, not this
    /// invariant.
    pub fn is_authoritative_over_kel(&self) -> bool {
        false
    }

    /// Whether this KSN may satisfy a revocation check. Always `false`, even when
    /// [`KsnTrust::Witnessed`]: revocation is anchored in the root KEL as an
    /// `ixn` fact, not a device's self-asserted key-state, and witness receipts
    /// attest the *establishment event*, not non-revocation.
    pub fn satisfies_revocation_check(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{KeriPublicKey, Prefix, Said, Threshold};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn real_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    /// A key-state whose current key is `kp`'s public key (CESR-encoded).
    fn state_for_key(kp: &Ed25519KeyPair, seq: u128) -> KeyState {
        let cesr = KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        let mut state = key_state(seq, false);
        state.current_keys = vec![CesrKey::new_unchecked(cesr)];
        state
    }

    fn sign_ksn(kp: &Ed25519KeyPair, notice: KeyStateNotice) -> SignedKsn {
        SignedKsn::sign_with(notice, |bytes| Ok(kp.sign(bytes).as_ref().to_vec())).unwrap()
    }

    fn key_state(seq: u128, delegated: bool) -> KeyState {
        let key = KeriPublicKey::ed25519(&[3u8; 32]).unwrap();
        let mut state = KeyState::from_inception(
            Prefix::new_unchecked("EksnTestPrefix000000000000000000000000000000".to_string()),
            vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            vec![Said::new_unchecked(
                "ENextCommitment0000000000000000000000000000".to_string(),
            )],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ELastEvent00000000000000000000000000000000000".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        );
        state.sequence = seq;
        if delegated {
            state.delegator = Some(Prefix::new_unchecked(
                "ERootDelegator00000000000000000000000000000".to_string(),
            ));
        }
        state
    }

    #[test]
    fn canonical_bytes_is_deterministic() {
        let notice = KeyStateNotice::new(key_state(2, false), "2026-06-03T00:00:00Z");
        assert_eq!(
            notice.canonical_bytes().unwrap(),
            notice.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn sign_with_and_round_trips() {
        let notice = KeyStateNotice::new(key_state(0, false), "2026-06-03T00:00:00Z");
        let signed = SignedKsn::sign_with(notice, |_| Ok(vec![7u8; 64])).unwrap();
        assert_eq!(signed.signature, vec![7u8; 64]);
        assert!(signed.receipts.is_empty());

        let json = serde_json::to_string(&signed).unwrap();
        // The empty reserved slot is omitted on the wire...
        assert!(!json.contains("receipts"));
        // ...and round-trips back to an equal value (receipts default to empty).
        let parsed: SignedKsn = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, signed);
    }

    #[test]
    fn sign_with_rejects_no_current_key() {
        let mut state = key_state(0, false);
        state.current_keys.clear();
        let notice = KeyStateNotice::new(state, "2026-06-03T00:00:00Z");
        let err = SignedKsn::sign_with(notice, |_| Ok(vec![0u8; 64])).unwrap_err();
        assert!(matches!(err, KsnError::NoCurrentKey));
    }

    #[test]
    fn signer_error_propagates() {
        let notice = KeyStateNotice::new(key_state(0, false), "2026-06-03T00:00:00Z");
        let err = SignedKsn::sign_with(notice, |_| Err("keychain locked".to_string())).unwrap_err();
        assert!(matches!(err, KsnError::Signer(_)));
    }

    #[test]
    fn delegated_device_is_flagged() {
        assert!(KeyStateNotice::new(key_state(1, true), "t").names_delegated_device());
        assert!(!KeyStateNotice::new(key_state(1, false), "t").names_delegated_device());
    }

    #[test]
    fn verify_accepts_valid_ksn() {
        let kp = real_keypair();
        let notice = KeyStateNotice::new(state_for_key(&kp, 1), "2026-06-03T00:00:00Z");
        let signed = sign_ksn(&kp, notice);
        let verified = signed.verify().unwrap();
        assert_eq!(verified.trust, KsnTrust::TrustOnFirstSight);
        // A KSN is never authoritative over a KEL and never satisfies revocation.
        assert!(!verified.is_authoritative_over_kel());
        assert!(!verified.satisfies_revocation_check());
    }

    #[test]
    fn verify_rejects_tampered_notice() {
        let kp = real_keypair();
        let notice = KeyStateNotice::new(state_for_key(&kp, 1), "2026-06-03T00:00:00Z");
        let mut signed = sign_ksn(&kp, notice);
        signed.notice.dt = "2099-01-01T00:00:00Z".to_string(); // mutate after signing
        assert!(matches!(signed.verify(), Err(KsnError::BadSignature)));
    }

    #[test]
    fn verify_rejects_signature_by_non_current_key() {
        let signer = real_keypair();
        let other = real_keypair();
        // The state names `other` as current, but `signer` produced the signature.
        let notice = KeyStateNotice::new(state_for_key(&other, 1), "2026-06-03T00:00:00Z");
        let signed = sign_ksn(&signer, notice);
        assert!(matches!(signed.verify(), Err(KsnError::BadSignature)));
    }

    #[test]
    fn verify_rejects_unsigned_or_garbage_signature() {
        let kp = real_keypair();
        let notice = KeyStateNotice::new(state_for_key(&kp, 1), "2026-06-03T00:00:00Z");
        let mut signed = sign_ksn(&kp, notice);
        signed.signature = vec![0u8; 64]; // a forged / unsigned signature
        assert!(matches!(signed.verify(), Err(KsnError::BadSignature)));
    }

    #[test]
    fn verify_rejects_wrong_type() {
        let kp = real_keypair();
        let mut notice = KeyStateNotice::new(state_for_key(&kp, 1), "t");
        notice.t = "rpy".to_string();
        let signed = sign_ksn(&kp, notice);
        assert!(matches!(signed.verify(), Err(KsnError::WrongType(_))));
    }

    #[test]
    fn check_not_stale_rejects_rollback() {
        let kp = real_keypair();
        let signed = sign_ksn(&kp, KeyStateNotice::new(state_for_key(&kp, 2), "t"));
        assert!(matches!(
            signed.check_not_stale(3),
            Err(KsnError::Stale { .. })
        ));
        assert!(signed.check_not_stale(2).is_ok());
        assert!(signed.check_not_stale(1).is_ok());
    }

    // ── D.13: KSN witness-hardening ──────────────────────────────────────────

    use crate::witness::{Receipt, ReceiptTag, SignedReceipt};
    use crate::{KeriSequence, VersionString};

    /// A witness keypair and its CESR AID (`D…`).
    fn witness_kp_and_aid() -> (Ed25519KeyPair, String) {
        let kp = real_keypair();
        let aid = KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        (kp, aid)
    }

    /// A stored receipt by `witness_kp` (AID `witness_aid`) over `(controller, seq, event_said)`.
    fn witness_receipt(
        witness_kp: &Ed25519KeyPair,
        witness_aid: &str,
        controller: &str,
        seq: u128,
        event_said: &str,
    ) -> StoredReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: Said::new_unchecked(event_said.to_string()),
            i: Prefix::new_unchecked(controller.to_string()),
            s: KeriSequence::new(seq),
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        let signature = witness_kp.sign(&payload).as_ref().to_vec();
        StoredReceipt {
            signed: SignedReceipt { receipt, signature },
            witness: Prefix::new_unchecked(witness_aid.to_string()),
        }
    }

    /// A controller key-state at `seq` designating `backers` with threshold `bt`.
    fn witnessed_state(
        controller_kp: &Ed25519KeyPair,
        seq: u128,
        backers: &[&str],
        bt: u64,
        delegated: bool,
    ) -> KeyState {
        let mut state = state_for_key(controller_kp, seq);
        state.backers = backers
            .iter()
            .map(|a| Prefix::new_unchecked(a.to_string()))
            .collect();
        state.backer_threshold = Threshold::Simple(bt);
        if delegated {
            state.delegator = Some(Prefix::new_unchecked(
                "ERootDelegator00000000000000000000000000000".to_string(),
            ));
        }
        state
    }

    #[test]
    fn ksn_witnessed_when_quorum_met() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (w2kp, w2) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2], 2, false);
        let controller = state.prefix.as_str().to_string();
        let said = state.last_event_said.as_str().to_string();
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t")).with_receipts(vec![
            witness_receipt(&w1kp, &w1, &controller, 1, &said),
            witness_receipt(&w2kp, &w2, &controller, 1, &said),
        ]);
        assert_eq!(
            signed.verify().unwrap().trust,
            KsnTrust::Witnessed {
                receipts: 2,
                threshold: 2
            }
        );
    }

    #[test]
    fn ksn_stays_tofu_under_quorum() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (_w2kp, w2) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2], 2, false);
        let controller = state.prefix.as_str().to_string();
        let said = state.last_event_said.as_str().to_string();
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t"))
            .with_receipts(vec![witness_receipt(&w1kp, &w1, &controller, 1, &said)]);
        assert_eq!(signed.verify().unwrap().trust, KsnTrust::TrustOnFirstSight);
    }

    #[test]
    fn ksn_ignores_duplicate_witness_receipts() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (_w2kp, w2) = witness_kp_and_aid();
        let (_w3kp, w3) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2, &w3], 2, false);
        let controller = state.prefix.as_str().to_string();
        let said = state.last_event_said.as_str().to_string();
        // The same witness twice must not satisfy a threshold of 2.
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t")).with_receipts(vec![
            witness_receipt(&w1kp, &w1, &controller, 1, &said),
            witness_receipt(&w1kp, &w1, &controller, 1, &said),
        ]);
        assert_eq!(signed.verify().unwrap().trust, KsnTrust::TrustOnFirstSight);
    }

    #[test]
    fn ksn_ignores_receipt_for_wrong_said() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (w2kp, w2) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2], 2, false);
        let controller = state.prefix.as_str().to_string();
        // Receipts for a different event SAID must not count — set directly to
        // exercise verify()'s own filtering (not just attach-time vetting).
        let mut signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t"));
        let wrong = "EWrongEventSaid0000000000000000000000000000";
        signed.receipts = vec![
            witness_receipt(&w1kp, &w1, &controller, 1, wrong),
            witness_receipt(&w2kp, &w2, &controller, 1, wrong),
        ];
        assert_eq!(signed.verify().unwrap().trust, KsnTrust::TrustOnFirstSight);
    }

    #[test]
    fn ksn_bt_zero_stays_tofu() {
        // A backerless (bt=0) KSN has no witnesses to satisfy.
        let ckp = real_keypair();
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state_for_key(&ckp, 1), "t"));
        assert_eq!(signed.verify().unwrap().trust, KsnTrust::TrustOnFirstSight);
    }

    #[test]
    fn witnessed_device_ksn_still_refuses_revocation() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (w2kp, w2) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2], 2, true); // delegated device
        let controller = state.prefix.as_str().to_string();
        let said = state.last_event_said.as_str().to_string();
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t")).with_receipts(vec![
            witness_receipt(&w1kp, &w1, &controller, 1, &said),
            witness_receipt(&w2kp, &w2, &controller, 1, &said),
        ]);
        let v = signed.verify().unwrap();
        assert!(matches!(v.trust, KsnTrust::Witnessed { .. }));
        // Witnessed, but a device KSN still cannot prove non-revocation or override the KEL.
        assert!(!v.satisfies_revocation_check());
        assert!(!v.is_authoritative_over_kel());
    }

    #[test]
    fn populating_receipts_preserves_controller_signature() {
        let ckp = real_keypair();
        let (w1kp, w1) = witness_kp_and_aid();
        let (w2kp, w2) = witness_kp_and_aid();
        let state = witnessed_state(&ckp, 1, &[&w1, &w2], 2, false);
        let controller = state.prefix.as_str().to_string();
        let said = state.last_event_said.as_str().to_string();
        let signed = sign_ksn(&ckp, KeyStateNotice::new(state, "t"));
        assert!(signed.verify().is_ok()); // controller sig valid before receipts

        let published = signed.with_receipts(vec![
            witness_receipt(&w1kp, &w1, &controller, 1, &said),
            witness_receipt(&w2kp, &w2, &controller, 1, &said),
        ]);
        // Attaching receipts (outside canonical_bytes) does not break the controller signature.
        let v = published
            .verify()
            .expect("controller signature must still verify after attaching receipts");
        assert!(matches!(v.trust, KsnTrust::Witnessed { .. }));
    }
}
