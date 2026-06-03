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

use crate::witness::SignedReceipt;
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
    /// Reserved for Epic D witness receipts. NOT covered by the controller
    /// signature; empty (and omitted) in v1 (trust-on-first-sight).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<SignedReceipt>,
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
            trust: KsnTrust::TrustOnFirstSight,
        })
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
    /// `false`: when the KEL is available, replay it — a KSN is only a shortcut
    /// for clients that cannot.
    pub fn is_authoritative_over_kel(&self) -> bool {
        false
    }

    /// Whether this KSN may satisfy a revocation check. Always `false` in v1:
    /// revocation is anchored in the root KEL, not a device's self-asserted
    /// key-state, and a TOFU notice cannot prove non-revocation.
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
}
