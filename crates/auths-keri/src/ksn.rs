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

use crate::events::Event;
use crate::types::{ConfigTrait, Prefix, Said, Threshold};
use crate::witness::StoredReceipt;
use crate::witness::agreement::{AgreementStatus, WitnessAgreement};
use crate::{CesrKey, KeyState};

/// Current KSN schema version.
pub const KSN_VERSION: u32 = 1;

/// The `t` discriminator for a Key-State Notice.
pub const KSN_TYPE: &str = "ksn";

/// The KERI protocol major/minor version a key-state record reports in `vn`.
/// Matches the `KERI10` wire generation (keripy `KeyStateRecord.vn == [1, 0]`).
pub const KERI_KEY_STATE_VERSION: [u32; 2] = [1, 0];

/// The latest establishment-event summary carried in a [`KeyStateRecord`] `ee`
/// field: the sequence and SAID of the most recent `icp`/`rot`/`dip`/`drt`, plus
/// the witnesses cut (`br`) and added (`ba`) by that event.
///
/// Mirrors keripy's `KeyStateRecord.ee` sub-record (`{s, d, br, ba}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestEstablishmentEvent {
    /// Sequence number of the latest establishment event, lowercase-hex (`"0"`).
    pub s: String,
    /// SAID of the latest establishment event.
    pub d: Said,
    /// Witnesses removed by the latest establishment event (rotation cuts).
    #[serde(default)]
    pub br: Vec<Prefix>,
    /// Witnesses added by the latest establishment event (rotation adds).
    #[serde(default)]
    pub ba: Vec<Prefix>,
}

/// A **KERI-conformant key-state notice** — the wire record keripy emits as a
/// `ksn`/`rpy` reply and persists as `KeyStateRecord`.
///
/// This is the byte-interoperable counterpart to the auths-internal
/// [`KeyStateNotice`]: where `KeyStateNotice` is an auths-only envelope around a
/// [`KeyState`], `KeyStateRecord` is the canonical KERI shape a peer (keripy,
/// keriox) produces and consumes — field order and labels
/// `{vn, i, s, p, d, f, dt, et, kt, k, nt, n, bt, b, c, ee, di}`, sequence
/// numbers as lowercase hex, thresholds as KERI hex/clause strings.
///
/// It is a *parsed* type: holding one means the labels and shapes already
/// matched the KERI form, so [`KeyStateRecord::into_key_state`] is total. Build
/// one from an auths KEL with [`KeyStateRecord::from_kel`] (emit a record a peer
/// can read); accept one from a peer by deserializing then
/// [`into_key_state`](KeyStateRecord::into_key_state) (consume a keripy KSN).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStateRecord {
    /// Protocol version `[major, minor]` — `[1, 0]` for the `KERI10` generation.
    pub vn: [u32; 2],
    /// Identifier prefix (the AID this state describes).
    pub i: Prefix,
    /// Sequence number of the latest event, lowercase-hex.
    pub s: String,
    /// SAID of the prior event (empty at inception).
    pub p: String,
    /// SAID of the latest event.
    pub d: Said,
    /// First-seen ordinal. auths does not maintain a first-seen log separate from
    /// the KEL, so this mirrors `s` (the latest sequence) — truthful for a
    /// single-source replay, where first-seen order *is* event order.
    pub f: String,
    /// Controller-asserted timestamp (RFC 3339).
    pub dt: String,
    /// Latest establishment event type (`icp`/`rot`/`dip`/`drt`).
    pub et: String,
    /// Current signing threshold (KERI hex/clause string).
    pub kt: Threshold,
    /// Current signing key(s), CESR-encoded.
    pub k: Vec<CesrKey>,
    /// Next-key threshold (KERI hex/clause string).
    pub nt: Threshold,
    /// Next-key commitment digest(s).
    pub n: Vec<Said>,
    /// Backer (witness) threshold (`bt`, hex string).
    pub bt: Threshold,
    /// Current backer (witness) list.
    pub b: Vec<Prefix>,
    /// Configuration traits.
    pub c: Vec<ConfigTrait>,
    /// Latest establishment event summary (`{s, d, br, ba}`).
    pub ee: LatestEstablishmentEvent,
    /// Delegator AID (empty string when not delegated).
    pub di: String,
}

impl KeyStateRecord {
    /// Build a KERI key-state record by replaying a validated KEL into its
    /// current state, stamped at `dt`.
    ///
    /// `events` is the full, in-order KEL (inception first); the record's `s`/`d`
    /// come from the last event and `p`/`ee`/`et` from its latest establishment
    /// event. Returns `None` only if `events` is empty (no inception to anchor a
    /// state) — the caller has nothing to notice.
    ///
    /// Args:
    /// * `events`: The replayed KEL, in sequence order.
    /// * `state`: The resolved current [`KeyState`] (from `replay`).
    /// * `dt`: An RFC-3339 timestamp (injected `now`).
    pub fn from_kel(events: &[Event], state: &KeyState, dt: impl Into<String>) -> Option<Self> {
        let last = events.last()?;
        let latest_est = events.iter().rev().find(|e| !e.is_interaction())?;
        Some(Self {
            vn: KERI_KEY_STATE_VERSION,
            i: state.prefix.clone(),
            s: format!("{:x}", state.sequence),
            p: last
                .previous()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default(),
            d: state.last_event_said.clone(),
            f: format!("{:x}", state.sequence),
            dt: dt.into(),
            et: establishment_type(latest_est).to_string(),
            kt: state.threshold.clone(),
            k: state.current_keys.clone(),
            nt: state.next_threshold.clone(),
            n: state.next_commitment.clone(),
            bt: state.backer_threshold.clone(),
            b: state.backers.clone(),
            c: state.config_traits.clone(),
            ee: LatestEstablishmentEvent {
                s: format!("{:x}", latest_est.sequence().value()),
                d: latest_est.said().clone(),
                br: Vec::new(),
                ba: Vec::new(),
            },
            di: state
                .delegator
                .as_ref()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default(),
        })
    }

    /// Project this KERI record back to the auths [`KeyState`] the rest of the
    /// platform reasons over (a thin client ingesting a peer's published state).
    ///
    /// Total: a parsed `KeyStateRecord` already carries the labels and shapes a
    /// `KeyState` needs, so no field can be missing or mistyped here.
    pub fn into_key_state(self) -> KeyState {
        let sequence = u128::from_str_radix(self.s.trim_start_matches("0x"), 16).unwrap_or(0);
        let last_est_seq =
            u128::from_str_radix(self.ee.s.trim_start_matches("0x"), 16).unwrap_or(0);
        let delegator = if self.di.is_empty() {
            None
        } else {
            Some(Prefix::new_unchecked(self.di))
        };
        KeyState {
            prefix: self.i,
            current_keys: self.k,
            next_commitment: self.n.clone(),
            sequence,
            last_event_said: self.d,
            is_abandoned: self.n.is_empty() && self.et != "icp" && self.et != "dip",
            threshold: self.kt,
            next_threshold: self.nt,
            backers: self.b,
            backer_threshold: self.bt,
            config_traits: self.c,
            is_non_transferable: self.n.is_empty(),
            delegator,
            last_establishment_sequence: last_est_seq,
        }
    }
}

/// The KERI `et` value for an establishment event (`icp`/`rot`/`dip`/`drt`).
/// Callers pass only establishment events (`!is_interaction`); a stray `ixn`
/// falls through to its own tag rather than panicking.
fn establishment_type(event: &Event) -> &'static str {
    match event {
        Event::Icp(_) => "icp",
        Event::Rot(_) => "rot",
        Event::Dip(_) => "dip",
        Event::Drt(_) => "drt",
        Event::Ixn(_) => "ixn",
    }
}

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

    // ── KERI-conformant key-state record (KeyStateRecord) ────────────────────

    /// A minimal self-addressing inception KEL (single event) parsed from JSON,
    /// mirroring the keripy `icp`/`KeyStateRecord` reference vector.
    const ICP_KEL_JSON: &str = r#"[{
        "v":"KERI10JSON0000fd_","t":"icp",
        "d":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
        "i":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
        "s":"0","kt":"1",
        "k":["DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"],
        "nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]
    }]"#;

    #[test]
    fn key_state_record_emits_keri_wire_shape() {
        let events = crate::validate::parse_kel_json(ICP_KEL_JSON).unwrap();
        let state = crate::validate::TrustedKel::from_trusted_source(&events)
            .replay()
            .unwrap();
        let record =
            KeyStateRecord::from_kel(&events, &state, "2026-06-12T02:49:41.677319+00:00").unwrap();

        let json = serde_json::to_value(&record).unwrap();
        let obj = json.as_object().unwrap();
        // Field order/labels are the KERI ksn record shape, not the auths envelope.
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "vn", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "nt", "n", "bt", "b", "c",
                "ee", "di"
            ]
        );
        assert_eq!(obj["vn"], serde_json::json!([1, 0]));
        assert_eq!(obj["s"], "0");
        assert_eq!(obj["p"], "");
        assert_eq!(obj["et"], "icp");
        assert_eq!(obj["kt"], "1");
        assert_eq!(obj["di"], "");
        let ee = obj["ee"].as_object().unwrap();
        assert_eq!(
            ee.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["s", "d", "br", "ba"]
        );
    }

    #[test]
    fn key_state_record_round_trips_through_key_state() {
        let events = crate::validate::parse_kel_json(ICP_KEL_JSON).unwrap();
        let state = crate::validate::TrustedKel::from_trusted_source(&events)
            .replay()
            .unwrap();
        let record = KeyStateRecord::from_kel(&events, &state, "t").unwrap();

        // Serialize -> deserialize (the peer's wire path) -> project to KeyState.
        let wire = serde_json::to_string(&record).unwrap();
        let parsed: KeyStateRecord = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, record);

        let projected = parsed.into_key_state();
        assert_eq!(projected.prefix, state.prefix);
        assert_eq!(projected.current_keys, state.current_keys);
        assert_eq!(projected.sequence, state.sequence);
        assert_eq!(projected.last_event_said, state.last_event_said);
        assert_eq!(projected.threshold, state.threshold);
        assert!(projected.is_non_transferable);
    }

    #[test]
    fn key_state_record_ingests_peer_published_record() {
        // A keripy-shaped record arriving over the wire (string sequence, hex
        // thresholds, empty delegator) projects to a usable KeyState.
        let wire = r#"{
            "vn":[1,0],
            "i":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
            "s":"0","p":"",
            "d":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
            "f":"0","dt":"2026-06-12T02:49:41.677319+00:00","et":"icp",
            "kt":"1","k":["DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"],
            "nt":"0","n":[],"bt":"0","b":[],"c":[],
            "ee":{"s":"0","d":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J","br":[],"ba":[]},
            "di":""
        }"#;
        let record: KeyStateRecord = serde_json::from_str(wire).unwrap();
        let state = record.into_key_state();
        assert_eq!(
            state.prefix.as_str(),
            "EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J"
        );
        assert_eq!(state.sequence, 0);
        assert!(state.is_non_transferable);
        assert!(state.delegator.is_none());
    }
}
