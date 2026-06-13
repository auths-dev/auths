//! Off-boarding audit records — durable, signed, seal-bound evidence.
//!
//! Revoking an org member anchors a revocation seal in the org KEL (the
//! provable event). These types turn that *action* into *evidence*: a typed
//! [`OffboardingRecord`] signed by the org key and **bound to the revocation
//! seal** — who off-boarded whom, at which **KEL position** (never
//! wall-clock), why, and a snapshot of the role + capabilities the subject
//! lost. The signing/storage side lives in `auths-sdk` (it needs a live
//! keychain and registry); the wire types and the pure verification live
//! here so any offline verifier checks a record from evidence alone.

use auths_crypto::CurveType;
use auths_keri::{Event, KeriPublicKey, Prefix, Seal};
use serde::{Deserialize, Serialize};

use super::error::OrgBundleError;

/// Parse a curve tag back to a [`CurveType`]; unknown/missing defaults to P-256
/// (the workspace default, per the wire-format rule).
fn curve_from_tag(tag: &str) -> CurveType {
    match tag {
        "ed25519" => CurveType::Ed25519,
        _ => CurveType::P256,
    }
}

/// A typed off-boarding record — the durable evidence emitted alongside a member
/// revocation. Ordering is by **KEL position** (`revoked_at_seq`), never wall-clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffboardingRecord {
    /// The org's `did:keri:` (the delegator that off-boarded the member).
    pub org_did: String,
    /// The off-boarded member's `did:keri:`.
    pub member_did: String,
    /// The KEL sequence of the org's revocation event — the exact position after
    /// which the member's authority is gone. Causal, not wall-clock.
    pub revoked_at_seq: u128,
    /// The SAID of the org KEL event carrying the revocation seal (anti-forgery
    /// binding: the record is only valid against this on-KEL event).
    pub revocation_seal_said: String,
    /// Optional operator-supplied reason for the off-boarding.
    pub reason: Option<String>,
    /// The DID that authored the revocation. For a `kt=1` org this is the org DID.
    pub operator_did: String,
    /// The role the member held at the revocation position (what they lost).
    pub prior_role: Option<String>,
    /// The capabilities the member held at the revocation position (what they lost).
    pub prior_caps: Vec<auths_keri::Capability>,
    /// When the record was recorded (RFC 3339, injected clock). Provenance only —
    /// authority ordering is by `revoked_at_seq`, never this timestamp.
    pub recorded_at: String,
}

/// An [`OffboardingRecord`] plus the org's signature over its canonical form. The
/// signature's curve travels in-band (`org_curve`) per the wire-format rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOffboardingRecord {
    /// The signed record payload.
    pub record: OffboardingRecord,
    /// In-band curve tag for `signature` (`"ed25519"` / `"p256"`).
    pub org_curve: String,
    /// Hex-encoded org signature over `json_canon(record)`.
    pub signature: String,
}

/// Locate the org KEL event that carries the revocation seal for `member_prefix`.
///
/// Returns `(seal_event_said, sequence)` for the latest such event, or `None` if the
/// org never revoked the member. The revocation seal is a `Seal::Digest` whose digest
/// equals the member prefix (the convention the revocation writer uses).
pub fn find_revocation_event(org_kel: &[Event], member_prefix: &Prefix) -> Option<(String, u128)> {
    let mut found = None;
    for event in org_kel {
        for seal in event.anchors() {
            if let Seal::Digest { d } = seal
                && d.as_str() == member_prefix.as_str()
            {
                found = Some((event.said().as_str().to_string(), event.sequence().value()));
            }
        }
    }
    found
}

/// Verify a signed off-boarding record: the org signature is valid **and** the record
/// is bound to a matching revocation event on the org KEL.
///
/// Fails closed if the signature does not verify (record tampered) or no org KEL
/// event with the record's `revocation_seal_said` revokes the member at
/// `revoked_at_seq` (seal tampered / record forged).
///
/// Args:
/// * `signed`: The signed record to verify.
/// * `org_public_key`: The org's current verkey bytes (resolved from its KEL).
/// * `org_curve`: The org key's curve.
/// * `org_kel`: The org's KEL events (oldest first).
///
/// Usage:
/// ```ignore
/// verify_offboarding_record(&signed, &org_pk, org_curve, &org_kel)?;
/// ```
pub fn verify_offboarding_record(
    signed: &SignedOffboardingRecord,
    org_public_key: &[u8],
    org_curve: CurveType,
    org_kel: &[Event],
) -> Result<(), OrgBundleError> {
    if curve_from_tag(&signed.org_curve) != org_curve {
        return Err(OrgBundleError::RecordInvalid(
            "offboarding record curve tag does not match the org key curve".to_string(),
        ));
    }

    let canonical = json_canon::to_string(&signed.record)
        .map_err(|e| OrgBundleError::Canonicalize(format!("offboarding record: {e}")))?;
    let sig = hex::decode(&signed.signature)
        .map_err(|e| OrgBundleError::RecordInvalid(format!("decode offboarding signature: {e}")))?;
    let key = KeriPublicKey::from_verkey_bytes(org_public_key, org_curve)
        .map_err(|e| OrgBundleError::RecordInvalid(format!("invalid org public key: {e}")))?;
    key.verify_signature(canonical.as_bytes(), &sig)
        .map_err(|e| {
            OrgBundleError::RecordInvalid(format!("offboarding signature invalid: {e}"))
        })?;

    let member_prefix = Prefix::new_unchecked(
        signed
            .record
            .member_did
            .strip_prefix("did:keri:")
            .unwrap_or(&signed.record.member_did)
            .to_string(),
    );
    match find_revocation_event(org_kel, &member_prefix) {
        Some((said, seq))
            if said == signed.record.revocation_seal_said
                && seq == signed.record.revoked_at_seq =>
        {
            Ok(())
        }
        _ => Err(OrgBundleError::RecordInvalid(
            "offboarding record is not bound to a matching org KEL revocation seal".to_string(),
        )),
    }
}
