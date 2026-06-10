//! Off-boarding audit records — durable, signed, seal-bound evidence.
//!
//! Revoking an org member anchors a revocation seal in the org KEL (the provable
//! event). This module turns that *action* into *evidence*: a typed
//! [`OffboardingRecord`] signed by the org key and **bound to the revocation seal**
//! — who off-boarded whom, at which **KEL position** (never wall-clock), why, and a
//! snapshot of the role + capabilities the subject lost.
//!
//! The record persists as a signed JSON blob in the org's credential-namespace ref
//! keyed by the member prefix (separate from the KEL event), so it is retrievable by
//! `(org, member)` and tamper-evident: any edit to the record or a mismatch against
//! the on-KEL revocation seal fails [`verify_offboarding_record`]. The surface is
//! named "offboarding" to avoid colliding with `auths audit` (commit-compliance) and
//! the SIEM `AuditEvent` stream.

use std::sync::Arc;

use auths_core::signing::{SecureSigner, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Said, Seal};
use auths_keri::KeriPublicKey;
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::org::error::OrgError;

/// The in-band curve tag for a signature (CLAUDE.md wire-format rule: never infer
/// curve from byte length).
fn curve_tag(curve: CurveType) -> &'static str {
    match curve {
        CurveType::Ed25519 => "ed25519",
        CurveType::P256 => "p256",
    }
}

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
/// equals the member prefix (the convention [`revoke_delegated_device`] writes).
///
/// [`revoke_delegated_device`]: auths_id::keri::delegation::revoke_delegated_device
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

/// Sign an [`OffboardingRecord`] with the org key, producing tamper-evident evidence.
///
/// Signs the `json_canon` of `record` with the org's signing key; the signature's
/// curve travels in-band.
///
/// Args:
/// * `ctx`: Auths context (key storage, passphrase provider).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `org_curve`: The org key's curve (carried in-band on the signed record).
/// * `record`: The off-boarding record to sign.
///
/// Usage:
/// ```ignore
/// let signed = sign_offboarding_record(&ctx, &org_alias, org_curve, record)?;
/// ```
pub fn sign_offboarding_record(
    ctx: &AuthsContext,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    record: OffboardingRecord,
) -> Result<SignedOffboardingRecord, OrgError> {
    let canonical = json_canon::to_string(&record)
        .map_err(|e| OrgError::Signing(format!("canonicalize offboarding record: {e}")))?;
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let sig = signer
        .sign_with_alias(
            org_alias,
            ctx.passphrase_provider.as_ref(),
            canonical.as_bytes(),
        )
        .map_err(|e| OrgError::Signing(e.to_string()))?;
    Ok(SignedOffboardingRecord {
        record,
        org_curve: curve_tag(org_curve).to_string(),
        signature: hex::encode(sig),
    })
}

/// Persist a signed off-boarding record, keyed by `(org, member)`.
///
/// Stores the record as a signed JSON blob in the org's credential-namespace ref
/// (separate from the KEL), retrievable by member prefix via
/// [`load_offboarding_record`].
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix (storage namespace).
/// * `member_prefix`: The off-boarded member's prefix (storage key).
/// * `signed`: The signed record to persist.
pub fn store_offboarding_record(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    member_prefix: &Prefix,
    signed: &SignedOffboardingRecord,
) -> Result<(), OrgError> {
    let bytes = serde_json::to_vec(signed)
        .map_err(|e| OrgError::Signing(format!("serialize offboarding record: {e}")))?;
    let key = Said::new_unchecked(member_prefix.as_str().to_string());
    ctx.registry
        .store_credential(org_prefix, &key, &bytes)
        .map_err(OrgError::Storage)
}

/// Load the off-boarding record for `(org, member)`, or `None` if the member was
/// never off-boarded.
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix (storage namespace).
/// * `member_prefix`: The member's prefix (storage key).
pub fn load_offboarding_record(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    member_prefix: &Prefix,
) -> Result<Option<SignedOffboardingRecord>, OrgError> {
    let key = Said::new_unchecked(member_prefix.as_str().to_string());
    let bytes = ctx
        .registry
        .load_credential(org_prefix, &key)
        .map_err(OrgError::Storage)?;
    match bytes {
        Some(b) => {
            let signed: SignedOffboardingRecord = serde_json::from_slice(&b)
                .map_err(|e| OrgError::Signing(format!("deserialize offboarding record: {e}")))?;
            Ok(Some(signed))
        }
        None => Ok(None),
    }
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
) -> Result<(), OrgError> {
    if curve_from_tag(&signed.org_curve) != org_curve {
        return Err(OrgError::Signing(
            "offboarding record curve tag does not match the org key curve".to_string(),
        ));
    }

    let canonical = json_canon::to_string(&signed.record)
        .map_err(|e| OrgError::Signing(format!("canonicalize offboarding record: {e}")))?;
    let sig = hex::decode(&signed.signature)
        .map_err(|e| OrgError::Signing(format!("decode offboarding signature: {e}")))?;
    let key = KeriPublicKey::from_verkey_bytes(org_public_key, org_curve)
        .map_err(|e| OrgError::InvalidPublicKey(e.to_string()))?;
    key.verify_signature(canonical.as_bytes(), &sig)
        .map_err(|e| OrgError::Signing(format!("offboarding signature invalid: {e}")))?;

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
        _ => Err(OrgError::Signing(
            "offboarding record is not bound to a matching org KEL revocation seal".to_string(),
        )),
    }
}
