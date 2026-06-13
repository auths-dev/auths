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
//!
//! The wire types and the pure verification live in
//! [`auths_verifier::org_bundle`] (so any offline verifier — native, FFI,
//! browser WASM — checks a record from evidence alone); this module keeps the
//! I/O half: signing with the org keychain and persisting to the registry.

use std::sync::Arc;

use auths_core::signing::{SecureSigner, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;
use auths_id::keri::Said;
use auths_id::keri::types::Prefix;

pub use auths_verifier::org_bundle::{
    OffboardingRecord, SignedOffboardingRecord, find_revocation_event, verify_offboarding_record,
};

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
