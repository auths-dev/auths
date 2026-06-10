//! Authority-at-signing classification + off-boarding-log queries.
//!
//! Answers the enterprise question "could this member have signed this *after* they
//! left?" as a **closed, typed verdict** — never a free-text status — ordered by
//! **KEL position**, never wall-clock (a backdated timestamp cannot flip the verdict,
//! which would reopen the backdating gap). Mirrors the shipped
//! `auths_verifier::commit_kel::CommitVerdict::SignedAfterRevocation` ordering for the
//! org-membership case, reading the revocation position from the org KEL.

use auths_id::keri::types::Prefix;
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::org::delegation::{OrgKelSnapshot, list_members};
use crate::domains::org::error::OrgError;
use crate::domains::org::offboarding::{
    SignedOffboardingRecord, find_revocation_event, load_offboarding_record,
};

/// A member's authority at the moment an artifact was signed — a closed sum ordered
/// strictly by **KEL position** (never wall-clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authority_at_signing", rename_all = "snake_case")]
pub enum AuthorityAtSigning {
    /// The member's authority was live at the signing position — the artifact was
    /// signed strictly before the revocation, or the member was never revoked.
    AuthorizedBeforeRevocation,
    /// The artifact was signed at or after the org revoked the member, by KEL
    /// position. Carries the exact revocation position.
    RejectedAfterRevocation {
        /// The KEL position at which the org anchored the revocation.
        #[serde(with = "u128_str")]
        revoked_at: u128,
    },
    /// The org revoked the member but the artifact carries no in-band signing
    /// position, so it cannot be ordered — conservatively rejected (mirrors the
    /// verifier's no-position default).
    RejectedRevokedPositionUnknown {
        /// The KEL position at which the org anchored the revocation.
        #[serde(with = "u128_str")]
        revoked_at: u128,
    },
    /// The org never delegated this member — there is no authority to classify.
    NeverDelegated,
}

/// (De)serialize a `u128` KEL position as a decimal string.
///
/// JSON numbers lose precision above 2^53, and serde's internally-tagged-enum
/// buffer cannot round-trip 128-bit integers — so KEL positions travel as strings
/// (the same convention [`auths_keri::KeriSequence`] uses for its hex form).
mod u128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Classify a member's authority at an artifact's signing position, ordered by KEL
/// position relative to the org's revocation.
///
/// `signed_at` is the artifact's in-band signing KEL position (e.g. a commit's
/// `Auths-Anchor-Seq`), or `None` when the artifact carries no position. Ordering is
/// causal — a member revoked at KEL seq `R` is authorized for any artifact signed at
/// `< R` and rejected at `>= R`; wall-clock is never consulted.
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `member_prefix`: The member's KEL prefix to classify.
/// * `signed_at`: The artifact's in-band signing position, if any.
///
/// Usage:
/// ```ignore
/// let verdict = classify_authority_at_signing(&ctx, &org, &member, Some(41))?;
/// ```
pub fn classify_authority_at_signing(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> Result<AuthorityAtSigning, OrgError> {
    let snapshot = OrgKelSnapshot::load(ctx, org_prefix)?;
    classify_authority_at_signing_with(&snapshot, member_prefix, signed_at)
}

/// Snapshot-based [`classify_authority_at_signing`] — no registry I/O.
///
/// Use this form when classifying many members of the same org (fleet listings,
/// chain walks): load the [`OrgKelSnapshot`] once and classify every member from it.
///
/// Args:
/// * `snapshot`: The org's KEL snapshot.
/// * `member_prefix`: The member's KEL prefix to classify.
/// * `signed_at`: The artifact's in-band signing position, if any.
///
/// Usage:
/// ```ignore
/// let verdict = classify_authority_at_signing_with(&snapshot, &member, Some(41))?;
/// ```
pub fn classify_authority_at_signing_with(
    snapshot: &OrgKelSnapshot,
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> Result<AuthorityAtSigning, OrgError> {
    let Some(authority) = snapshot.member_authority(member_prefix) else {
        return Ok(AuthorityAtSigning::NeverDelegated);
    };
    if !authority.revoked {
        return Ok(AuthorityAtSigning::AuthorizedBeforeRevocation);
    }

    let revoked_at = find_revocation_event(snapshot.org_kel(), member_prefix)
        .map(|(_, seq)| seq)
        .ok_or_else(|| {
            OrgError::Signing("revoked member has no revocation event on the org KEL".to_string())
        })?;

    Ok(match signed_at {
        None => AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at },
        Some(seq) if seq < revoked_at => AuthorityAtSigning::AuthorizedBeforeRevocation,
        Some(_) => AuthorityAtSigning::RejectedAfterRevocation { revoked_at },
    })
}

/// List an org's durable off-boarding records, newest-revocation-first not guaranteed
/// — order follows the KEL roster.
///
/// Enumerates revoked members from the KEL-authoritative roster and loads each one's
/// signed off-boarding record (fn-154.3). Members revoked before the record surface
/// existed simply have no record and are skipped.
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// for r in list_offboarding_records(&ctx, &org_prefix)? { /* ... */ }
/// ```
pub fn list_offboarding_records(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
) -> Result<Vec<SignedOffboardingRecord>, OrgError> {
    let mut records = Vec::new();
    for member in list_members(ctx, org_prefix)?
        .into_iter()
        .filter(|m| m.revoked)
    {
        let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());
        if let Some(record) = load_offboarding_record(ctx, org_prefix, &member_prefix)? {
            records.push(record);
        }
    }
    Ok(records)
}
