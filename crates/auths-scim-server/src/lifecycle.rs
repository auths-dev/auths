//! SCIM lifecycle handlers — the Leaver: PATCH, DELETE, and explicit hard-revoke.
//!
//! Honors the deprovision-vs-revocation boundary: `PATCH {active:false}` and
//! `DELETE` are reversible soft-disables that never touch the KEL, while
//! `POST /Users/{id}/revoke` is the explicit, irreversible cryptographic
//! off-boarding (`revoke_member`). The atomic PATCH transform runs under a single
//! lock, giving all-or-nothing rollback and a concurrent-PATCH guard.

use auths_scim::ScimError;
use auths_scim::patch::{ScimPatchOp, apply_patch_operations};
use auths_scim::resource::ScimUser;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;

use crate::auth::AuthenticatedTenant;
use crate::error::ScimServerError;
use crate::provisioner::RevokeOutcome;
use crate::state::ScimServerState;

/// `PATCH /scim/v2/Users/{id}` — atomic, all-or-nothing lifecycle PATCH.
///
/// `active:false` soft-disables (reversible, no KEL write); `active:true`
/// reactivates a soft-disabled member but is rejected for a hard-revoked one.
/// A failing operation rolls the resource back to its pre-PATCH state, and the
/// single-lock transform serializes concurrent PATCHes so they cannot split state.
pub async fn patch_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchOp>,
) -> Result<Json<ScimUser>, ScimServerError> {
    let ops = patch.operations;
    let allowed = tenant.allowed_capabilities.clone();
    let allow_all = tenant.allow_all;
    let updated = state.update_user(&tenant.tenant_id, &id, move |user| {
        let was_revoked = user
            .auths_extension
            .as_ref()
            .map(|e| e.revoked)
            .unwrap_or(false);
        let patched = apply_patch_operations(user, &ops)?;
        // Re-enforce the capability allowlist on PATCH so a lifecycle update
        // cannot widen capabilities past the tenant's grant (RT-006/RT-026).
        if !allow_all {
            let patched_caps = patched
                .auths_extension
                .as_ref()
                .map(|e| e.capabilities.clone())
                .unwrap_or_default();
            auths_scim::mapping::validate_capabilities(&patched_caps, &allowed)?;
        }
        if was_revoked && patched.active {
            return Err(ScimError::InvalidValue {
                message: "cannot reactivate a hard-revoked member; the identity is \
                          cryptographically off-boarded — re-onboard to restore"
                    .to_string(),
            });
        }
        Ok(patched)
    })?;
    Ok(Json(updated))
}

/// `DELETE /scim/v2/Users/{id}` — soft Leaver (deprovision); always 204.
///
/// Tombstones and deactivates the resource without revoking the KERI identity, so
/// the delete is recoverable. Idempotent: an unknown or already-deleted id is a
/// no-op success — no existence is leaked and no KEL write occurs.
pub async fn delete_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
) -> StatusCode {
    state.soft_delete(&tenant.tenant_id, &id);
    StatusCode::NO_CONTENT
}

/// The result of an explicit hard-revoke control call.
#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    /// True once the call returns `Ok` — the member is revoked.
    pub revoked: bool,
    /// Whether THIS call anchored a fresh off-boarding record (false on an
    /// idempotent repeat against an already-revoked member).
    pub offboarding_recorded: bool,
}

/// `POST /scim/v2/Users/{id}/revoke` — the explicit, irreversible hard-revoke.
///
/// A distinct Auths control operation (NOT a standard SCIM verb) so a deprovision
/// can never be mistaken for cryptographic revocation. Resolves the member's
/// `did:keri:` from the resource and calls `revoke_member`, producing a signed
/// off-boarding record. Idempotent: a repeat returns success with
/// `offboarding_recorded:false`.
pub async fn revoke_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<RevokeResponse>, ScimServerError> {
    let user = state
        .find_any_by_id(&tenant.tenant_id, &id)
        .ok_or_else(|| ScimError::NotFound { id: id.clone() })?;
    let member_did = user
        .auths_extension
        .as_ref()
        .and_then(|e| e.identity_did.as_ref())
        .ok_or_else(|| ScimError::Internal {
            message: "resource is missing its delegated identity DID".to_string(),
        })?;

    let outcome = state.provisioner().revoke(
        &tenant.org_prefix,
        &tenant.org_key_alias,
        member_did.as_str(),
    )?;
    state.mark_revoked(&tenant.tenant_id, &id);

    Ok(Json(RevokeResponse {
        revoked: true,
        offboarding_recorded: matches!(outcome, RevokeOutcome::Revoked),
    }))
}
