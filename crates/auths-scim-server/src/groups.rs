//! SCIM `/Groups` resource handlers — org-directory groupings.
//!
//! `POST /Groups` creates a group, `GET /Groups` lists + paginates, `GET /Groups/{id}`
//! fetches one, `PUT /Groups/{id}` replaces it (honoring `If-Match`), and `DELETE`
//! soft-deletes it. Groups are a directory convenience, not KERI identities, so there is no
//! provisioner round-trip — they live in the rebuildable in-memory store.

use auths_scim::resource::{ScimGroup, ScimMeta};
use auths_scim::{ScimError, ScimListResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;

use crate::auth::AuthenticatedTenant;
use crate::error::ScimServerError;
use crate::state::ScimServerState;
use crate::users::{etag_matches, presentation_now};

/// `POST /scim/v2/Groups` — create a group. The server assigns the `id` and ETag.
pub async fn create_group(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Json(input): Json<ScimGroup>,
) -> Result<(StatusCode, Json<ScimGroup>), ScimServerError> {
    let now = presentation_now();
    let id = new_group_id(&tenant.tenant_id, &input.display_name, now);
    let group = ScimGroup {
        schemas: ScimGroup::default_schemas(),
        id: id.clone(),
        external_id: input.external_id,
        display_name: input.display_name,
        members: input.members,
        meta: ScimMeta {
            resource_type: "Group".into(),
            created: now,
            last_modified: now,
            version: String::new(), // insert stamps the content ETag
            location: format!("{}/Groups/{}", tenant.base_url, id),
        },
    };
    let stored = state.insert_group(&tenant.tenant_id, group);
    Ok((StatusCode::CREATED, Json(stored)))
}

/// `GET /scim/v2/Groups` — list + paginate this tenant's groups (id-ordered for determinism).
pub async fn list_groups(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Query(params): Query<GroupListParams>,
) -> Result<Json<ScimListResponse<ScimGroup>>, ScimServerError> {
    let mut groups = state.groups_for_tenant(&tenant.tenant_id);
    groups.sort_by(|a, b| a.id.cmp(&b.id));
    let total = groups.len() as u64;

    let start_index = params.start_index.unwrap_or(1).max(1);
    let skip = (start_index - 1) as usize;
    let count = params.count.unwrap_or(u64::MAX);
    let page: Vec<ScimGroup> = groups.into_iter().skip(skip).take(count as usize).collect();
    Ok(Json(ScimListResponse::new(page, total, start_index)))
}

/// `GET /scim/v2/Groups/{id}` — fetch one group; unknown id → 404 envelope.
pub async fn get_group(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<ScimGroup>, ScimServerError> {
    state
        .find_group_by_id(&tenant.tenant_id, &id)
        .map(Json)
        .ok_or_else(|| ScimServerError::from(ScimError::NotFound { id }))
}

/// `PUT /scim/v2/Groups/{id}` — full-resource replace honoring `If-Match` optimistic
/// concurrency (a stale match → 412; `*` or absent → allowed). The store refreshes the ETag.
pub async fn put_group(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ScimGroup>,
) -> Result<Json<ScimGroup>, ScimServerError> {
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let updated = state.update_group(&tenant.tenant_id, &id, move |current| {
        apply_group_put(current, input, if_match.as_deref())
    })?;
    Ok(Json(updated))
}

/// `DELETE /scim/v2/Groups/{id}` — soft-delete (tombstone). Idempotent; always 204.
pub async fn delete_group(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
) -> StatusCode {
    state.delete_group(&tenant.tenant_id, &id);
    StatusCode::NO_CONTENT
}

/// Apply a `PUT` replacement to a group, enforcing `If-Match`. Pure, so the precondition is
/// tested without the HTTP layer; `meta` is left for the store to refresh.
fn apply_group_put(
    current: ScimGroup,
    input: ScimGroup,
    if_match: Option<&str>,
) -> Result<ScimGroup, ScimError> {
    if let Some(expected) = if_match
        && !etag_matches(expected, &current.meta.version)
    {
        return Err(ScimError::PreconditionFailed);
    }
    let mut next = current;
    next.external_id = input.external_id;
    next.display_name = input.display_name;
    next.members = input.members;
    Ok(next)
}

/// A server-assigned group id, derived from the tenant, display name, and creation time so it
/// is unique without an external id source.
fn new_group_id(tenant_id: &str, display_name: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tenant_id.hash(&mut hasher);
    display_name.hash(&mut hasher);
    now.timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Pagination query parameters for `GET /Groups`.
#[derive(Debug, Deserialize)]
pub struct GroupListParams {
    #[serde(rename = "startIndex", default)]
    start_index: Option<u64>,
    #[serde(default)]
    count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str, display: &str) -> ScimGroup {
        ScimGroup {
            schemas: ScimGroup::default_schemas(),
            id: id.to_string(),
            external_id: None,
            display_name: display.to_string(),
            members: vec![],
            meta: Default::default(),
        }
    }

    #[test]
    fn group_put_enforces_if_match_and_replaces_fields() {
        let mut current = group("g1", "eng");
        current.meta.version = "W/\"abc\"".to_string();

        // A stale If-Match → PreconditionFailed (412).
        assert!(matches!(
            apply_group_put(current.clone(), group("g1", "eng"), Some("W/\"stale\"")),
            Err(ScimError::PreconditionFailed)
        ));

        // A matching If-Match → replace succeeds (displayName updated).
        let out = apply_group_put(
            current.clone(),
            group("g1", "engineering"),
            Some("W/\"abc\""),
        )
        .unwrap();
        assert_eq!(out.display_name, "engineering");

        // `*` matches; absent If-Match is permitted.
        assert!(apply_group_put(current.clone(), group("g1", "eng"), Some("*")).is_ok());
        assert!(apply_group_put(current, group("g1", "eng"), None).is_ok());
    }
}
