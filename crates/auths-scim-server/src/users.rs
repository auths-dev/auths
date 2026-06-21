//! SCIM `/Users` resource handlers — the Joiner.
//!
//! `POST /Users` provisions a **real delegated** org identity via the
//! [`Provisioner`](crate::provisioner::Provisioner) port, idempotent on
//! `(tenant, externalId)` so an IdP's aggressive retries never mint a second
//! delegation. `GET /Users` filters (RFC 7644) and paginates; `GET /Users/{id}`
//! fetches one. KERI is authoritative; the in-memory index is a rebuildable cache.

use auths_scim::mapping::{
    ProvisionAgentResult, provision_result_to_scim_user, scim_user_to_provision_request,
};
use auths_scim::resource::ScimUser;
use auths_scim::{CompareOp, ScimError, ScimFilter, ScimListResponse, parse_filter};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;

use crate::auth::AuthenticatedTenant;
use crate::error::ScimServerError;
use crate::state::ScimServerState;

/// `POST /scim/v2/Users` — provision a delegated org identity (the Joiner).
///
/// Idempotent on `(tenant, externalId)`: a re-POST with a known `externalId`
/// returns the existing resource (200) and issues **no** second delegation; a new
/// `externalId` mints a new delegated identity (201). An unprovisioned org tenant
/// yields a typed 4xx, not a 500.
pub async fn create_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Json(input): Json<ScimUser>,
) -> Result<(StatusCode, Json<ScimUser>), ScimServerError> {
    let request =
        scim_user_to_provision_request(&input, &tenant.allowed_capabilities, tenant.allow_all)?;

    if let Some(external_id) = request.external_id.as_deref()
        && let Some(existing) = state.find_by_external(&tenant.tenant_id, external_id)
    {
        return Ok((StatusCode::OK, Json(existing)));
    }

    let provisioned =
        state
            .provisioner()
            .provision(&tenant.org_prefix, &tenant.org_key_alias, &request)?;

    let now = presentation_now();
    let result = ProvisionAgentResult {
        id: provisioned.member_prefix.clone(),
        identity_did: provisioned.identity_did.as_str().to_string(),
        created_at: now,
    };
    let user = provision_result_to_scim_user(&result, &request, now, &tenant.base_url);
    state.insert_user(&tenant.tenant_id, request.external_id.clone(), user.clone());
    Ok((StatusCode::CREATED, Json(user)))
}

/// `GET /scim/v2/Users` — list, filter (RFC 7644), and paginate this tenant's
/// provisioned identities.
pub async fn list_users(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Query(params): Query<ListParams>,
) -> Result<Json<ScimListResponse<ScimUser>>, ScimServerError> {
    let mut users = state.users_for_tenant(&tenant.tenant_id);

    if let Some(filter_str) = params.filter.as_deref() {
        let filter = parse_filter(filter_str)?;
        let mut kept = Vec::with_capacity(users.len());
        for user in users {
            if matches_filter(&user, &filter)? {
                kept.push(user);
            }
        }
        users = kept;
    }

    sort_users(
        &mut users,
        params.sort_by.as_deref(),
        params.sort_order.as_deref(),
    );
    let total = users.len() as u64;

    let start_index = params.start_index.unwrap_or(1).max(1);
    let skip = (start_index - 1) as usize;
    let count = auths_scim::list::clamp_list_count(params.count);
    let page: Vec<ScimUser> = users.into_iter().skip(skip).take(count).collect();

    Ok(Json(ScimListResponse::new(page, total, start_index)))
}

/// Sort users per the SCIM `sortBy` attribute (case-insensitive) and `sortOrder` (`ascending`
/// default), with `id` as a stable tiebreaker so pagination stays deterministic. An absent or
/// unrecognized `sortBy` falls back to `id`.
///
/// Args:
/// * `users`: the (filtered) user list, sorted in place.
/// * `sort_by`: the requested SCIM attribute (`userName`, `externalId`, or `id`).
/// * `sort_order`: `ascending` (default) or `descending`.
fn sort_users(users: &mut [ScimUser], sort_by: Option<&str>, sort_order: Option<&str>) {
    let key = |u: &ScimUser| -> String {
        match sort_by.map(str::to_ascii_lowercase).as_deref() {
            Some("username") => u.user_name.clone(),
            Some("externalid") => u.external_id.clone().unwrap_or_default(),
            _ => u.id.clone(),
        }
    };
    users.sort_by(|a, b| key(a).cmp(&key(b)).then_with(|| a.id.cmp(&b.id)));
    if sort_order.is_some_and(|s| s.eq_ignore_ascii_case("descending")) {
        users.reverse();
    }
}

/// `GET /scim/v2/Users/{id}` — fetch one resource; unknown id → 404 envelope.
pub async fn get_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<ScimUser>, ScimServerError> {
    state
        .find_by_id(&tenant.tenant_id, &id)
        .map(Json)
        .ok_or_else(|| ScimServerError::from(ScimError::NotFound { id }))
}

/// `PUT /scim/v2/Users/{id}` — full-resource replace (RFC 7644 §3.5.1). Honors `If-Match`
/// optimistic concurrency against the resource's current ETag (a stale match → 412) and rejects a
/// `userName` change (`userName` is immutable). An absent `If-Match` is permitted.
pub async fn put_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ScimUser>,
) -> Result<Json<ScimUser>, ScimServerError> {
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let updated = state.update_user(&tenant.tenant_id, &id, move |current| {
        apply_put(current, input, if_match.as_deref())
    })?;
    Ok(Json(updated))
}

/// Apply a `PUT` replacement to the stored resource, enforcing `If-Match` and `userName`
/// immutability. Pure, so the precondition + mutability rules are tested without the HTTP layer.
/// `meta` is left for the store to refresh — it recomputes the ETag on write.
fn apply_put(
    current: ScimUser,
    input: ScimUser,
    if_match: Option<&str>,
) -> Result<ScimUser, ScimError> {
    if let Some(expected) = if_match
        && !etag_matches(expected, &current.meta.version)
    {
        return Err(ScimError::PreconditionFailed);
    }
    if input.user_name != current.user_name {
        return Err(ScimError::Mutability {
            attribute: "userName".to_string(),
        });
    }
    let mut next = current;
    next.external_id = input.external_id;
    next.display_name = input.display_name;
    next.active = input.active;
    Ok(next)
}

/// Whether an `If-Match` value matches the current ETag: `*` matches any existing resource,
/// otherwise some ETag in the comma-separated list must equal `current` (RFC 7232).
pub(crate) fn etag_matches(if_match: &str, current: &str) -> bool {
    let v = if_match.trim();
    v == "*" || v.split(',').any(|t| t.trim() == current)
}

/// RFC 7644 list query parameters.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default)]
    filter: Option<String>,
    #[serde(rename = "startIndex", default)]
    start_index: Option<u64>,
    #[serde(default)]
    count: Option<u64>,
    #[serde(rename = "sortBy", default)]
    sort_by: Option<String>,
    #[serde(rename = "sortOrder", default)]
    sort_order: Option<String>,
}

/// The presentation-boundary timestamp for new resources.
#[allow(clippy::disallowed_methods)] // SCIM server is a presentation layer (like the CLI)
pub(crate) fn presentation_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// The trailing attribute name, dropping any schema-URI qualifier
/// (`urn:…:User:userName` → `userName`).
fn attr_name(attr: &str) -> &str {
    attr.rsplit(':').next().unwrap_or(attr)
}

/// Evaluate a parsed SCIM filter against a resource.
fn matches_filter(user: &ScimUser, filter: &ScimFilter) -> Result<bool, ScimError> {
    match filter {
        ScimFilter::Compare { attr, op, value } => compare_attr(user, attr, *op, value),
        ScimFilter::Present { attr } => Ok(present_attr(user, attr)),
        ScimFilter::And(a, b) => Ok(matches_filter(user, a)? && matches_filter(user, b)?),
        ScimFilter::Or(a, b) => Ok(matches_filter(user, a)? || matches_filter(user, b)?),
        ScimFilter::Not(inner) => Ok(!matches_filter(user, inner)?),
    }
}

/// The string value of a supported string attribute (outer `None` = unknown
/// attribute, inner `None` = known but absent).
fn string_attr<'a>(user: &'a ScimUser, attr: &str) -> Option<Option<&'a str>> {
    match attr_name(attr) {
        "userName" => Some(Some(user.user_name.as_str())),
        "externalId" => Some(user.external_id.as_deref()),
        "id" => Some(Some(user.id.as_str())),
        _ => None,
    }
}

fn compare_attr(
    user: &ScimUser,
    attr: &str,
    op: CompareOp,
    value: &str,
) -> Result<bool, ScimError> {
    if attr_name(attr) == "active" {
        let want = value.eq_ignore_ascii_case("true");
        return match op {
            CompareOp::Eq => Ok(user.active == want),
            CompareOp::Ne => Ok(user.active != want),
            _ => Err(ScimError::InvalidFilter {
                message: "unsupported operator on the 'active' attribute".to_string(),
            }),
        };
    }

    let Some(field) = string_attr(user, attr) else {
        return Err(ScimError::InvalidFilter {
            message: format!("unsupported filter attribute: {attr}"),
        });
    };
    let Some(field) = field else {
        return Ok(false); // a known-but-absent attribute never matches a value comparison
    };

    Ok(match op {
        CompareOp::Eq => field == value,
        CompareOp::Ne => field != value,
        CompareOp::Co => field.contains(value),
        CompareOp::Sw => field.starts_with(value),
    })
}

fn present_attr(user: &ScimUser, attr: &str) -> bool {
    match attr_name(attr) {
        "userName" => !user.user_name.is_empty(),
        "externalId" => user.external_id.is_some(),
        "id" => !user.id.is_empty(),
        "active" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str, user_name: &str) -> ScimUser {
        ScimUser {
            schemas: ScimUser::default_schemas(),
            id: id.to_string(),
            external_id: None,
            user_name: user_name.to_string(),
            display_name: None,
            active: true,
            meta: Default::default(),
            auths_extension: None,
        }
    }

    #[test]
    fn sort_users_honors_sort_by_and_order() {
        let mut users = vec![user("3", "charlie"), user("1", "alice"), user("2", "bob")];
        // sortBy=userName, ascending (default) → alice, bob, charlie.
        sort_users(&mut users, Some("userName"), None);
        assert_eq!(
            users
                .iter()
                .map(|u| u.user_name.as_str())
                .collect::<Vec<_>>(),
            ["alice", "bob", "charlie"]
        );
        // sortOrder=descending → charlie, bob, alice.
        sort_users(&mut users, Some("userName"), Some("descending"));
        assert_eq!(
            users
                .iter()
                .map(|u| u.user_name.as_str())
                .collect::<Vec<_>>(),
            ["charlie", "bob", "alice"]
        );
        // No sortBy → the deterministic id order (stable for pagination).
        sort_users(&mut users, None, None);
        assert_eq!(
            users.iter().map(|u| u.id.as_str()).collect::<Vec<_>>(),
            ["1", "2", "3"]
        );
        // An unrecognized sortBy falls back to id order and never panics.
        sort_users(&mut users, Some("bogus"), None);
        assert_eq!(
            users.iter().map(|u| u.id.as_str()).collect::<Vec<_>>(),
            ["1", "2", "3"]
        );
    }

    #[test]
    fn put_enforces_if_match_and_username_immutability() {
        let mut current = user("1", "alice");
        current.meta.version = "W/\"abc\"".to_string();

        // userName is immutable — a PUT changing it is rejected.
        let renamed = user("1", "alice-renamed");
        assert!(matches!(
            apply_put(current.clone(), renamed, Some("W/\"abc\"")),
            Err(ScimError::Mutability { .. })
        ));

        // A stale If-Match → PreconditionFailed (412) — the optimistic-concurrency guard.
        assert!(matches!(
            apply_put(current.clone(), user("1", "alice"), Some("W/\"stale\"")),
            Err(ScimError::PreconditionFailed)
        ));

        // A matching If-Match → replace succeeds: mutable fields updated, userName kept.
        let mut update = user("1", "alice");
        update.display_name = Some("Alice A.".to_string());
        update.active = false;
        let out = apply_put(current.clone(), update, Some("W/\"abc\"")).unwrap();
        assert_eq!(out.user_name, "alice");
        assert_eq!(out.display_name.as_deref(), Some("Alice A."));
        assert!(!out.active);

        // `*` matches any existing resource; an absent If-Match is permitted.
        assert!(apply_put(current.clone(), user("1", "alice"), Some("*")).is_ok());
        assert!(apply_put(current, user("1", "alice"), None).is_ok());
    }
}
