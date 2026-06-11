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
use axum::http::StatusCode;
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

    users.sort_by(|a, b| a.id.cmp(&b.id));
    let total = users.len() as u64;

    let start_index = params.start_index.unwrap_or(1).max(1);
    let skip = (start_index - 1) as usize;
    let count = params.count.unwrap_or(u64::MAX);
    let page: Vec<ScimUser> = users.into_iter().skip(skip).take(count as usize).collect();

    Ok(Json(ScimListResponse::new(page, total, start_index)))
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

/// RFC 7644 list query parameters.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default)]
    filter: Option<String>,
    #[serde(rename = "startIndex", default)]
    start_index: Option<u64>,
    #[serde(default)]
    count: Option<u64>,
}

/// The presentation-boundary timestamp for new resources.
#[allow(clippy::disallowed_methods)] // SCIM server is a presentation layer (like the CLI)
fn presentation_now() -> chrono::DateTime<chrono::Utc> {
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
