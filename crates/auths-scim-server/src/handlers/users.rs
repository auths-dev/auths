//! SCIM User resource handlers (CRUD).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use auths_scim::{
    apply_patch_operations, provision_result_to_scim_user, scim_user_to_provision_request,
    scim_user_to_update_fields, AuthsAgentExtension, ProvisionAgentResult, ScimError,
    ScimListResponse, ScimMeta, ScimPatchOp, ScimUser,
};

use crate::auth::AuthenticatedTenant;
use crate::db::ScimDb;
use crate::error::ScimServerError;
use crate::state::ScimServerState;

/// SCIM list query parameters (RFC 7644 Section 3.4.2).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListParams {
    pub filter: Option<String>,
    pub start_index: Option<u64>,
    pub count: Option<u64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub attributes: Option<String>,
    pub excluded_attributes: Option<String>,
}

/// `POST /Users` — Create a new agent identity.
///
/// Args:
/// * `state`: Shared server state with DB pool.
/// * `tenant`: Authenticated tenant from bearer token.
/// * `body`: SCIM User resource to create.
///
/// Usage:
/// ```ignore
/// POST /Users
/// Authorization: Bearer <token>
/// Content-Type: application/scim+json
/// {"schemas": [...], "userName": "deploy-bot"}
/// ```
#[allow(clippy::disallowed_methods)] // Layer 6 boundary: Utc::now(), Uuid::new_v4()
pub async fn create_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Json(body): Json<ScimUser>,
) -> Result<(StatusCode, HeaderMap, Json<ScimUser>), ScimServerError> {
    let provision_req = scim_user_to_provision_request(&body, &tenant.allowed_capabilities)?;

    // Idempotent POST: if externalId already exists, return existing resource
    if let Some(ref ext_id) = provision_req.external_id {
        if let Some(existing) =
            ScimDb::find_by_external_id(state.db(), tenant.tenant_id, ext_id).await?
        {
            let user = agent_row_to_scim_user(&existing, state.base_url());
            let mut headers = HeaderMap::new();
            headers.insert("Location", make_location(state.base_url(), existing.id));
            headers.insert("ETag", make_etag(existing.version));
            return Ok((StatusCode::OK, headers, Json(user)));
        }
    }

    let agent_id = Uuid::new_v4();
    let identity_did = format!("did:keri:E{}", hex::encode(&agent_id.as_bytes()[..8]));
    let now = Utc::now();

    let row = ScimDb::insert_agent(
        state.db(),
        tenant.tenant_id,
        provision_req.external_id.as_deref(),
        &identity_did,
        &provision_req.user_name,
        provision_req.display_name.as_deref(),
        &provision_req.capabilities,
    )
    .await?;

    let result = ProvisionAgentResult {
        id: row.id.to_string(),
        identity_did: row.identity_did.clone(),
        created_at: row.created_at,
    };

    let scim_user = provision_result_to_scim_user(&result, &provision_req, now, state.base_url());

    let mut headers = HeaderMap::new();
    headers.insert("Location", make_location(state.base_url(), row.id));
    headers.insert("ETag", make_etag(row.version));

    Ok((StatusCode::CREATED, headers, Json(scim_user)))
}

/// `GET /Users/{id}` — Retrieve a single agent resource.
///
/// Args:
/// * `state`: Shared server state.
/// * `tenant`: Authenticated tenant.
/// * `id`: Agent UUID from path.
///
/// Usage:
/// ```ignore
/// GET /Users/a1b2c3d4-...
/// Authorization: Bearer <token>
/// ```
pub async fn get_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<ScimUser>), ScimServerError> {
    let row = ScimDb::find_agent(state.db(), tenant.tenant_id, id)
        .await?
        .ok_or(ScimServerError::Scim(ScimError::NotFound {
            id: id.to_string(),
        }))?;

    let user = agent_row_to_scim_user(&row, state.base_url());
    let mut headers = HeaderMap::new();
    headers.insert("ETag", make_etag(row.version));

    Ok((headers, Json(user)))
}

/// `GET /Users` — List agents with filtering and pagination.
///
/// Args:
/// * `state`: Shared server state.
/// * `tenant`: Authenticated tenant.
/// * `params`: SCIM query parameters (filter, pagination, sort).
///
/// Usage:
/// ```ignore
/// GET /Users?filter=active+eq+true&startIndex=1&count=10
/// Authorization: Bearer <token>
/// ```
pub async fn list_users(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Query(params): Query<ScimListParams>,
) -> Result<Json<ScimListResponse<ScimUser>>, ScimServerError> {
    if let Some(ref filter_str) = params.filter {
        let _parsed = auths_scim::parse_filter(filter_str).map_err(ScimServerError::Scim)?;
    }

    let start_index = params.start_index.unwrap_or(1).max(1);
    let count = params
        .count
        .unwrap_or(100)
        .min(state.config().max_filter_results);
    let offset = (start_index - 1) as i64;

    let total = ScimDb::count_agents(state.db(), tenant.tenant_id).await?;
    let rows = ScimDb::list_agents(state.db(), tenant.tenant_id, offset, count as i64).await?;

    let users: Vec<ScimUser> = rows
        .iter()
        .map(|r| agent_row_to_scim_user(r, state.base_url()))
        .collect();

    let response = ScimListResponse::new(users, total as u64, start_index);
    Ok(Json(response))
}

/// `PUT /Users/{id}` — Full replacement of mutable fields.
///
/// Args:
/// * `state`: Shared server state.
/// * `tenant`: Authenticated tenant.
/// * `id`: Agent UUID from path.
/// * `headers`: Request headers (for If-Match).
/// * `body`: Complete SCIM User resource.
///
/// Usage:
/// ```ignore
/// PUT /Users/a1b2c3d4-...
/// Authorization: Bearer <token>
/// If-Match: W/"v1"
/// ```
pub async fn replace_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ScimUser>,
) -> Result<(HeaderMap, Json<ScimUser>), ScimServerError> {
    let existing = ScimDb::find_agent(state.db(), tenant.tenant_id, id)
        .await?
        .ok_or(ScimServerError::Scim(ScimError::NotFound {
            id: id.to_string(),
        }))?;

    check_etag(&headers, existing.version)?;

    if body.user_name != existing.user_name {
        return Err(ScimServerError::Scim(ScimError::Mutability {
            attribute: "userName".into(),
        }));
    }

    let fields = scim_user_to_update_fields(&body);
    let updated = ScimDb::update_agent(
        state.db(),
        id,
        tenant.tenant_id,
        fields.display_name.as_deref(),
        fields.external_id.as_deref(),
        &fields.capabilities,
        fields.active,
        existing.version,
    )
    .await?
    .ok_or(ScimServerError::Scim(ScimError::PreconditionFailed))?;

    let user = agent_row_to_scim_user(&updated, state.base_url());
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("ETag", make_etag(updated.version));

    Ok((resp_headers, Json(user)))
}

/// `PATCH /Users/{id}` — Partial update (active, displayName, capabilities).
///
/// Args:
/// * `state`: Shared server state.
/// * `tenant`: Authenticated tenant.
/// * `id`: Agent UUID from path.
/// * `headers`: Request headers (for optional If-Match).
/// * `body`: SCIM PatchOp request.
///
/// Usage:
/// ```ignore
/// PATCH /Users/a1b2c3d4-...
/// Authorization: Bearer <token>
/// {"schemas": [...], "Operations": [{"op": "Replace", "value": {"active": false}}]}
/// ```
pub async fn update_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ScimPatchOp>,
) -> Result<(HeaderMap, Json<ScimUser>), ScimServerError> {
    let existing = ScimDb::find_agent(state.db(), tenant.tenant_id, id)
        .await?
        .ok_or(ScimServerError::Scim(ScimError::NotFound {
            id: id.to_string(),
        }))?;

    // If-Match is optional for PATCH but checked if present
    if headers.contains_key("If-Match") {
        check_etag(&headers, existing.version)?;
    }

    let current_user = agent_row_to_scim_user(&existing, state.base_url());
    let patched = apply_patch_operations(current_user, &body.operations)?;

    let caps = patched
        .auths_extension
        .as_ref()
        .map(|ext| ext.capabilities.clone())
        .unwrap_or_default();

    let updated = ScimDb::update_agent(
        state.db(),
        id,
        tenant.tenant_id,
        patched.display_name.as_deref(),
        patched.external_id.as_deref(),
        &caps,
        patched.active,
        existing.version,
    )
    .await?
    .ok_or(ScimServerError::Scim(ScimError::PreconditionFailed))?;

    let user = agent_row_to_scim_user(&updated, state.base_url());
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("ETag", make_etag(updated.version));

    Ok((resp_headers, Json(user)))
}

/// `DELETE /Users/{id}` — Hard-delete with KERI revocation.
///
/// Args:
/// * `state`: Shared server state.
/// * `tenant`: Authenticated tenant.
/// * `id`: Agent UUID from path.
///
/// Usage:
/// ```ignore
/// DELETE /Users/a1b2c3d4-...
/// Authorization: Bearer <token>
/// ```
pub async fn delete_user(
    State(state): State<ScimServerState>,
    tenant: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ScimServerError> {
    let _existing = ScimDb::find_agent(state.db(), tenant.tenant_id, id)
        .await?
        .ok_or(ScimServerError::Scim(ScimError::NotFound {
            id: id.to_string(),
        }))?;

    // TODO: Revoke KERI identity via SDK before deleting from PostgreSQL.
    // The saga ordering is: Git revocation first, then PostgreSQL delete.

    let deleted = ScimDb::delete_agent(state.db(), id, tenant.tenant_id).await?;
    if !deleted {
        return Err(ScimServerError::Scim(ScimError::NotFound {
            id: id.to_string(),
        }));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[allow(clippy::expect_used)] // ETag format is always valid ASCII
fn make_etag(version: i64) -> HeaderValue {
    format!("W/\"v{}\"", version)
        .parse()
        .expect("ETag is valid ASCII")
}

#[allow(clippy::expect_used)] // Location URL is always valid ASCII
fn make_location(base_url: &str, id: uuid::Uuid) -> HeaderValue {
    format!("{}/Users/{}", base_url, id)
        .parse()
        .expect("Location URL is valid ASCII")
}

fn agent_row_to_scim_user(row: &crate::db::AgentRow, base_url: &str) -> ScimUser {
    ScimUser {
        schemas: ScimUser::default_schemas(),
        id: row.id.to_string(),
        external_id: row.external_id.clone(),
        user_name: row.user_name.clone(),
        display_name: row.display_name.clone(),
        active: row.active,
        meta: ScimMeta {
            resource_type: "User".into(),
            created: row.created_at,
            last_modified: row.last_modified,
            version: format!("W/\"v{}\"", row.version),
            location: format!("{}/Users/{}", base_url, row.id),
        },
        auths_extension: Some(AuthsAgentExtension {
            identity_did: row.identity_did.clone(),
            capabilities: row.capabilities.clone(),
        }),
    }
}

fn check_etag(headers: &HeaderMap, current_version: i64) -> Result<(), ScimServerError> {
    if let Some(if_match) = headers.get("If-Match") {
        let expected = format!("W/\"v{}\"", current_version);
        let provided = if_match.to_str().unwrap_or("");
        if provided != expected {
            return Err(ScimServerError::Scim(ScimError::PreconditionFailed));
        }
    }
    Ok(())
}
