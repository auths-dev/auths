//! Read-only SCIM discovery endpoints (RFC 7644 §4) and the auth-gated `/Users`
//! list stub.
//!
//! Discovery serves the shipped `auths_scim::schema` types directly and is
//! unauthenticated, as Okta/Entra expect. `/Users` is auth-gated and returns an
//! empty list until the Joiner/Leaver lifecycle wiring lands.

use auths_scim::resource::ScimUser;
use auths_scim::schema::{ResourceType, SchemaDefinition, SchemaExtension, ServiceProviderConfig};
use auths_scim::{ScimListResponse, constants};
use axum::Json;

use crate::auth::AuthenticatedTenant;

/// `GET /scim/v2/ServiceProviderConfig` — advertised server capabilities.
pub async fn service_provider_config() -> Json<ServiceProviderConfig> {
    Json(ServiceProviderConfig::auths_default())
}

/// `GET /scim/v2/ResourceTypes` — the resource types this server exposes.
pub async fn resource_types() -> Json<ScimListResponse<ResourceType>> {
    let types = vec![user_resource_type()];
    let total = types.len() as u64;
    Json(ScimListResponse::new(types, total, 1))
}

/// `GET /scim/v2/Schemas` — the schemas backing the resource types.
pub async fn schemas() -> Json<ScimListResponse<SchemaDefinition>> {
    let schemas = vec![user_schema()];
    let total = schemas.len() as u64;
    Json(ScimListResponse::new(schemas, total, 1))
}

/// `GET /scim/v2/Users` — auth-gated. Returns an empty list until provisioning
/// is wired (the Joiner task replaces this with real, filterable listing).
pub async fn list_users(_tenant: AuthenticatedTenant) -> Json<ScimListResponse<ScimUser>> {
    Json(ScimListResponse::new(vec![], 0, 1))
}

fn user_resource_type() -> ResourceType {
    ResourceType {
        schemas: vec![constants::SCHEMA_RESOURCE_TYPE.into()],
        id: "User".into(),
        name: "User".into(),
        endpoint: "/Users".into(),
        schema: constants::SCHEMA_USER.into(),
        description: Some("Auths agent identity".into()),
        schema_extensions: vec![SchemaExtension {
            schema: constants::SCHEMA_AUTHS_AGENT.into(),
            required: false,
        }],
    }
}

fn user_schema() -> SchemaDefinition {
    SchemaDefinition {
        schemas: vec![constants::SCHEMA_SCHEMA.into()],
        id: constants::SCHEMA_USER.into(),
        name: "User".into(),
        description: Some(
            "SCIM core User; attribute definitions are published as the lifecycle wiring lands"
                .into(),
        ),
        attributes: vec![],
    }
}
