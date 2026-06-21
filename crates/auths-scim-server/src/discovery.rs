//! Read-only SCIM discovery endpoints (RFC 7644 §4).
//!
//! Discovery serves the shipped `auths_scim::schema` types directly and is
//! unauthenticated, as Okta/Entra expect. The auth-gated `/Users` resource
//! handlers live in [`crate::users`].

use auths_scim::schema::{ResourceType, SchemaDefinition, SchemaExtension, ServiceProviderConfig};
use auths_scim::{ScimListResponse, constants};
use axum::Json;

/// `GET /scim/v2/ServiceProviderConfig` — advertised server capabilities.
pub async fn service_provider_config() -> Json<ServiceProviderConfig> {
    Json(ServiceProviderConfig::auths_default())
}

/// `GET /scim/v2/ResourceTypes` — the resource types this server exposes.
pub async fn resource_types() -> Json<ScimListResponse<ResourceType>> {
    let types = resource_type_list();
    let total = types.len() as u64;
    Json(ScimListResponse::new(types, total, 1))
}

/// `GET /scim/v2/Schemas` — the schemas backing the resource types.
pub async fn schemas() -> Json<ScimListResponse<SchemaDefinition>> {
    let schemas = schema_list();
    let total = schemas.len() as u64;
    Json(ScimListResponse::new(schemas, total, 1))
}

/// The resource types this server exposes (User and Group).
fn resource_type_list() -> Vec<ResourceType> {
    vec![user_resource_type(), group_resource_type()]
}

/// The schemas backing the resource types.
fn schema_list() -> Vec<SchemaDefinition> {
    vec![user_schema(), group_schema()]
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

fn group_resource_type() -> ResourceType {
    ResourceType {
        schemas: vec![constants::SCHEMA_RESOURCE_TYPE.into()],
        id: "Group".into(),
        name: "Group".into(),
        endpoint: "/Groups".into(),
        schema: constants::SCHEMA_GROUP.into(),
        description: Some("Org directory group".into()),
        schema_extensions: vec![],
    }
}

fn group_schema() -> SchemaDefinition {
    SchemaDefinition {
        schemas: vec![constants::SCHEMA_SCHEMA.into()],
        id: constants::SCHEMA_GROUP.into(),
        name: "Group".into(),
        description: Some(
            "SCIM core Group (displayName, members); attribute definitions are published as the \
             schema surface lands"
                .into(),
        ),
        attributes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_advertises_the_group_resource_and_schema() {
        // The Group resource type is advertised at /Groups with the core Group schema URI,
        // and it is included in the ResourceTypes listing alongside User.
        let listed = resource_type_list();
        let group = listed
            .iter()
            .find(|rt| rt.id == "Group")
            .expect("ResourceTypes must advertise Group");
        assert_eq!(group.endpoint, "/Groups");
        assert_eq!(group.schema, constants::SCHEMA_GROUP);

        // The Group schema is published under the core Group URI in the Schemas listing.
        let schema = schema_list()
            .into_iter()
            .find(|s| s.id == constants::SCHEMA_GROUP)
            .expect("Schemas must publish the Group schema");
        assert_eq!(schema.name, "Group");
    }
}
