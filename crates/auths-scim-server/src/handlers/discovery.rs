//! SCIM discovery endpoints (no authentication required).

use axum::response::IntoResponse;
use axum::Json;

use auths_scim::{
    ResourceType, SchemaExtension, ServiceProviderConfig, SCHEMA_AUTHS_AGENT, SCHEMA_RESOURCE_TYPE,
    SCHEMA_USER,
};

/// `GET /ServiceProviderConfig`
pub async fn service_provider_config() -> impl IntoResponse {
    Json(ServiceProviderConfig::auths_default())
}

/// `GET /ResourceTypes`
pub async fn resource_types() -> impl IntoResponse {
    let user_type = ResourceType {
        schemas: vec![SCHEMA_RESOURCE_TYPE.into()],
        id: "User".into(),
        name: "User".into(),
        endpoint: "/Users".into(),
        schema: SCHEMA_USER.into(),
        description: Some("Auths agent identity".into()),
        schema_extensions: vec![SchemaExtension {
            schema: SCHEMA_AUTHS_AGENT.into(),
            required: false,
        }],
    };
    Json(vec![user_type])
}

/// `GET /` — self-documenting API root.
pub async fn api_root() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "Auths SCIM 2.0 Provisioning API",
        "version": env!("CARGO_PKG_VERSION"),
        "docs": "https://docs.auths.dev/scim",
        "endpoints": {
            "users": "/Users",
            "service_provider_config": "/ServiceProviderConfig",
            "resource_types": "/ResourceTypes",
            "schemas": "/Schemas"
        }
    }))
}
