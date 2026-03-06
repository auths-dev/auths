//! SCIM 2.0 discovery response types (RFC 7643 Section 5).

use serde::{Deserialize, Serialize};

/// SCIM ServiceProviderConfig (RFC 7643 Section 5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProviderConfig {
    pub schemas: Vec<String>,
    pub patch: Supported,
    pub bulk: Supported,
    pub filter: FilterSupported,
    pub change_password: Supported,
    pub sort: Supported,
    pub etag: Supported,
    pub authentication_schemes: Vec<AuthenticationScheme>,
}

/// Feature support flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Supported {
    pub supported: bool,
}

/// Filter support with result limit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilterSupported {
    pub supported: bool,
    pub max_results: u64,
}

/// Authentication scheme descriptor (RFC 7643 Section 5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
}

/// SCIM ResourceType descriptor (RFC 7643 Section 6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceType {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_extensions: Vec<SchemaExtension>,
}

/// Schema extension reference for a ResourceType.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaExtension {
    pub schema: String,
    pub required: bool,
}

/// SCIM Schema definition (RFC 7643 Section 7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaDefinition {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub attributes: Vec<SchemaAttribute>,
}

/// A single attribute in a SCIM schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchemaAttribute {
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub multi_valued: bool,
    pub required: bool,
    pub case_exact: bool,
    pub mutability: String,
    pub returned: String,
    pub uniqueness: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ServiceProviderConfig {
    /// Build the Auths SCIM server's provider config.
    pub fn auths_default() -> Self {
        Self {
            schemas: vec![crate::constants::SCHEMA_SERVICE_PROVIDER_CONFIG.into()],
            patch: Supported { supported: true },
            bulk: Supported { supported: false },
            filter: FilterSupported {
                supported: true,
                max_results: 100,
            },
            change_password: Supported { supported: false },
            sort: Supported { supported: true },
            etag: Supported { supported: true },
            authentication_schemes: vec![AuthenticationScheme {
                scheme_type: "oauthbearertoken".into(),
                name: "Bearer Token".into(),
                description: "Bearer token authentication via SCIM API key".into(),
                spec_uri: Some("https://datatracker.ietf.org/doc/html/rfc6750".into()),
                documentation_uri: None,
            }],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn service_provider_config_roundtrip() {
        let config = ServiceProviderConfig::auths_default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ServiceProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn resource_type_roundtrip() {
        let rt = ResourceType {
            schemas: vec![crate::constants::SCHEMA_RESOURCE_TYPE.into()],
            id: "User".into(),
            name: "User".into(),
            endpoint: "/Users".into(),
            schema: crate::constants::SCHEMA_USER.into(),
            description: Some("Auths agent identity".into()),
            schema_extensions: vec![SchemaExtension {
                schema: crate::constants::SCHEMA_AUTHS_AGENT.into(),
                required: false,
            }],
        };
        let json = serde_json::to_string(&rt).unwrap();
        let parsed: ResourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rt);
    }
}
