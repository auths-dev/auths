//! SCIM 2.0 User resource type and custom Auths extension.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::constants::{SCHEMA_AUTHS_AGENT, SCHEMA_USER};

/// SCIM 2.0 User resource adapted for Auths agent identities.
///
/// The `schemas` field always includes the core User schema and the
/// Auths agent extension. Fields not used by agents (password, emails,
/// phoneNumbers) are omitted — RFC 7643 allows partial schema support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(default)]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub meta: ScimMeta,
    /// Auths agent extension attributes.
    #[serde(rename = "urn:ietf:params:scim:schemas:extension:auths:2.0:Agent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auths_extension: Option<AuthsAgentExtension>,
}

impl ScimUser {
    /// Default schemas for a new User resource.
    pub fn default_schemas() -> Vec<String> {
        vec![SCHEMA_USER.into(), SCHEMA_AUTHS_AGENT.into()]
    }
}

fn default_active() -> bool {
    true
}

/// SCIM resource metadata (RFC 7643 Section 3.1).
///
/// All fields default for deserialization since clients omit `meta` on POST.
/// The server always overwrites these with authoritative values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub version: String,
    pub location: String,
}

impl Default for ScimMeta {
    fn default() -> Self {
        Self {
            resource_type: String::new(),
            created: DateTime::default(),
            last_modified: DateTime::default(),
            version: String::new(),
            location: String::new(),
        }
    }
}

/// Auths-specific SCIM extension attributes.
///
/// Exposed under `urn:ietf:params:scim:schemas:extension:auths:2.0:Agent`.
/// The `identity_did` is the KERI DID (did:keri:E...) — read-only, assigned
/// by the server during provisioning. The `capabilities` list is writable
/// by the IdP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthsAgentExtension {
    /// KERI DID assigned by Auths (read-only for IdP).
    pub identity_did: String,
    /// Capabilities granted to this agent.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_user() -> ScimUser {
        ScimUser {
            schemas: ScimUser::default_schemas(),
            id: "abc-123".into(),
            external_id: Some("okta-user-456".into()),
            user_name: "deploy-bot".into(),
            display_name: Some("Deploy Bot".into()),
            active: true,
            meta: ScimMeta {
                resource_type: "User".into(),
                created: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                last_modified: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                version: r#"W/"v1""#.into(),
                location: "/Users/abc-123".into(),
            },
            auths_extension: Some(AuthsAgentExtension {
                identity_did: "did:keri:Eabc123".into(),
                capabilities: vec!["sign:commit".into(), "deploy:staging".into()],
            }),
        }
    }

    #[test]
    fn serde_roundtrip() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        let parsed: ScimUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, user);
    }

    #[test]
    fn serde_camel_case_fields() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("userName"));
        assert!(json.contains("displayName"));
        assert!(json.contains("externalId"));
        assert!(json.contains("resourceType"));
        assert!(json.contains("lastModified"));
    }

    #[test]
    fn serde_extension_key() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains(SCHEMA_AUTHS_AGENT));
    }

    #[test]
    fn serde_without_extension() {
        let mut user = sample_user();
        user.auths_extension = None;
        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains(SCHEMA_AUTHS_AGENT));
    }

    #[test]
    fn default_schemas() {
        let schemas = ScimUser::default_schemas();
        assert_eq!(schemas.len(), 2);
        assert!(schemas.contains(&SCHEMA_USER.to_string()));
        assert!(schemas.contains(&SCHEMA_AUTHS_AGENT.to_string()));
    }
}
