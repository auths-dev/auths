//! SCIM 2.0 User resource type and custom Auths extension.

use auths_verifier::{Capability, IdentityDID};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::constants::{SCHEMA_AUTHS_AGENT, SCHEMA_GROUP, SCHEMA_USER};

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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub version: String,
    pub location: String,
}

/// Auths-specific SCIM extension attributes.
///
/// Exposed under `urn:ietf:params:scim:schemas:extension:auths:2.0:Agent`.
/// The `identity_did` is the KERI DID (`did:keri:E…`) — **read-only**, assigned by
/// the server during provisioning, so it is absent on an inbound IdP create/PATCH
/// and present on every server response. It is the typed [`IdentityDID`] newtype
/// (validate-on-deserialize, fail-closed) rather than a bare `String`. The
/// `capabilities` list is writable by the IdP.
///
/// `revoked` is the honest deprovision-vs-revocation signal: a member soft-disabled
/// via `PATCH {active:false}` reports `active:false revoked:false` — still
/// KERI-authoritative until an explicit hard-revoke flips `revoked:true`. It is
/// server-authoritative (the IdP cannot set it through PATCH) so a deprovisioned
/// member is never silently presented as cryptographically off-boarded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthsAgentExtension {
    /// KERI DID assigned by Auths (read-only for IdP; absent until provisioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<IdentityDID>,
    /// Capabilities granted to this agent.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Whether the underlying KERI identity has been cryptographically revoked
    /// (irreversible hard-revoke). `false` for a merely soft-disabled member.
    /// Server-authoritative; read-only for the IdP.
    #[serde(default)]
    pub revoked: bool,
}

/// A SCIM Group resource (RFC 7643 §4.2) — a named collection of members.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(default)]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<GroupMember>,
    #[serde(default)]
    pub meta: ScimMeta,
}

impl ScimGroup {
    /// Default schemas for a new Group resource.
    pub fn default_schemas() -> Vec<String> {
        vec![SCHEMA_GROUP.into()]
    }
}

/// A member reference within a SCIM Group (RFC 7643 §4.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    /// The member resource's `id`.
    pub value: String,
    /// A human-readable label for the member (e.g. the user's `userName`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// The URI reference to the member resource, serialized as `$ref`.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
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
                identity_did: Some(IdentityDID::parse("did:keri:Eabc123").unwrap()),
                capabilities: vec![
                    Capability::parse("sign:commit").unwrap(),
                    Capability::parse("deploy:staging").unwrap(),
                ],
                revoked: false,
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
        user.schemas.retain(|s| s != SCHEMA_AUTHS_AGENT);
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

    #[test]
    fn scim_group_serializes_with_display_name_and_members() {
        let group = ScimGroup {
            schemas: ScimGroup::default_schemas(),
            id: "g-1".into(),
            external_id: Some("okta-grp-9".into()),
            display_name: "engineering".into(),
            members: vec![GroupMember {
                value: "u-1".into(),
                display: Some("alice".into()),
                ref_uri: Some("/Users/u-1".into()),
            }],
            meta: ScimMeta::default(),
        };
        let json = serde_json::to_string(&group).unwrap();
        assert!(json.contains("\"displayName\":\"engineering\""));
        assert!(json.contains("\"members\""));
        assert!(json.contains("\"value\":\"u-1\""));
        // The member reference uses the SCIM `$ref` key, not the Rust field name.
        assert!(json.contains("\"$ref\":\"/Users/u-1\""));
        assert!(json.contains(SCHEMA_GROUP));
        // Round-trips through serde.
        let back: ScimGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back, group);
    }

    #[test]
    fn group_default_schemas() {
        let schemas = ScimGroup::default_schemas();
        assert_eq!(schemas, vec![SCHEMA_GROUP.to_string()]);
    }
}
