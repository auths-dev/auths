//! SCIM-to-Auths field mapping.
//!
//! Produces intermediate DTOs that the server layer translates to SDK config types.
//! This keeps `auths-scim` decoupled from `auths-sdk`.

use auths_verifier::{Capability, IdentityDID};
use chrono::{DateTime, Utc};

use crate::error::ScimError;
use crate::resource::{AuthsAgentExtension, ScimMeta, ScimUser};

/// Request to provision a new agent identity (SCIM → Auths).
#[derive(Debug, Clone)]
pub struct ProvisionAgentRequest {
    /// IdP's external identifier.
    pub external_id: Option<String>,
    /// SCIM userName.
    pub user_name: String,
    /// Human-readable display name.
    pub display_name: Option<String>,
    /// Requested capabilities.
    pub capabilities: Vec<Capability>,
}

/// Result of provisioning an agent identity (Auths → SCIM).
#[derive(Debug, Clone)]
pub struct ProvisionAgentResult {
    /// Auths-internal resource UUID.
    pub id: String,
    /// KERI DID assigned by Auths.
    pub identity_did: String,
    /// When the identity was created.
    pub created_at: DateTime<Utc>,
}

/// Request to deactivate an agent (SCIM `active: false`).
#[derive(Debug, Clone)]
pub struct DeactivateAgentRequest {
    /// Auths-internal resource UUID.
    pub id: String,
    /// KERI DID of the agent.
    pub identity_did: String,
}

/// Request to permanently revoke an agent (SCIM DELETE).
#[derive(Debug, Clone)]
pub struct RevokeAgentRequest {
    /// Auths-internal resource UUID.
    pub id: String,
    /// KERI DID of the agent.
    pub identity_did: String,
}

/// Fields that can be updated via SCIM PUT.
#[derive(Debug, Clone)]
pub struct UpdateAgentFields {
    pub display_name: Option<String>,
    pub external_id: Option<String>,
    pub capabilities: Vec<Capability>,
    pub active: bool,
}

/// Convert a SCIM User create request to a provision request.
///
/// Args:
/// * `user`: The incoming SCIM User resource.
/// * `allowed_capabilities`: Tenant-scoped capability allowlist (deny by default).
/// * `allow_all`: Opt-in permit-all that bypasses the allowlist.
///
/// Usage:
/// ```ignore
/// let request = scim_user_to_provision_request(&scim_user, &allowed, false)?;
/// ```
pub fn scim_user_to_provision_request(
    user: &ScimUser,
    allowed_capabilities: &[Capability],
    allow_all: bool,
) -> Result<ProvisionAgentRequest, ScimError> {
    if user.user_name.is_empty() {
        return Err(ScimError::MissingAttribute {
            attribute: "userName".into(),
        });
    }

    let capabilities = user
        .auths_extension
        .as_ref()
        .map(|ext| ext.capabilities.clone())
        .unwrap_or_default();

    if !allow_all {
        validate_capabilities(&capabilities, allowed_capabilities)?;
    }

    Ok(ProvisionAgentRequest {
        external_id: user.external_id.clone(),
        user_name: user.user_name.clone(),
        display_name: user.display_name.clone(),
        capabilities,
    })
}

/// Convert a provision result to a SCIM User response.
///
/// Args:
/// * `result`: The provision result from the SDK.
/// * `request`: The original provision request.
/// * `now`: Current time for metadata.
/// * `base_url`: Base URL for resource location.
///
/// Usage:
/// ```ignore
/// let scim_user = provision_result_to_scim_user(&result, &request, now, "https://api.example.com");
/// ```
pub fn provision_result_to_scim_user(
    result: &ProvisionAgentResult,
    request: &ProvisionAgentRequest,
    now: DateTime<Utc>,
    base_url: &str,
) -> ScimUser {
    ScimUser {
        schemas: ScimUser::default_schemas(),
        id: result.id.clone(),
        external_id: request.external_id.clone(),
        user_name: request.user_name.clone(),
        display_name: request.display_name.clone(),
        active: true,
        meta: ScimMeta {
            resource_type: "User".into(),
            created: result.created_at,
            last_modified: now,
            version: format!("W/\"{}\"", etag_hash(&result.id, 1)),
            location: format!("{}/Users/{}", base_url, result.id),
        },
        auths_extension: Some(AuthsAgentExtension {
            // Fail-closed: the SDK yields a valid `did:keri`, but a malformed value
            // renders as absent rather than flowing through as a bad DID.
            identity_did: IdentityDID::parse(&result.identity_did).ok(),
            capabilities: request.capabilities.clone(),
            revoked: false,
        }),
    }
}

/// Extract updatable fields from a SCIM User (for PUT).
pub fn scim_user_to_update_fields(user: &ScimUser) -> UpdateAgentFields {
    let capabilities = user
        .auths_extension
        .as_ref()
        .map(|ext| ext.capabilities.clone())
        .unwrap_or_default();

    UpdateAgentFields {
        display_name: user.display_name.clone(),
        external_id: user.external_id.clone(),
        capabilities,
        active: user.active,
    }
}

/// Reject any requested capability outside the tenant's allowlist.
///
/// **Deny by default (RT-006):** an empty allowlist permits NO capabilities, so
/// a tenant must explicitly enumerate what it may grant — or opt into permit-all
/// at the call site (`allow_all`). A request carrying no capabilities always
/// passes. Previously an empty allowlist meant "permit all", which — combined
/// with the setter never being wired — let every tenant anchor arbitrary
/// authority into the org KEL.
pub fn validate_capabilities(
    capabilities: &[Capability],
    allowed: &[Capability],
) -> Result<(), ScimError> {
    for cap in capabilities {
        if !allowed.contains(cap) {
            return Err(ScimError::CapabilityNotAllowed {
                capability: cap.as_str().to_string(),
            });
        }
    }
    Ok(())
}

fn etag_hash(id: &str, version: u64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    version.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::resource::ScimMeta;
    use chrono::Utc;

    fn sample_scim_user() -> ScimUser {
        ScimUser {
            schemas: ScimUser::default_schemas(),
            id: String::new(),
            external_id: Some("okta-123".into()),
            user_name: "deploy-bot".into(),
            display_name: Some("Deploy Bot".into()),
            active: true,
            meta: ScimMeta {
                resource_type: "User".into(),
                created: Utc::now(),
                last_modified: Utc::now(),
                version: "v1".into(),
                location: String::new(),
            },
            auths_extension: Some(AuthsAgentExtension {
                // Read-only/server-assigned: an inbound IdP create omits the DID.
                identity_did: None,
                capabilities: vec![Capability::parse("sign:commit").unwrap()],
                revoked: false,
            }),
        }
    }

    #[test]
    fn provision_request_from_scim() {
        let user = sample_scim_user();
        let allowed = vec![
            Capability::parse("sign:commit").unwrap(),
            Capability::parse("deploy:staging").unwrap(),
        ];
        let req = scim_user_to_provision_request(&user, &allowed, false).unwrap();
        assert_eq!(req.user_name, "deploy-bot");
        assert_eq!(
            req.capabilities,
            vec![Capability::parse("sign:commit").unwrap()]
        );
    }

    #[test]
    fn missing_username_rejected() {
        let mut user = sample_scim_user();
        user.user_name = String::new();
        let result = scim_user_to_provision_request(&user, &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn disallowed_capability_rejected() {
        let user = sample_scim_user();
        let allowed = vec![Capability::parse("deploy:staging").unwrap()]; // sign:commit not allowed
        let result = scim_user_to_provision_request(&user, &allowed, false);
        assert!(result.is_err());
    }

    #[test]
    fn empty_allowlist_denies_capabilities() {
        // RT-006: an unconfigured (empty) allowlist must DENY, not permit-all —
        // otherwise any SCIM tenant could anchor arbitrary authority into the KEL.
        let user = sample_scim_user(); // requests `sign:commit`
        let result = scim_user_to_provision_request(&user, &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn allow_all_bypasses_the_allowlist() {
        // The explicit permit-all opt-in still works for single-tenant pilots.
        let user = sample_scim_user();
        let result = scim_user_to_provision_request(&user, &[], true);
        assert!(result.is_ok());
    }

    #[test]
    fn provision_result_to_scim() {
        let result = ProvisionAgentResult {
            id: "uuid-123".into(),
            identity_did: "did:keri:Eabc".into(),
            created_at: Utc::now(),
        };
        let request = ProvisionAgentRequest {
            external_id: Some("okta-456".into()),
            user_name: "bot".into(),
            display_name: None,
            capabilities: vec![Capability::parse("sign:commit").unwrap()],
        };
        let now = Utc::now();
        let user =
            provision_result_to_scim_user(&result, &request, now, "https://scim.example.com");
        assert_eq!(user.id, "uuid-123");
        assert_eq!(user.user_name, "bot");
        assert!(user.meta.location.contains("uuid-123"));
        let ext = user.auths_extension.unwrap();
        assert_eq!(
            ext.identity_did.as_ref().map(|d| d.as_str()),
            Some("did:keri:Eabc")
        );
    }

    #[test]
    fn update_fields_extraction() {
        let user = sample_scim_user();
        let fields = scim_user_to_update_fields(&user);
        assert_eq!(fields.display_name, Some("Deploy Bot".into()));
        assert!(fields.active);
        assert_eq!(
            fields.capabilities,
            vec![Capability::parse("sign:commit").unwrap()]
        );
    }
}
