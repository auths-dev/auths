//! SCIM PATCH operation types (RFC 7644 Section 3.5.2).

use serde::{Deserialize, Serialize};

use crate::error::ScimError;
use crate::resource::{AuthsAgentExtension, ScimUser};

/// SCIM PATCH request body (RFC 7644 Section 3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// A single PATCH operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// Normalized PATCH operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOpType {
    Add,
    Remove,
    Replace,
}

impl PatchOpType {
    /// Parse a PATCH operation string (case-insensitive for Azure AD compatibility).
    pub fn parse(op: &str) -> Result<Self, ScimError> {
        match op.to_lowercase().as_str() {
            "add" => Ok(Self::Add),
            "remove" => Ok(Self::Remove),
            "replace" => Ok(Self::Replace),
            _ => Err(ScimError::InvalidPatch {
                message: format!(
                    "Unknown operation '{}'. Use 'add', 'remove', or 'replace'.",
                    op
                ),
            }),
        }
    }
}

/// Immutable SCIM fields that cannot be modified via PATCH.
const IMMUTABLE_FIELDS: &[&str] = &["id", "userName", "meta"];

/// Apply PATCH operations to a ScimUser (pure function).
///
/// Args:
/// * `user`: The user to patch (consumed and returned modified).
/// * `operations`: The PATCH operations to apply.
///
/// Usage:
/// ```ignore
/// let patched = apply_patch_operations(user, &ops)?;
/// ```
pub fn apply_patch_operations(
    mut user: ScimUser,
    operations: &[PatchOperation],
) -> Result<ScimUser, ScimError> {
    for op in operations {
        let op_type = PatchOpType::parse(&op.op)?;
        let path = op.path.as_deref();

        if let Some(path) = path
            && IMMUTABLE_FIELDS.contains(&path)
        {
            return Err(ScimError::Mutability {
                attribute: path.to_string(),
            });
        }

        match (op_type, path) {
            (PatchOpType::Replace, Some("active")) | (PatchOpType::Add, Some("active")) => {
                let active = op.value.as_ref().and_then(|v| v.as_bool()).ok_or_else(|| {
                    ScimError::InvalidValue {
                        message: "active must be a boolean. Set it to true or false.".into(),
                    }
                })?;
                user.active = active;
            }
            (PatchOpType::Replace, Some("displayName"))
            | (PatchOpType::Add, Some("displayName")) => {
                let name = op.value.as_ref().and_then(|v| v.as_str()).ok_or_else(|| {
                    ScimError::InvalidValue {
                        message: "displayName must be a string.".into(),
                    }
                })?;
                user.display_name = Some(name.to_string());
            }
            (PatchOpType::Remove, Some("displayName")) => {
                user.display_name = None;
            }
            (PatchOpType::Replace, Some("externalId")) | (PatchOpType::Add, Some("externalId")) => {
                let ext_id = op.value.as_ref().and_then(|v| v.as_str()).ok_or_else(|| {
                    ScimError::InvalidValue {
                        message: "externalId must be a string.".into(),
                    }
                })?;
                user.external_id = Some(ext_id.to_string());
            }
            (PatchOpType::Replace, None) => {
                if let Some(value) = &op.value {
                    apply_replace_no_path(&mut user, value)?;
                }
            }
            (_, Some(path)) if is_extension_path(path) => {
                apply_extension_patch(&mut user, op_type, path, &op.value)?;
            }
            (_, Some(path)) => {
                return Err(ScimError::InvalidPatch {
                    message: format!(
                        "Unsupported path '{}'. Supported: active, displayName, externalId, extension attributes.",
                        path
                    ),
                });
            }
            (_, None) => {
                return Err(ScimError::InvalidPatch {
                    message: "Path is required for add/remove operations.".into(),
                });
            }
        }
    }

    Ok(user)
}

fn apply_replace_no_path(user: &mut ScimUser, value: &serde_json::Value) -> Result<(), ScimError> {
    if let Some(active) = value.get("active").and_then(|v| v.as_bool()) {
        user.active = active;
    }
    if let Some(name) = value.get("displayName").and_then(|v| v.as_str()) {
        user.display_name = Some(name.to_string());
    }
    if let Some(ext_id) = value.get("externalId").and_then(|v| v.as_str()) {
        user.external_id = Some(ext_id.to_string());
    }
    Ok(())
}

fn is_extension_path(path: &str) -> bool {
    path.starts_with("urn:") || path == "capabilities"
}

fn apply_extension_patch(
    user: &mut ScimUser,
    op_type: PatchOpType,
    path: &str,
    value: &Option<serde_json::Value>,
) -> Result<(), ScimError> {
    let ext = user
        .auths_extension
        .get_or_insert_with(|| AuthsAgentExtension {
            identity_did: String::new(),
            capabilities: Vec::new(),
        });

    let effective_path = if path.contains(':') {
        // Strip the extension URI prefix to get the attribute name
        path.rsplit_once('.').map_or(path, |(_, attr)| attr)
    } else {
        path
    };

    match (op_type, effective_path) {
        (PatchOpType::Replace, "capabilities") | (PatchOpType::Add, "capabilities") => {
            let caps = value.as_ref().and_then(|v| v.as_array()).ok_or_else(|| {
                ScimError::InvalidValue {
                    message: "capabilities must be an array of strings.".into(),
                }
            })?;
            let caps: Result<Vec<String>, _> = caps
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| ScimError::InvalidValue {
                            message: "Each capability must be a string.".into(),
                        })
                })
                .collect();
            ext.capabilities = caps?;
        }
        (PatchOpType::Remove, "capabilities") => {
            ext.capabilities.clear();
        }
        (_, "identityDid") => {
            return Err(ScimError::Mutability {
                attribute: "identityDid".into(),
            });
        }
        _ => {
            return Err(ScimError::InvalidPatch {
                message: format!(
                    "Unsupported extension path '{}'. Supported: capabilities.",
                    effective_path
                ),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::resource::ScimMeta;
    use chrono::Utc;

    fn test_user() -> ScimUser {
        ScimUser {
            schemas: ScimUser::default_schemas(),
            id: "test-123".into(),
            external_id: Some("ext-456".into()),
            user_name: "test-bot".into(),
            display_name: Some("Test Bot".into()),
            active: true,
            meta: ScimMeta {
                resource_type: "User".into(),
                created: Utc::now(),
                last_modified: Utc::now(),
                version: "v1".into(),
                location: "/Users/test-123".into(),
            },
            auths_extension: Some(AuthsAgentExtension {
                identity_did: "did:keri:Etest".into(),
                capabilities: vec!["sign:commit".into()],
            }),
        }
    }

    #[test]
    fn parse_op_type_case_insensitive() {
        assert_eq!(PatchOpType::parse("replace").unwrap(), PatchOpType::Replace);
        assert_eq!(PatchOpType::parse("Replace").unwrap(), PatchOpType::Replace);
        assert_eq!(PatchOpType::parse("REPLACE").unwrap(), PatchOpType::Replace);
        assert_eq!(PatchOpType::parse("add").unwrap(), PatchOpType::Add);
        assert_eq!(PatchOpType::parse("Add").unwrap(), PatchOpType::Add);
    }

    #[test]
    fn parse_op_type_invalid() {
        assert!(PatchOpType::parse("unknown").is_err());
    }

    #[test]
    fn patch_active_false() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "Replace".into(),
            path: Some("active".into()),
            value: Some(serde_json::Value::Bool(false)),
        }];
        let patched = apply_patch_operations(user, &ops).unwrap();
        assert!(!patched.active);
    }

    #[test]
    fn patch_display_name() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: Some("displayName".into()),
            value: Some(serde_json::Value::String("New Name".into())),
        }];
        let patched = apply_patch_operations(user, &ops).unwrap();
        assert_eq!(patched.display_name, Some("New Name".into()));
    }

    #[test]
    fn patch_immutable_field_rejected() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: Some("id".into()),
            value: Some(serde_json::Value::String("new-id".into())),
        }];
        let result = apply_patch_operations(user, &ops);
        assert!(result.is_err());
    }

    #[test]
    fn patch_identity_did_rejected() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: Some("identityDid".into()),
            value: Some(serde_json::Value::String("did:keri:new".into())),
        }];
        let result = apply_patch_operations(user, &ops);
        assert!(result.is_err());
    }

    #[test]
    fn patch_capabilities() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "replace".into(),
            path: Some("capabilities".into()),
            value: Some(serde_json::json!(["deploy:prod", "sign:commit"])),
        }];
        let patched = apply_patch_operations(user, &ops).unwrap();
        let ext = patched.auths_extension.unwrap();
        assert_eq!(ext.capabilities, vec!["deploy:prod", "sign:commit"]);
    }

    #[test]
    fn patch_replace_no_path_azure_style() {
        let user = test_user();
        let ops = vec![PatchOperation {
            op: "Replace".into(),
            path: None,
            value: Some(serde_json::json!({"active": false})),
        }];
        let patched = apply_patch_operations(user, &ops).unwrap();
        assert!(!patched.active);
    }
}
