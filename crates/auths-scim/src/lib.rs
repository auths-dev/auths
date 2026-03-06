//! SCIM 2.0 protocol types and logic for Auths agent provisioning.
//!
//! This crate is Layer 3 — pure protocol types, filter parsing, field mapping.
//! No HTTP, no storage, no server code. No dependency on `auths-sdk`.
//!
//! # Modules
//!
//! - [`constants`]: SCIM schema URIs and content type
//! - [`resource`]: SCIM User resource type and Auths extension
//! - [`list`]: SCIM ListResponse container
//! - [`schema`]: SCIM discovery response types
//! - [`error`]: SCIM protocol error types (RFC 7644 Section 3.12)
//! - [`filter`]: SCIM filter parser (nom-based)
//! - [`patch`]: SCIM PATCH operation types and application
//! - [`mapping`]: SCIM-to-Auths field mapping and DTOs

pub mod constants;
pub mod error;
pub mod filter;
pub mod list;
pub mod mapping;
pub mod patch;
pub mod resource;
pub mod schema;

pub use constants::*;
pub use error::{ScimError, ScimErrorResponse};
pub use filter::{CompareOp, ScimFilter, parse_filter};
pub use list::ScimListResponse;
pub use mapping::{
    DeactivateAgentRequest, ProvisionAgentRequest, ProvisionAgentResult, RevokeAgentRequest,
    UpdateAgentFields, provision_result_to_scim_user, scim_user_to_provision_request,
    scim_user_to_update_fields,
};
pub use patch::{PatchOpType, PatchOperation, ScimPatchOp, apply_patch_operations};
pub use resource::{AuthsAgentExtension, ScimMeta, ScimUser};
pub use schema::{
    AuthenticationScheme, FilterSupported, ResourceType, SchemaAttribute, SchemaDefinition,
    SchemaExtension, ServiceProviderConfig, Supported,
};
