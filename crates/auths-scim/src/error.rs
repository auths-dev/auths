//! SCIM protocol error types (RFC 7644 Section 3.12).

use serde::{Deserialize, Serialize};

use crate::constants::SCHEMA_ERROR;

/// SCIM protocol error (typed, no anyhow).
#[derive(Debug, thiserror::Error)]
pub enum ScimError {
    #[error("Resource not found: {id}")]
    NotFound { id: String },

    #[error("Resource already exists: {external_id}")]
    Conflict { external_id: String },

    #[error("Invalid value: {message}")]
    InvalidValue { message: String },

    #[error("Immutable attribute: {attribute}")]
    Mutability { attribute: String },

    #[error("Invalid filter: {message}")]
    InvalidFilter { message: String },

    #[error("Invalid PATCH operation: {message}")]
    InvalidPatch { message: String },

    #[error("Missing required attribute: {attribute}")]
    MissingAttribute { attribute: String },

    #[error("Invalid schema: {message}")]
    InvalidSchema { message: String },

    #[error("Precondition failed: ETag mismatch")]
    PreconditionFailed,

    #[error("Too many results: max {max}")]
    TooMany { max: u64 },

    #[error("Unauthorized: {message}")]
    Unauthorized { message: String },

    #[error("Forbidden: {message}")]
    Forbidden { message: String },

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Capability not allowed: {capability}")]
    CapabilityNotAllowed { capability: String },
}

/// SCIM error response body per RFC 7644 Section 3.12.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorResponse {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
}

impl ScimError {
    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotFound { .. } => 404,
            Self::Conflict { .. } => 409,
            Self::InvalidValue { .. }
            | Self::InvalidFilter { .. }
            | Self::InvalidPatch { .. }
            | Self::MissingAttribute { .. }
            | Self::InvalidSchema { .. } => 400,
            Self::Mutability { .. } => 400,
            Self::PreconditionFailed => 412,
            Self::TooMany { .. } => 400,
            Self::Unauthorized { .. } => 401,
            Self::Forbidden { .. } | Self::CapabilityNotAllowed { .. } => 403,
            Self::RateLimited => 429,
            Self::Internal { .. } => 500,
        }
    }

    /// SCIM error type string per RFC 7644 Section 3.12.
    pub fn scim_type(&self) -> Option<&str> {
        match self {
            Self::Mutability { .. } => Some("mutability"),
            Self::PreconditionFailed => Some("mutability"),
            Self::Conflict { .. } => Some("uniqueness"),
            Self::InvalidFilter { .. } => Some("invalidFilter"),
            Self::InvalidValue { .. } => Some("invalidValue"),
            Self::TooMany { .. } => Some("tooMany"),
            Self::InvalidPatch { .. } => Some("invalidSyntax"),
            Self::MissingAttribute { .. } => Some("invalidValue"),
            _ => None,
        }
    }

    /// Convert to SCIM error response body.
    pub fn to_response(&self) -> ScimErrorResponse {
        ScimErrorResponse {
            schemas: vec![SCHEMA_ERROR.into()],
            status: self.status_code().to_string(),
            scim_type: self.scim_type().map(String::from),
            detail: self.to_string(),
            docs: Some(format!(
                "https://docs.auths.dev/scim/errors#{}",
                self.error_slug()
            )),
        }
    }

    fn error_slug(&self) -> &str {
        match self {
            Self::NotFound { .. } => "not-found",
            Self::Conflict { .. } => "conflict",
            Self::InvalidValue { .. } => "invalid-value",
            Self::Mutability { .. } => "mutability",
            Self::InvalidFilter { .. } => "invalid-filter",
            Self::InvalidPatch { .. } => "invalid-patch",
            Self::MissingAttribute { .. } => "missing-attribute",
            Self::InvalidSchema { .. } => "invalid-schema",
            Self::PreconditionFailed => "precondition-failed",
            Self::TooMany { .. } => "too-many",
            Self::Unauthorized { .. } => "unauthorized",
            Self::Forbidden { .. } => "forbidden",
            Self::RateLimited => "rate-limited",
            Self::Internal { .. } => "internal",
            Self::CapabilityNotAllowed { .. } => "capability-not-allowed",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn error_response_roundtrip() {
        let err = ScimError::NotFound {
            id: "abc-123".into(),
        };
        let response = err.to_response();
        let json = serde_json::to_string(&response).unwrap();
        let parsed: ScimErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, "404");
        assert!(parsed.detail.contains("abc-123"));
        assert!(parsed.docs.is_some());
    }

    #[test]
    fn error_status_codes() {
        assert_eq!(ScimError::NotFound { id: "x".into() }.status_code(), 404);
        assert_eq!(
            ScimError::Conflict {
                external_id: "x".into()
            }
            .status_code(),
            409
        );
        assert_eq!(
            ScimError::InvalidValue {
                message: "x".into()
            }
            .status_code(),
            400
        );
        assert_eq!(ScimError::PreconditionFailed.status_code(), 412);
        assert_eq!(
            ScimError::Unauthorized {
                message: "x".into()
            }
            .status_code(),
            401
        );
        assert_eq!(ScimError::RateLimited.status_code(), 429);
        assert_eq!(
            ScimError::Internal {
                message: "x".into()
            }
            .status_code(),
            500
        );
    }
}
