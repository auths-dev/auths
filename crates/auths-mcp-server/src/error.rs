//! Error types for the MCP server.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// MCP server error type.
#[derive(Debug, Error)]
pub enum McpServerError {
    /// JWT is missing or malformed.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// JWT is valid but lacks required capabilities for the requested tool.
    #[error(
        "insufficient capabilities: tool '{tool}' requires '{required}', agent has {granted:?}"
    )]
    InsufficientCapabilities {
        tool: String,
        required: String,
        granted: Vec<String>,
    },

    /// The requested tool is not registered.
    #[error("unknown tool: {0}")]
    UnknownTool(String),

    /// JWKS fetch or parse failure.
    #[error("JWKS error: {0}")]
    JwksError(String),

    /// JWT decode or validation failure.
    #[error("token invalid: {0}")]
    TokenInvalid(String),

    /// Tool execution failed.
    #[error("tool error: {0}")]
    ToolError(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl McpServerError {
    /// The AUTHS-E code for this failure, reusing the taxonomy's existing codes so
    /// the gateway's headline surface is lookupable via `auths error show` — the
    /// same "insufficient capabilities" failure carries the same code everywhere.
    pub fn auths_code(&self) -> &'static str {
        match self {
            Self::InsufficientCapabilities { .. } => "AUTHS-E5504",
            Self::Unauthorized(_) | Self::TokenInvalid(_) => "AUTHS-E5501",
            Self::JwksError(_) => "AUTHS-E5502",
            Self::UnknownTool(_) => "AUTHS-E5505",
            Self::ToolError(_) | Self::Internal(_) => "AUTHS-E5599",
        }
    }

    /// The actionable next step for this failure, mirroring the CLI contract.
    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InsufficientCapabilities { .. } => Some(
                "The agent's grant does not cover this tool. Widen its scope via `auths id agent add`/policy, or call a tool within scope.",
            ),
            Self::Unauthorized(_) | Self::TokenInvalid(_) => {
                Some("Attach a valid agent passport (Authorization: Bearer <jwt>).")
            }
            _ => None,
        }
    }
}

/// Error response body. Carries both the HTTP string code and the AUTHS-E code so
/// the wire body matches the CLI JSON contract (code + suggestion + offline lookup).
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    pub auths_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup: Option<String>,
}

impl IntoResponse for McpServerError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            McpServerError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            McpServerError::InsufficientCapabilities { .. } => {
                (StatusCode::FORBIDDEN, "INSUFFICIENT_CAPABILITIES")
            }
            McpServerError::UnknownTool(_) => (StatusCode::NOT_FOUND, "UNKNOWN_TOOL"),
            McpServerError::JwksError(_) => (StatusCode::BAD_GATEWAY, "JWKS_ERROR"),
            McpServerError::TokenInvalid(_) => (StatusCode::UNAUTHORIZED, "TOKEN_INVALID"),
            McpServerError::ToolError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "TOOL_ERROR"),
            McpServerError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        };

        let auths_code = self.auths_code();
        let body = ErrorResponse {
            error: self.to_string(),
            code: code.to_string(),
            auths_code: auths_code.to_string(),
            suggestion: self.suggestion().map(|s| s.to_string()),
            lookup: Some(format!("auths error show {auths_code}")),
        };

        let mut response = (status, Json(body)).into_response();

        if matches!(
            self,
            McpServerError::Unauthorized(_) | McpServerError::TokenInvalid(_)
        ) && let Ok(value) = axum::http::HeaderValue::from_str("Bearer")
        {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, value);
        }

        response
    }
}

/// Result type alias for MCP server operations.
pub type McpServerResult<T> = Result<T, McpServerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_capabilities_carries_auths_e5504() {
        // The gateway's headline denial must carry the same AUTHS-E code the SDK and
        // verifier use for "insufficient capabilities", plus a suggestion and the
        // offline lookup — so the wire body matches the CLI JSON contract.
        let err = McpServerError::InsufficientCapabilities {
            tool: "deploy".into(),
            required: "deploy:prod".into(),
            granted: vec!["read".into()],
        };
        assert_eq!(err.auths_code(), "AUTHS-E5504");
        let body = ErrorResponse {
            error: err.to_string(),
            code: "INSUFFICIENT_CAPABILITIES".into(),
            auths_code: err.auths_code().to_string(),
            suggestion: err.suggestion().map(|s| s.to_string()),
            lookup: Some(format!("auths error show {}", err.auths_code())),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["auths_code"], "AUTHS-E5504");
        assert!(json["suggestion"].is_string());
        assert!(
            json["lookup"]
                .as_str()
                .unwrap()
                .contains("auths error show")
        );
    }

    #[test]
    fn auth_failures_map_into_the_auth_range() {
        assert_eq!(
            McpServerError::Unauthorized("no token".into()).auths_code(),
            "AUTHS-E5501"
        );
        assert_eq!(
            McpServerError::TokenInvalid("bad jwt".into()).auths_code(),
            "AUTHS-E5501"
        );
        assert!(
            McpServerError::Unauthorized("x".into())
                .suggestion()
                .is_some()
        );
    }
}
