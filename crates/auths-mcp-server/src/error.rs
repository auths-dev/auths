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

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
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

        let body = ErrorResponse {
            error: self.to_string(),
            code: code.to_string(),
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
