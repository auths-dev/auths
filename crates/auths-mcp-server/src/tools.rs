//! Reference MCP tool implementations.
//!
//! These are demonstration tools that showcase Auths-backed authorization.
//! Each tool requires a specific capability in the agent's JWT.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::McpServerError;

const SANDBOX_ROOT: &str = "/tmp";

/// Request body for the `read_file` tool.
#[derive(Debug, Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
}

/// Request body for the `write_file` tool.
#[derive(Debug, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    pub content: String,
}

/// Request body for the `deploy` tool.
#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub env: String,
}

/// Response from a tool execution.
#[derive(Debug, Serialize)]
pub struct ToolResponse {
    pub success: bool,
    pub result: serde_json::Value,
}

/// Execute the `read_file` tool.
///
/// Args:
/// * `request`: The file read request containing the path.
pub fn execute_read_file(request: ReadFileRequest) -> Result<ToolResponse, McpServerError> {
    let safe_path = sandbox_path(&request.path)?;

    let content = std::fs::read_to_string(&safe_path)
        .map_err(|e| McpServerError::ToolError(format!("read failed: {e}")))?;

    Ok(ToolResponse {
        success: true,
        result: serde_json::json!({
            "path": request.path,
            "content": content,
            "size": content.len(),
        }),
    })
}

/// Execute the `write_file` tool.
///
/// Args:
/// * `request`: The file write request containing path and content.
pub fn execute_write_file(request: WriteFileRequest) -> Result<ToolResponse, McpServerError> {
    let safe_path = sandbox_path(&request.path)?;

    std::fs::write(&safe_path, &request.content)
        .map_err(|e| McpServerError::ToolError(format!("write failed: {e}")))?;

    Ok(ToolResponse {
        success: true,
        result: serde_json::json!({
            "path": request.path,
            "bytes_written": request.content.len(),
        }),
    })
}

/// Execute the `deploy` tool (mock implementation).
///
/// Args:
/// * `request`: The deploy request containing the target environment.
pub fn execute_deploy(request: DeployRequest) -> Result<ToolResponse, McpServerError> {
    Ok(ToolResponse {
        success: true,
        result: serde_json::json!({
            "env": request.env,
            "status": "deployed",
            "message": format!("Mock deployment to {} completed", request.env),
        }),
    })
}

/// Resolve a path within the sandbox, preventing directory traversal.
fn sandbox_path(user_path: &str) -> Result<PathBuf, McpServerError> {
    let sandbox = Path::new(SANDBOX_ROOT)
        .canonicalize()
        .map_err(|e| McpServerError::Internal(format!("sandbox root not accessible: {e}")))?;

    let requested = sandbox.join(user_path.trim_start_matches('/').trim_start_matches("tmp/"));

    let canonical = if requested.exists() {
        requested
            .canonicalize()
            .map_err(|e| McpServerError::ToolError(format!("path resolution failed: {e}")))?
    } else {
        // For writes, the file may not exist yet — canonicalize the parent
        let parent = requested.parent().ok_or_else(|| {
            McpServerError::ToolError("invalid path: no parent directory".to_string())
        })?;

        if !parent.exists() {
            return Err(McpServerError::ToolError(format!(
                "parent directory does not exist: {}",
                parent.display()
            )));
        }

        let canonical_parent = parent.canonicalize().map_err(|e| {
            McpServerError::ToolError(format!("parent path resolution failed: {e}"))
        })?;

        if !canonical_parent.starts_with(&sandbox) {
            return Err(McpServerError::ToolError(
                "path escapes sandbox".to_string(),
            ));
        }

        if let Some(filename) = requested.file_name() {
            return Ok(canonical_parent.join(filename));
        }

        return Err(McpServerError::ToolError(
            "invalid path: no filename".to_string(),
        ));
    };

    if !canonical.starts_with(&sandbox) {
        return Err(McpServerError::ToolError(
            "path escapes sandbox".to_string(),
        ));
    }

    Ok(canonical)
}
