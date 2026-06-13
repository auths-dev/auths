//! Reference MCP tool implementations.
//!
//! These are demonstration tools that showcase Auths-backed authorization.
//! Each tool requires a specific capability in the agent's JWT.
//!
//! File-touching tools execute inside a [`Sandbox`] rooted at a configurable
//! directory ([`McpServerConfig::sandbox_root`](crate::config::McpServerConfig)),
//! so a relying party roots tool execution at its own workspace rather than a
//! pinned location.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::McpServerError;

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

/// A canonicalized directory that file-touching tools are confined to.
///
/// Constructed once from the configured root; the canonical path is parsed at
/// the boundary so every [`resolve`](Sandbox::resolve) downstream can trust it
/// is an existing, absolute directory — no executor re-checks the root.
#[derive(Debug, Clone)]
pub struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    /// Open the sandbox at `root`, resolving symlinks once.
    ///
    /// Args:
    /// * `root`: The directory tool execution is confined to. It must exist.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, McpServerError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|e| McpServerError::Internal(format!("sandbox root not accessible: {e}")))?;
        Ok(Self { root })
    }

    /// The canonical sandbox root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a user-supplied path to a location inside the sandbox.
    ///
    /// Directory traversal is rejected: the resolved path (or its parent, for a
    /// not-yet-existing write target) must lie under the sandbox root.
    ///
    /// Args:
    /// * `user_path`: The caller-supplied path, treated as relative to the root.
    pub fn resolve(&self, user_path: &str) -> Result<PathBuf, McpServerError> {
        let requested = self
            .root
            .join(user_path.trim_start_matches('/').trim_start_matches("tmp/"));

        let canonical = if requested.exists() {
            requested
                .canonicalize()
                .map_err(|e| McpServerError::ToolError(format!("path resolution failed: {e}")))?
        } else {
            // For writes, the file may not exist yet — canonicalize the parent.
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

            if !canonical_parent.starts_with(&self.root) {
                return Err(McpServerError::ToolError(
                    "path escapes sandbox".to_string(),
                ));
            }

            let filename = requested.file_name().ok_or_else(|| {
                McpServerError::ToolError("invalid path: no filename".to_string())
            })?;
            return Ok(canonical_parent.join(filename));
        };

        if !canonical.starts_with(&self.root) {
            return Err(McpServerError::ToolError(
                "path escapes sandbox".to_string(),
            ));
        }

        Ok(canonical)
    }
}

/// Execute the `read_file` tool inside `sandbox`.
///
/// Args:
/// * `sandbox`: The directory tool execution is confined to.
/// * `request`: The file read request containing the path.
pub fn execute_read_file(
    sandbox: &Sandbox,
    request: ReadFileRequest,
) -> Result<ToolResponse, McpServerError> {
    let safe_path = sandbox.resolve(&request.path)?;

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

/// Execute the `write_file` tool inside `sandbox`.
///
/// Args:
/// * `sandbox`: The directory tool execution is confined to.
/// * `request`: The file write request containing path and content.
pub fn execute_write_file(
    sandbox: &Sandbox,
    request: WriteFileRequest,
) -> Result<ToolResponse, McpServerError> {
    let safe_path = sandbox.resolve(&request.path)?;

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
