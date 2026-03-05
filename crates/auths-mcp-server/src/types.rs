//! Shared types for the MCP server.

use serde::Serialize;

/// A verified agent identity extracted from a validated JWT.
///
/// Args:
/// * `did`: The agent's DID (from JWT `sub` claim).
/// * `keri_prefix`: The KERI prefix of the root identity.
/// * `capabilities`: Capabilities granted to the agent.
/// * `delegated_by`: The DID of the delegating identity, if applicable.
///
/// Usage:
/// ```ignore
/// let agent = auth.authorize_tool_call(token, "read_file").await?;
/// println!("Agent DID: {}", agent.did);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedAgent {
    pub did: String,
    pub keri_prefix: String,
    pub capabilities: Vec<String>,
}
