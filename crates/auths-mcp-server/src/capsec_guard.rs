use auths_sdk::domains::agent_guard::error::AgentGuardError;
use capsec::runtime::{RuntimeCap, TimedCap};
use std::time::Duration;

/// Holds runtime capability bounds for an active MCP agent tool execution session.
pub struct McpCapsecGuard {
    /// Agent identity DID string backing this session
    pub agent_did: String,
    /// Time-bounded validity token enforcing --ttl
    pub timed_cap: TimedCap,
    /// Revocable capability token for instant remote kill switch
    pub runtime_cap: RuntimeCap,
}

impl McpCapsecGuard {
    /// Create a new capability guard for an MCP tool invocation.
    ///
    /// Args:
    /// * `agent_did`: Canonical DID string of the agent.
    /// * `ttl`: Duration representing the time-to-live for tool execution.
    ///
    /// Usage:
    /// ```ignore
    /// let guard = McpCapsecGuard::new("did:key:z1", Duration::from_secs(1800))?;
    /// ```
    pub fn new(agent_did: String, ttl: Duration) -> Result<Self, AgentGuardError> {
        let timed_cap = TimedCap::new(ttl)
            .map_err(|e| AgentGuardError::CapsecViolation(e.to_string()))?;
        let runtime_cap = RuntimeCap::new()
            .map_err(|e| AgentGuardError::CapsecViolation(e.to_string()))?;
        Ok(Self {
            agent_did,
            timed_cap,
            runtime_cap,
        })
    }

    /// Check if the capability guard is still valid before forwarding tool call.
    ///
    /// Usage:
    /// ```ignore
    /// guard.validate_execution()?;
    /// ```
    pub fn validate_execution(&self) -> Result<(), AgentGuardError> {
        self.timed_cap
            .check_valid()
            .map_err(|e| AgentGuardError::CapsecViolation(e.to_string()))?;
        self.runtime_cap
            .check_valid()
            .map_err(|e| AgentGuardError::CapsecViolation(e.to_string()))?;
        Ok(())
    }
}
