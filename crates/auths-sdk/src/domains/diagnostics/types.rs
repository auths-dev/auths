use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use serde::{Deserialize, Serialize};

/// Identity status for status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStatus {
    /// The controller DID.
    pub controller_did: IdentityDID,
    /// Key aliases available in keychain.
    pub key_aliases: Vec<KeyAlias>,
}

/// Agent status for status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    /// Whether the agent is currently running.
    pub running: bool,
    /// Process ID if running.
    pub pid: Option<u32>,
    /// Socket path if running.
    pub socket_path: Option<String>,
}

/// Next step recommendation for users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextStep {
    /// Summary of what to do.
    pub summary: String,
    /// Command to run.
    pub command: String,
}

/// Full status report combining identity, devices, and agent state.
///
/// Usage:
/// ```ignore
/// let report = StatusWorkflow::query(&ctx, now)?;
/// println!("Identity: {}", report.identity.controller_did);
/// println!("Devices: {} linked", report.devices.len());
/// for step in report.next_steps {
///     println!("Try: {}", step.command);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// Current identity status, if initialized.
    pub identity: Option<IdentityStatus>,
    /// Per-device authorization status.
    pub devices: Vec<crate::domains::device::types::DeviceStatus>,
    /// Agent/SSH-agent status.
    pub agent: AgentStatus,
    /// Suggested next steps for the user.
    pub next_steps: Vec<NextStep>,
}
