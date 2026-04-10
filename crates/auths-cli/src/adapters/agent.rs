//! CLI adapter for agent-based signing operations.
//!
//! Wraps the Unix-only agent client from `auths-core` behind the
//! `AgentSigningPort` trait, producing SSHSIG PEM output compatible
//! with `sign_with_seed()`.

#[cfg(unix)]
use auths_sdk::agent_core::{AgentStatus, add_identity, agent_sign, check_agent_status};
#[cfg(unix)]
use auths_sdk::crypto::{construct_sshsig_pem, construct_sshsig_signed_data};
use auths_sdk::ports::agent::{AgentSigningError, AgentSigningPort};

#[cfg(unix)]
use crate::commands::agent::{ensure_agent_running, get_default_socket_path};

/// CLI adapter that delegates signing to the Unix SSH agent.
///
/// On non-Unix platforms this struct is not compiled; the CLI wires
/// `NoopAgentProvider` instead.
///
/// Usage:
/// ```ignore
/// let adapter = CliAgentAdapter;
/// let pem = adapter.try_sign("git", &pubkey, &data)?;
/// ```
#[cfg(unix)]
pub struct CliAgentAdapter;

#[cfg(unix)]
impl AgentSigningPort for CliAgentAdapter {
    fn try_sign(
        &self,
        namespace: &str,
        pubkey: &auths_verifier::DevicePublicKey,
        data: &[u8],
    ) -> Result<String, AgentSigningError> {
        let socket_path =
            get_default_socket_path().map_err(|e| AgentSigningError::Unavailable(e.to_string()))?;

        match check_agent_status(&socket_path) {
            AgentStatus::Running { key_count } if key_count > 0 => {}
            AgentStatus::Running { .. } => {
                return Err(AgentSigningError::Unavailable(
                    "agent running but no keys loaded".into(),
                ));
            }
            AgentStatus::ConnectionFailed => {
                return Err(AgentSigningError::ConnectionFailed(
                    "agent socket unreachable".into(),
                ));
            }
            AgentStatus::NotRunning => {
                return Err(AgentSigningError::Unavailable("agent not running".into()));
            }
        }

        let sig_data = construct_sshsig_signed_data(data, namespace)
            .map_err(|e| AgentSigningError::SigningFailed(e.to_string()))?;

        let raw_sig = agent_sign(&socket_path, pubkey.as_bytes(), &sig_data)
            .map_err(|e| AgentSigningError::SigningFailed(e.to_string()))?;

        construct_sshsig_pem(pubkey.as_bytes(), &raw_sig, namespace, pubkey.curve())
            .map_err(|e| AgentSigningError::SigningFailed(e.to_string()))
    }

    fn ensure_running(&self) -> Result<(), AgentSigningError> {
        ensure_agent_running(true)
            .map(|_| ())
            .map_err(|e| AgentSigningError::StartupFailed(e.to_string()))
    }

    fn add_identity(&self, _namespace: &str, pkcs8_der: &[u8]) -> Result<(), AgentSigningError> {
        let socket_path = get_default_socket_path()
            .map_err(|e| AgentSigningError::ConnectionFailed(e.to_string()))?;

        add_identity(&socket_path, pkcs8_der)
            .map(|_| ())
            .map_err(|e| AgentSigningError::SigningFailed(e.to_string()))
    }
}
