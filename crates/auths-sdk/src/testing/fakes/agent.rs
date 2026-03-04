use std::sync::{Arc, Mutex};

use crate::ports::agent::{AgentSigningError, AgentSigningPort};

/// Recorded call from [`FakeAgentProvider`].
#[derive(Debug, Clone)]
pub enum AgentCall {
    TrySign {
        namespace: String,
        pubkey: Vec<u8>,
        data: Vec<u8>,
    },
    EnsureRunning,
    AddIdentity {
        namespace: String,
        pkcs8_der: Vec<u8>,
    },
}

#[derive(Clone)]
enum FakeSignResult {
    Ok(String),
    Unavailable(String),
    ConnectionFailed(String),
    SigningFailed(String),
    StartupFailed(String),
}

impl FakeSignResult {
    fn from_error(err: &AgentSigningError) -> Self {
        match err {
            AgentSigningError::Unavailable(msg) => Self::Unavailable(msg.clone()),
            AgentSigningError::ConnectionFailed(msg) => Self::ConnectionFailed(msg.clone()),
            AgentSigningError::SigningFailed(msg) => Self::SigningFailed(msg.clone()),
            AgentSigningError::StartupFailed(msg) => Self::StartupFailed(msg.clone()),
        }
    }

    fn to_sign_result(&self) -> Result<String, AgentSigningError> {
        match self {
            Self::Ok(pem) => Ok(pem.clone()),
            Self::Unavailable(msg) => Err(AgentSigningError::Unavailable(msg.clone())),
            Self::ConnectionFailed(msg) => Err(AgentSigningError::ConnectionFailed(msg.clone())),
            Self::SigningFailed(msg) => Err(AgentSigningError::SigningFailed(msg.clone())),
            Self::StartupFailed(msg) => Err(AgentSigningError::StartupFailed(msg.clone())),
        }
    }
}

/// Configurable fake for [`AgentSigningPort`].
///
/// Returns canned responses and records all calls for assertion.
///
/// Usage:
/// ```ignore
/// let fake = FakeAgentProvider::unavailable();
/// let fake = FakeAgentProvider::signing_with("SSHSIG PEM...");
/// assert_eq!(fake.calls().len(), 1);
/// ```
pub struct FakeAgentProvider {
    sign_result: Mutex<FakeSignResult>,
    calls: Arc<Mutex<Vec<AgentCall>>>,
}

impl FakeAgentProvider {
    /// Create a fake where all methods return [`AgentSigningError::Unavailable`].
    pub fn unavailable() -> Self {
        Self {
            sign_result: Mutex::new(FakeSignResult::Unavailable(
                "agent not supported on this platform".into(),
            )),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a fake that returns the given PEM string from `try_sign`.
    pub fn signing_with(pem: impl Into<String>) -> Self {
        Self {
            sign_result: Mutex::new(FakeSignResult::Ok(pem.into())),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a fake that returns a specific error from `try_sign`.
    pub fn sign_fails_with(err: AgentSigningError) -> Self {
        Self {
            sign_result: Mutex::new(FakeSignResult::from_error(&err)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return all recorded calls.
    pub fn calls(&self) -> Vec<AgentCall> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl AgentSigningPort for FakeAgentProvider {
    fn try_sign(
        &self,
        namespace: &str,
        pubkey: &[u8],
        data: &[u8],
    ) -> Result<String, AgentSigningError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(AgentCall::TrySign {
                namespace: namespace.to_string(),
                pubkey: pubkey.to_vec(),
                data: data.to_vec(),
            });

        self.sign_result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .to_sign_result()
    }

    fn ensure_running(&self) -> Result<(), AgentSigningError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(AgentCall::EnsureRunning);

        // Best-effort — return Ok unless the fake is configured as unavailable
        match &*self.sign_result.lock().unwrap_or_else(|e| e.into_inner()) {
            FakeSignResult::Unavailable(msg) => Err(AgentSigningError::Unavailable(msg.clone())),
            _ => Ok(()),
        }
    }

    fn add_identity(&self, namespace: &str, pkcs8_der: &[u8]) -> Result<(), AgentSigningError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(AgentCall::AddIdentity {
                namespace: namespace.to_string(),
                pkcs8_der: pkcs8_der.to_vec(),
            });

        match &*self.sign_result.lock().unwrap_or_else(|e| e.into_inner()) {
            FakeSignResult::Unavailable(msg) => Err(AgentSigningError::Unavailable(msg.clone())),
            _ => Ok(()),
        }
    }
}
