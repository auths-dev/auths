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

/// Configurable fake for [`AgentSigningPort`].
///
/// Returns canned responses and records all calls for assertion.
///
/// Usage:
/// ```ignore
/// let fake = FakeAgentProvider::unavailable(); // all methods return Unavailable
/// let fake = FakeAgentProvider::signing_with("SSHSIG PEM...");
/// assert_eq!(fake.calls().len(), 1);
/// ```
pub struct FakeAgentProvider {
    sign_result: Mutex<Option<Result<String, AgentSigningError>>>,
    ensure_result: Mutex<Option<Result<(), AgentSigningError>>>,
    add_identity_result: Mutex<Option<Result<(), AgentSigningError>>>,
    calls: Arc<Mutex<Vec<AgentCall>>>,
}

impl FakeAgentProvider {
    /// Create a fake where all methods return [`AgentSigningError::Unavailable`].
    pub fn unavailable() -> Self {
        Self {
            sign_result: Mutex::new(None),
            ensure_result: Mutex::new(None),
            add_identity_result: Mutex::new(None),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a fake that returns the given PEM string from `try_sign`.
    pub fn signing_with(pem: impl Into<String>) -> Self {
        Self {
            sign_result: Mutex::new(Some(Ok(pem.into()))),
            ensure_result: Mutex::new(Some(Ok(()))),
            add_identity_result: Mutex::new(Some(Ok(()))),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a fake that returns a specific error from `try_sign`.
    pub fn sign_fails_with(err: AgentSigningError) -> Self {
        Self {
            sign_result: Mutex::new(Some(Err(err))),
            ensure_result: Mutex::new(Some(Ok(()))),
            add_identity_result: Mutex::new(Some(Ok(()))),
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

        match &*self.sign_result.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(Ok(pem)) => Ok(pem.clone()),
            Some(Err(_)) => Err(AgentSigningError::SigningFailed(
                "fake signing error".into(),
            )),
            None => Err(AgentSigningError::Unavailable(
                "agent not supported on this platform".into(),
            )),
        }
    }

    fn ensure_running(&self) -> Result<(), AgentSigningError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(AgentCall::EnsureRunning);

        match &*self.ensure_result.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) => Err(AgentSigningError::StartupFailed(
                "fake startup error".into(),
            )),
            None => Err(AgentSigningError::Unavailable(
                "agent not supported on this platform".into(),
            )),
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

        match &*self
            .add_identity_result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) => Err(AgentSigningError::SigningFailed(
                "fake add_identity error".into(),
            )),
            None => Err(AgentSigningError::Unavailable(
                "agent not supported on this platform".into(),
            )),
        }
    }
}
