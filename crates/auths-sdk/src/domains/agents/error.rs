use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from agent delegation operations (`agents::add` and friends).
///
/// An agent is a KERI `dip`-delegated identifier of a root/org identity — the same
/// engine devices use. These errors mirror the device delegation surface.
///
/// Usage:
/// ```ignore
/// match agents::add(&ctx, &root_alias, &agent_alias, curve) {
///     Err(AgentError::AlreadyDelegated { alias }) => { /* key in use */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* agent did:keri */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The delegating (root/org) identity could not be found in storage.
    #[error("identity not found: {did}")]
    IdentityNotFound {
        /// The DID (or load context) that was not found.
        did: String,
    },

    /// A key already exists under the requested agent alias — re-delegating it
    /// would clobber an existing agent. Choose a fresh `--label`/alias.
    #[error("an agent key already exists under alias '{alias}'")]
    AlreadyDelegated {
        /// The keychain alias already in use.
        alias: String,
    },

    /// No agent delegated by this root matches the given DID (or its key is
    /// missing from the keychain).
    #[error("agent not found: {did}")]
    AgentNotFound {
        /// The agent DID that could not be resolved.
        did: String,
    },

    /// The agent has been revoked by the delegator and cannot be rotated.
    #[error("agent {did} is revoked")]
    Revoked {
        /// The revoked agent's DID.
        did: String,
    },

    /// The requested agent scope exceeds the delegator's own scope — a delegate's
    /// authority can only narrow, never widen (subset rule).
    #[error("requested capability '{capability}' exceeds the delegator's scope")]
    OutsideDelegatorScope {
        /// The capability that the delegator does not itself hold.
        capability: String,
    },

    /// A cryptographic operation failed (e.g. resolving the root's curve).
    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    /// Authoring or anchoring the delegated agent identifier failed.
    #[error("agent delegation failed: {0}")]
    DelegationError(#[source] auths_id::error::InitError),
}

impl From<auths_core::AgentError> for AgentError {
    fn from(err: auths_core::AgentError) -> Self {
        AgentError::CryptoError(err)
    }
}

impl AuthsErrorInfo for AgentError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound { .. } => "AUTHS-E5311",
            Self::AlreadyDelegated { .. } => "AUTHS-E5312",
            Self::CryptoError(e) => e.error_code(),
            Self::DelegationError(_) => "AUTHS-E5313",
            Self::AgentNotFound { .. } => "AUTHS-E5314",
            Self::Revoked { .. } => "AUTHS-E5315",
            Self::OutsideDelegatorScope { .. } => "AUTHS-E5316",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound { .. } => {
                Some("Run `auths init` to create a root identity first")
            }
            Self::AlreadyDelegated { .. } => {
                Some("Choose a different --label; run `auths id agent list` to see existing agents")
            }
            Self::CryptoError(e) => e.suggestion(),
            Self::DelegationError(_) => Some(
                "The agent delegation could not be authored or anchored; check the root identity",
            ),
            Self::AgentNotFound { .. } => {
                Some("Run `auths id agent list` to see the agents this identity has delegated")
            }
            Self::Revoked { .. } => {
                Some("This agent was revoked and cannot be rotated; delegate a new agent instead")
            }
            Self::OutsideDelegatorScope { .. } => {
                Some("Narrow the agent's --scope to a subset of the delegator's own capabilities")
            }
        }
    }
}
