use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from trust policy resolution during verification.
///
/// Usage:
/// ```ignore
/// match resolve_issuer_key(did, policy) {
///     Err(TrustError::UnknownIdentity { did, policy }) => {
///         eprintln!("Unknown identity under {} policy; run `auths trust add {}`", policy, did)
///     }
///     Err(e) => return Err(e.into()),
///     Ok(key) => { /* use key for verification */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrustError {
    /// Identity is unknown and trust policy does not permit TOFU/resolution.
    #[error("Unknown identity '{did}' and trust policy is '{policy}'")]
    UnknownIdentity {
        /// The unknown identity DID.
        did: String,
        /// The policy preventing resolution (e.g., "explicit").
        policy: String,
    },

    /// Identity exists but no public key could be resolved.
    #[error("Failed to resolve public key for identity {did}")]
    KeyResolutionFailed {
        /// The DID whose key could not be resolved.
        did: String,
    },

    /// The provided roots.json or trust store is invalid.
    #[error("Invalid trust store: {0}")]
    InvalidTrustStore(String),

    /// TOFU prompt was required but execution is non-interactive.
    #[error("TOFU trust decision required but running in non-interactive mode")]
    TofuRequiresInteraction,
}

/// Errors from MCP token exchange operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(McpAuthError::BridgeUnreachable(msg)) => { /* retry later */ }
///     Err(McpAuthError::InsufficientCapabilities { .. }) => { /* request fewer caps */ }
///     Err(e) => return Err(e.into()),
///     Ok(token) => { /* use token */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpAuthError {
    /// The OIDC bridge is unreachable.
    #[error("bridge unreachable: {0}")]
    BridgeUnreachable(String),

    /// The bridge returned a non-success status.
    #[error("token exchange failed (HTTP {status}): {body}")]
    TokenExchangeFailed {
        /// HTTP status code from the bridge.
        status: u16,
        /// Response body.
        body: String,
    },

    /// The bridge response could not be parsed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The bridge rejected the requested capabilities.
    #[error("insufficient capabilities: requested {requested:?}")]
    InsufficientCapabilities {
        /// The capabilities that were requested.
        requested: Vec<String>,
        /// Detail from the bridge error response.
        detail: String,
    },
}

impl AuthsErrorInfo for TrustError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::UnknownIdentity { .. } => "AUTHS-E5551",
            Self::KeyResolutionFailed { .. } => "AUTHS-E5552",
            Self::InvalidTrustStore(_) => "AUTHS-E5553",
            Self::TofuRequiresInteraction => "AUTHS-E5554",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::UnknownIdentity { .. } => {
                Some("Run `auths trust add <did>` or add the identity to .auths/roots.json")
            }
            Self::KeyResolutionFailed { .. } => {
                Some("Verify the identity exists and has a valid public key registered")
            }
            Self::InvalidTrustStore(_) => Some(
                "Check the format of your trust store (roots.json or ~/.auths/known_identities.json)",
            ),
            Self::TofuRequiresInteraction => {
                Some("Run interactively (on a TTY) or use `auths verify --trust explicit`")
            }
        }
    }
}

impl AuthsErrorInfo for McpAuthError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::BridgeUnreachable(_) => "AUTHS-E5501",
            Self::TokenExchangeFailed { .. } => "AUTHS-E5502",
            Self::InvalidResponse(_) => "AUTHS-E5503",
            Self::InsufficientCapabilities { .. } => "AUTHS-E5504",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::BridgeUnreachable(_) => Some("Check network connectivity to the OIDC bridge"),
            Self::TokenExchangeFailed { .. } => Some("Verify your credentials and try again"),
            Self::InvalidResponse(_) => Some(
                "The OIDC bridge returned an unexpected response; verify the bridge URL and try again",
            ),
            Self::InsufficientCapabilities { .. } => {
                Some("Request fewer capabilities or contact your administrator")
            }
        }
    }
}
