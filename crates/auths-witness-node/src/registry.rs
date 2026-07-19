//! Party key resolution for the anchor role.
//!
//! A witness verifies an anchor's party signature under the controller's
//! CURRENT keys, resolved from the party's public identity registry — never
//! under a key the request carries about itself. The node reads a local copy
//! of the registry (a path the operator syncs); resolution requires the agent
//! to be a delegated identity whose delegator is the claimed root, mirroring
//! the attestation verifier's rule.

use std::path::Path;

use auths_anchor::ControllerKeys;
use auths_keri::Prefix;
use auths_sdk::ports::RegistryBackend;
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

/// A failure resolving the submitting party's current keys.
#[derive(Debug, thiserror::Error)]
pub enum PartyResolveError {
    /// The identifier did not parse as a KERI prefix.
    #[error("party identifier: {0}")]
    BadIdentifier(String),
    /// The registry lookup failed (missing identity, unreadable registry).
    #[error("registry: {0}")]
    Registry(String),
    /// The agent is not delegated, or is delegated by someone other than the
    /// claimed root.
    #[error("delegation: {0}")]
    Delegation(String),
    /// The resolved key material did not parse.
    #[error("key material: {0}")]
    Keys(String),
}

/// Resolve the agent's current keys from a local registry copy, requiring its
/// delegator to be the claimed root.
///
/// Args:
/// * `registry`: path to the local copy of the party's public registry.
/// * `root`: the claimed root (`did:keri:…`).
/// * `agent`: the submitting agent (`did:keri:…`).
///
/// Usage:
/// ```ignore
/// let keys = controller_keys_for_party(&registry_dir, &root_did, &agent_did)?;
/// ```
pub fn controller_keys_for_party(
    registry: &Path,
    root: &str,
    agent: &str,
) -> Result<ControllerKeys, PartyResolveError> {
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry));
    let agent_tail = agent.strip_prefix("did:keri:").unwrap_or(agent);
    let prefix = Prefix::new(agent_tail.to_string())
        .map_err(|e| PartyResolveError::BadIdentifier(e.to_string()))?;
    let state = backend
        .get_key_state(&prefix)
        .map_err(|e| PartyResolveError::Registry(e.to_string()))?;

    let root_tail = root.strip_prefix("did:keri:").unwrap_or(root);
    match &state.delegator {
        Some(delegator) if delegator.as_str() == root_tail => {}
        Some(delegator) => {
            return Err(PartyResolveError::Delegation(format!(
                "agent delegator {} is not the claimed root {root_tail}",
                delegator.as_str()
            )));
        }
        None => {
            return Err(PartyResolveError::Delegation(
                "agent is not a delegated identity — no chain to a root".to_string(),
            ));
        }
    }

    ControllerKeys::from_key_state(&state).map_err(|e| PartyResolveError::Keys(e.to_string()))
}
