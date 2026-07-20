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
use auths_sdk::ports::{RegistryBackend, RegistryError};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

/// A failure resolving the submitting party's current keys.
#[derive(Debug, thiserror::Error)]
pub enum PartyResolveError {
    /// The identifier did not parse as a KERI prefix.
    #[error("party identifier: {0}")]
    BadIdentifier(String),
    /// The witness has no synced registry at all — no submitter can be resolved.
    /// This is the operator's action: sync the registry before anchoring.
    #[error(
        "this witness has no synced registry — the operator must sync the parties' \
         public registry before anchoring is possible"
    )]
    RegistryUnavailable,
    /// The registry is present but does not contain this submitter yet — the
    /// operator must sync it before this party can anchor.
    #[error(
        "your identity is not in this witness's registry yet — the operator must sync \
         it before you can anchor"
    )]
    IdentityNotInRegistry,
    /// A registry lookup failed in a way that is neither a clean absence nor a
    /// missing repo (kept as a residual so nothing is silently reclassified).
    #[error("registry lookup failed: {0}")]
    Registry(String),
    /// The agent is not delegated, or is delegated by someone other than the
    /// claimed root.
    #[error("delegation: {0}")]
    Delegation(String),
    /// The resolved key material did not parse.
    #[error("key material: {0}")]
    Keys(String),
}

/// Classify a registry lookup failure into the one action that fixes it.
///
/// A missing identity in a real registry is the *stranger's* concern (sync your
/// entry); a repo that will not open, or a storage/IO fault, is the *operator's*
/// (sync your registry). Classification is structural — on the `RegistryError`
/// variant — so no libgit2 string ever leaks to a submitter.
fn classify_registry_error(e: RegistryError) -> PartyResolveError {
    match &e {
        RegistryError::NotFound { entity_type, .. } if entity_type == "identity" => {
            PartyResolveError::IdentityNotInRegistry
        }
        RegistryError::NotFound { .. } | RegistryError::Storage(_) | RegistryError::Io(_) => {
            PartyResolveError::RegistryUnavailable
        }
        _ => PartyResolveError::Registry(e.to_string()),
    }
}

/// Confirm the anchor role has a registry it can actually resolve against,
/// before the node binds. A mounted-but-empty volume *exists* yet resolves
/// nothing — exactly how a node boots healthy and then refuses every submission
/// — so `exists()` is not enough: probe a syntactically valid sentinel and treat
/// anything but a clean "no such identity" as not ready.
///
/// Args:
/// * `registry`: path to the local copy of the parties' public registry.
///
/// Usage:
/// ```ignore
/// registry_ready(&args.registry)?; // refuse to bind if the registry is unsynced
/// ```
pub fn registry_ready(registry: &Path) -> Result<(), PartyResolveError> {
    if !registry.exists() {
        return Err(PartyResolveError::RegistryUnavailable);
    }
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry));
    let sentinel = Prefix::new("EReadinessProbe0000000000000000000000000000".to_string())
        .map_err(|e| PartyResolveError::BadIdentifier(e.to_string()))?;
    match backend.get_key_state(&sentinel) {
        Ok(_) => Ok(()),
        Err(RegistryError::NotFound { entity_type, .. }) if entity_type == "identity" => Ok(()),
        Err(_) => Err(PartyResolveError::RegistryUnavailable),
    }
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
        .map_err(classify_registry_error)?;

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
