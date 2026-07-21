//! Party key resolution for the anchor role.
//!
//! A witness verifies an anchor's party signature under the controller's
//! CURRENT keys, resolved from the party's public identity registry — never
//! under a key the request carries about itself. Resolution reads the node's
//! local registry repo in two layers:
//!
//! 1. **Per-prefix KEL refs** (`refs/auths/kel/<s1>/<prefix>`) — the store the
//!    write path populates when this witness receipts a member's events, and
//!    what `sync-registry` replicates from peer witnesses.
//! 2. **The aggregated tree** (`refs/auths/registry`) — the packed registry an
//!    operator may have synced from a first-party source.
//!
//! Resolution requires the agent to be a delegated identity whose delegator is
//! the claimed root, mirroring the attestation verifier's rule. Since the
//! write path landed, an *empty but openable* registry is a valid state — the
//! store self-populates as members publish — so readiness means "openable",
//! not "already populated".

use std::path::Path;

use auths_anchor::ControllerKeys;
use auths_id::keri::state::KeyState;
use auths_keri::Prefix;
use auths_sdk::ports::{RegistryBackend, RegistryError};
use auths_sdk::storage::{GitRegistryBackend, PerPrefixKelStore, RegistryConfig};

/// A failure resolving the submitting party's current keys.
#[derive(Debug, thiserror::Error)]
pub enum PartyResolveError {
    /// The identifier did not parse as a KERI prefix.
    #[error("party identifier: {0}")]
    BadIdentifier(String),
    /// The witness has no openable registry at all — no submitter can be
    /// resolved. This is the operator's action: create or sync the registry.
    #[error(
        "this witness has no openable registry — the operator must initialize or sync \
         the parties' public registry before anchoring is possible"
    )]
    RegistryUnavailable,
    /// The registry is present but does not contain this submitter yet — the
    /// member publishes its KEL to this witness (or the operator syncs it).
    #[error(
        "your identity is not in this witness's registry yet — publish your KEL to this \
         witness (or have the operator sync it) before you can anchor"
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

/// Classify a failure from the per-prefix layer.
///
/// A missing repository is the operator's problem; a missing identity falls
/// through to the aggregated layer. Classification is structural — on the
/// `RegistryError` variant — so no libgit2 string ever leaks to a submitter.
fn classify_per_prefix_error(e: RegistryError) -> PartyResolveError {
    match &e {
        RegistryError::NotFound { entity_type, .. } if entity_type == "repository" => {
            PartyResolveError::RegistryUnavailable
        }
        RegistryError::NotFound { .. } => PartyResolveError::IdentityNotInRegistry,
        RegistryError::Storage(_) | RegistryError::Io(_) => PartyResolveError::RegistryUnavailable,
        _ => PartyResolveError::Registry(e.to_string()),
    }
}

/// Classify a failure from the aggregated-tree layer.
///
/// Any clean absence — the identity, or the aggregated ref itself — means the
/// member simply isn't held here yet (the write path populates the per-prefix
/// namespace without ever creating `refs/auths/registry`). Storage/IO faults
/// stay the operator's problem.
fn classify_aggregated_error(e: RegistryError) -> PartyResolveError {
    match &e {
        RegistryError::NotFound { .. } => PartyResolveError::IdentityNotInRegistry,
        RegistryError::Storage(_) | RegistryError::Io(_) => PartyResolveError::RegistryUnavailable,
        _ => PartyResolveError::Registry(e.to_string()),
    }
}

/// Resolve a prefix's validated key state from the node's registry: the
/// per-prefix KEL refs first, then the aggregated tree.
///
/// Args:
/// * `registry`: path to the local registry repo.
/// * `prefix`: the identity to resolve.
///
/// Usage:
/// ```ignore
/// let state = resolve_party_key_state(&registry_dir, &prefix)?;
/// ```
pub fn resolve_party_key_state(
    registry: &Path,
    prefix: &Prefix,
) -> Result<KeyState, PartyResolveError> {
    let per_prefix = PerPrefixKelStore::open(registry);
    match per_prefix.get_key_state(prefix) {
        Ok(state) => return Ok(state),
        Err(RegistryError::NotFound { entity_type, .. }) if entity_type != "repository" => {}
        Err(e) => return Err(classify_per_prefix_error(e)),
    }
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry));
    backend
        .get_key_state(prefix)
        .map_err(classify_aggregated_error)
}

/// Confirm the anchor role has a registry it can resolve against before the
/// node binds. Since the write path landed, the registry self-populates as
/// members publish — so an *empty but openable* repo is ready; only a missing
/// repo or a storage fault refuses the role. The probe resolves a
/// syntactically valid sentinel and treats a clean "no such identity" as
/// ready.
///
/// Args:
/// * `registry`: path to the local copy of the parties' public registry.
///
/// Usage:
/// ```ignore
/// registry_ready(&args.registry)?; // refuse to bind only if the repo is unopenable
/// ```
pub fn registry_ready(registry: &Path) -> Result<(), PartyResolveError> {
    if !registry.exists() {
        return Err(PartyResolveError::RegistryUnavailable);
    }
    let sentinel = Prefix::new("EReadinessProbe0000000000000000000000000000".to_string())
        .map_err(|e| PartyResolveError::BadIdentifier(e.to_string()))?;
    match resolve_party_key_state(registry, &sentinel) {
        Ok(_) => Ok(()),
        Err(PartyResolveError::IdentityNotInRegistry) => Ok(()),
        Err(e) => Err(e),
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
    let agent_tail = agent.strip_prefix("did:keri:").unwrap_or(agent);
    let prefix = Prefix::new(agent_tail.to_string())
        .map_err(|e| PartyResolveError::BadIdentifier(e.to_string()))?;
    let state = resolve_party_key_state(registry, &prefix)?;

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
