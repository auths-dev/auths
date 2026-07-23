//! Delegated agent workflow — add an AI agent as a KERI delegated identifier.
//!
//! An agent is a KERI delegated AID, identical in mechanism to a delegated device
//! (Model D): its own KEL is incepted with a `dip` delegated by the chosen root, and
//! the root anchors it via an `ixn`. The agent holds its own freshly-generated key;
//! the root only anchors. This is the keripy-native replacement for the deleted
//! bearer-token / standalone-`icp` agent models.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, extract_public_key_bytes};
use auths_id::attestation::create::{AttestationInput, create_signed_attestation};
use auths_id::keri::delegation::{
    BulkAgentSpec, DelegatedRole, incept_delegated_agents_bulk, incept_delegated_device,
    list_delegated_devices, mark_agent_scope, mark_delegated_agent, read_agent_scope,
    revoke_delegated_device, revoke_delegated_devices_batch, rotate_delegated_device,
};
use auths_id::keri::{Event, anchor_and_persist_via_backend, parse_did_keri};
use auths_id::storage::git_refs::AttestationMetadata;
use auths_keri::{AgentScope, Capability};
use auths_verifier::core::SignerType;
use auths_verifier::types::CanonicalDid;

use crate::context::AuthsContext;
use crate::domains::agents::error::AgentError;
use crate::signing::PassphraseProvider;

/// Result of adding a delegated agent.
#[derive(Debug, Clone)]
pub struct AgentDelegationResult {
    /// The new agent's `did:keri:` (self-addressing — derived from its `dip` SAID).
    pub agent_did: String,
    /// The new agent's KEL prefix.
    pub agent_prefix: String,
}

/// Add an agent as a delegated identifier of the current root identity.
///
/// Thin wrapper over the generic delegation engine: it incepts the agent's own KEL
/// (a `dip` delegated by the root) and authors the root's anchoring `ixn` via
/// [`incept_delegated_device`] (the engine is not device-specific). The agent holds
/// its own key; the root only anchors. KERI delegation carries no timestamps, so no
/// clock is needed.
///
/// Re-using an `agent_alias` whose key already exists is rejected
/// ([`AgentError::AlreadyDelegated`]) so an existing agent's key is never clobbered.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, identity storage, passphrase).
/// * `root_alias`: Keychain alias of the delegating root identity's signing key.
/// * `agent_alias`: Keychain alias to store the new agent key under.
/// * `agent_curve`: Curve for the new agent key.
///
/// Usage:
/// ```ignore
/// let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519)?;
/// println!("{}", agent.agent_did);
/// ```
pub fn add(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_alias: &KeyAlias,
    agent_curve: auths_crypto::CurveType,
) -> Result<AgentDelegationResult, AgentError> {
    add_scoped(ctx, root_alias, agent_alias, agent_curve, &[], None)
}

/// Add an agent with a delegator-anchored scope/expiry (Epic E.7).
///
/// Like [`add`], plus the delegator anchors a scope seal carrying `scope`
/// (capabilities) and an optional `expires_at` (Unix epoch seconds) in its **own**
/// `ixn` — authority comes from the delegator, never the agent. The requested scope
/// must be a subset of the delegator's own scope (the delegate can only narrow);
/// re-using an existing alias is rejected.
///
/// Args:
/// * `ctx`: Auths context.
/// * `root_alias`: Keychain alias of the delegating root identity's signing key.
/// * `agent_alias`: Keychain alias to store the new agent key under.
/// * `agent_curve`: Curve for the new agent key.
/// * `scope`: Capabilities granted to the agent (empty = unrestricted).
/// * `expires_at`: Expiry as Unix epoch seconds (`None` = never).
///
/// Usage:
/// ```ignore
/// let agent = add_scoped(&ctx, &root_alias, &agent_alias, curve, &[Capability::sign_commit()], Some(now + 3600))?;
/// ```
pub fn add_scoped(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_alias: &KeyAlias,
    agent_curve: auths_crypto::CurveType,
    scope: &[Capability],
    expires_at: Option<i64>,
) -> Result<AgentDelegationResult, AgentError> {
    // Dedup: never re-delegate over an alias that already holds a key.
    if ctx.key_storage.load_key(agent_alias).is_ok() {
        return Err(AgentError::AlreadyDelegated {
            alias: agent_alias.as_str().to_string(),
        });
    }

    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let (parent_did, _, _) =
        ctx.key_storage
            .load_key(root_alias)
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!(
                    "parent key alias '{}' load failed: {e}",
                    root_alias.as_str()
                ),
            })?;
    let root_prefix =
        parse_did_keri(parent_did.as_str()).map_err(|e| AgentError::IdentityNotFound {
            did: format!("invalid parent did:keri: {e}"),
        })?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;

    // Subset rule: the agent's scope can only narrow the scope the DELEGATOR itself
    // holds. The delegator is whoever's key signs this delegation (`root_alias`),
    // which may be the loaded root OR a scoped mid-chain delegate signing on the same
    // registry — its granted scope is anchored by ITS delegator, never self-asserted.
    enforce_scope_subset(ctx, &root_prefix, root_alias, scope)?;

    let cached_provider = Arc::new(auths_core::signing::CachedPassphraseProvider::new(
        ctx.passphrase_provider.clone(),
        std::time::Duration::from_secs(300),
    ));

    let agent = incept_delegated_device(
        Arc::clone(&ctx.registry),
        &root_prefix,
        root_alias,
        root_curve,
        agent_alias,
        agent_curve,
        cached_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(AgentError::DelegationError)?;

    // Tag the delegation as an agent (an `agent:{prefix}` role marker) so it shows
    // under `agent list`, not `device list`. Reuses `Seal::Digest` — no new seal type.
    mark_delegated_agent(
        ctx.registry.as_ref(),
        &root_prefix,
        root_alias,
        root_curve,
        &agent.device_prefix,
        cached_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(AgentError::DelegationError)?;

    // Delegator-anchored scope/expiry seal (only if a scope or expiry was requested).
    if !scope.is_empty() || expires_at.is_some() {
        mark_agent_scope(
            ctx.registry.as_ref(),
            &root_prefix,
            root_alias,
            root_curve,
            &agent.device_prefix,
            &AgentScope {
                capabilities: scope.to_vec(),
                expires_at,
            },
            cached_provider.as_ref(),
            ctx.key_storage.as_ref(),
        )
        .map_err(AgentError::DelegationError)?;
    }

    // Record the delegation as a signed attestation (issuer = root, subject =
    // agent), persisted and KEL-anchored through the same path device links
    // use. Exported identity bundles then carry a walkable delegation chain —
    // a provenance leg independent of the KEL events themselves.
    record_delegation_attestation_with_provider(
        ctx,
        cached_provider.as_ref(),
        &managed.controller_did,
        &managed.storage_id,
        root_alias,
        &root_prefix,
        agent_alias,
        &agent.device_did,
        expires_at,
    )?;

    Ok(AgentDelegationResult {
        agent_did: agent.device_did.as_str().to_string(),
        agent_prefix: agent.device_prefix.as_str().to_string(),
    })
}

/// Bulk-onboard agents: each batch of `batch_size` is incepted with ONE root
/// anchoring `ixn` and ONE atomic commit (issue #255 / PRD KL-9), instead of the
/// three root events and three-plus commits per agent the per-agent path costs.
///
/// Per-agent semantics match [`add`]: a device-signed `dip`, the dip anchor seal,
/// the `agent:{prefix}` role marker, and the signed delegation attestation — the
/// anchors are simply co-located in the shared batch `ixn`. Unscoped only:
/// scope/expiry seals stay on the per-agent [`add_scoped`] path. Witness receipting
/// is one round per batch, never per agent: each chunk's shared anchor `ixn` is
/// published to the backers in `ctx.witness_params()` before its atomic commit.
pub fn add_bulk(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_aliases: &[KeyAlias],
    agent_curve: auths_crypto::CurveType,
    batch_size: usize,
) -> Result<Vec<AgentDelegationResult>, AgentError> {
    for alias in agent_aliases {
        if ctx.key_storage.load_key(alias).is_ok() {
            return Err(AgentError::AlreadyDelegated {
                alias: alias.as_str().to_string(),
            });
        }
    }
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        AgentError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;

    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let issuer_canonical = CanonicalDid::from(managed.controller_did.clone());
    let mut out = Vec::with_capacity(agent_aliases.len());

    for chunk in agent_aliases.chunks(batch_size.max(1)) {
        let specs: Vec<BulkAgentSpec> = chunk
            .iter()
            .map(|alias| BulkAgentSpec {
                device_alias: alias.clone(),
                device_curve: agent_curve,
            })
            .collect();

        // Per agent: build + sign the delegation attestation (mirroring
        // record_delegation_attestation), stage its blob into the shared batch,
        // and hand its digest seal back to join the batch ixn.
        let mut idx = 0usize;
        let bulk = incept_delegated_agents_bulk(
            ctx.registry.as_ref(),
            &root_prefix,
            root_alias,
            root_curve,
            &specs,
            ctx.passphrase_provider.as_ref(),
            ctx.key_storage.as_ref(),
            &ctx.witness_params(),
            ctx.clock.now(),
            |bundle, batch| {
                let agent_alias = &chunk[idx];
                idx += 1;
                let (agent_pk, agent_pk_curve) = extract_public_key_bytes(
                    ctx.key_storage.as_ref(),
                    agent_alias,
                    ctx.passphrase_provider.as_ref(),
                )
                .map_err(|e| auths_id::error::InitError::Crypto(e.to_string()))?;
                let now = ctx.clock.now();
                let meta = AttestationMetadata {
                    timestamp: Some(now),
                    expires_at: None,
                    note: None,
                };
                let subject = CanonicalDid::from(bundle.device_did.clone());
                let attestation = create_signed_attestation(
                    now,
                    AttestationInput {
                        rid: &managed.storage_id,
                        issuer: &issuer_canonical,
                        subject: &subject,
                        device_public_key: &agent_pk,
                        device_curve: agent_pk_curve,
                        payload: None,
                        meta: &meta,
                        identity_alias: Some(root_alias),
                        device_alias: Some(agent_alias),
                        delegated_by: None,
                        commit_sha: None,
                        signer_type: Some(SignerType::Agent),
                        oidc_binding: None,
                    },
                    &signer,
                    ctx.passphrase_provider.as_ref(),
                )
                .map_err(|e| auths_id::error::InitError::Keri(e.to_string()))?;
                let said = auths_id::keri::anchor::attestation_said(&attestation)
                    .map_err(|e| auths_id::error::InitError::Keri(e.to_string()))?;
                batch.stage_attestation(attestation);
                Ok(vec![auths_id::keri::Seal::digest(said.as_str())])
            },
        )
        .map_err(AgentError::DelegationError)?;

        for device in bulk.devices {
            out.push(AgentDelegationResult {
                agent_did: device.device_did.as_str().to_string(),
                agent_prefix: device.device_prefix.as_str().to_string(),
            });
        }
    }
    Ok(out)
}

/// Sign and anchor the attestation for a freshly delegated agent.
///
/// The delegating root issues (and the agent's key co-signs) an attestation over
/// the agent's public key, then persists and KEL-anchors it through
/// [`anchor_and_persist_via_backend`] — the same single path device links use.
/// This is what puts a programmatically delegated agent into the identity's
/// attestation chain.
#[allow(clippy::too_many_arguments)]
pub fn record_delegation_attestation(
    ctx: &AuthsContext,
    identity_did: &IdentityDID,
    rid: &str,
    root_alias: &KeyAlias,
    root_prefix: &auths_id::keri::types::Prefix,
    agent_alias: &KeyAlias,
    agent_did: &IdentityDID,
    expires_at: Option<i64>,
) -> Result<(), AgentError> {
    record_delegation_attestation_with_provider(
        ctx,
        ctx.passphrase_provider.as_ref(),
        identity_did,
        rid,
        root_alias,
        root_prefix,
        agent_alias,
        agent_did,
        expires_at,
    )
}

/// Record a delegation attestation using a custom passphrase provider.
#[allow(clippy::too_many_arguments)]
pub fn record_delegation_attestation_with_provider(
    ctx: &AuthsContext,
    passphrase_provider: &dyn PassphraseProvider,
    identity_did: &IdentityDID,
    rid: &str,
    root_alias: &KeyAlias,
    root_prefix: &auths_id::keri::types::Prefix,
    agent_alias: &KeyAlias,
    agent_did: &IdentityDID,
    expires_at: Option<i64>,
) -> Result<(), AgentError> {
    let (agent_pk, agent_pk_curve) =
        extract_public_key_bytes(ctx.key_storage.as_ref(), agent_alias, passphrase_provider)
            .map_err(AgentError::CryptoError)?;
    let now = ctx.clock.now();
    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: expires_at.and_then(|secs| chrono::DateTime::from_timestamp(secs, 0)),
        note: None,
    };
    let subject = CanonicalDid::from(agent_did.clone());
    let issuer_canonical = CanonicalDid::from(identity_did.clone());
    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let attestation = create_signed_attestation(
        now,
        AttestationInput {
            rid,
            issuer: &issuer_canonical,
            subject: &subject,
            device_public_key: &agent_pk,
            device_curve: agent_pk_curve,
            payload: None,
            meta: &meta,
            identity_alias: Some(root_alias),
            device_alias: Some(agent_alias),
            delegated_by: None,
            commit_sha: None,
            signer_type: Some(SignerType::Agent),
            oidc_binding: None,
        },
        &signer,
        passphrase_provider,
    )
    .map_err(AgentError::AttestationError)?;
    let mut batch = auths_id::storage::registry::backend::AtomicWriteBatch::new();
    batch.stage_attestation(attestation.clone());
    anchor_and_persist_via_backend(
        ctx.registry.as_ref(),
        &signer,
        root_alias,
        passphrase_provider,
        root_prefix,
        &attestation,
        &mut batch,
        &ctx.witness_params(),
        now,
    )
    .map_err(AgentError::AnchorError)?;
    Ok(())
}

/// Collect a KEL into a `Vec<Event>` (oldest first) via the registry.
fn collect_kel(ctx: &AuthsContext, prefix: &auths_id::keri::types::Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    let _ = ctx.registry.visit_events(prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    events
}

/// Enforce that `requested` capabilities are a subset of the scope the DELEGATOR
/// itself holds.
///
/// The delegator is whoever's key signs this delegation — `root_alias` — which is
/// not necessarily the loaded root identity (`root_prefix`). A scoped mid-chain
/// delegate (e.g. a manager holding `{sign_commit}`) signs on the same registry and
/// must only be able to *narrow*. Its granted scope is anchored by ITS delegator in
/// the registry's KEL, keyed by the delegate's OWN prefix — never by `root_prefix`,
/// and never self-asserted from its own KEL. We therefore resolve the signing key's
/// identity and read the scope seal anchored *for that identity*:
///
/// * the loaded root signing for itself → no seal keyed by the root prefix exists →
///   unrestricted (a top-level root grants any scope), preserving prior behavior; and
/// * a scoped delegate signing → the seal its delegator anchored *for it* is found,
///   so an over-grant beyond what the delegate holds is refused at issuance.
///
/// If the resolved delegator carries no anchored scope seal it is unrestricted.
/// Reuses the salvaged capability-subset rule.
fn enforce_scope_subset(
    ctx: &AuthsContext,
    root_prefix: &auths_id::keri::types::Prefix,
    root_alias: &KeyAlias,
    requested: &[Capability],
) -> Result<(), AgentError> {
    if requested.is_empty() {
        return Ok(());
    }
    // The actual delegator is the identity that owns the signing key, not the loaded
    // root: a scoped mid-chain delegate cannot read its OWN (unrestricted-looking)
    // KEL as the authority for what it may hand out.
    let (delegator_did, _role, _key) = ctx
        .key_storage
        .load_key(root_alias)
        .map_err(AgentError::CryptoError)?;
    let delegator_prefix =
        parse_did_keri(delegator_did.as_str()).map_err(|e| AgentError::IdentityNotFound {
            did: format!("invalid delegator did:keri for alias {root_alias}: {e}"),
        })?;
    // Scope seals are anchored on the registry's KEL by the party that delegated each
    // agent; the delegator's own grant is keyed by ITS prefix. Read from the loaded
    // root KEL (where this registry anchors every delegation), keyed by the delegator.
    let root_kel = collect_kel(ctx, root_prefix);
    let is_registry_root = delegator_prefix == *root_prefix;
    match resolve_delegator_authority(
        is_registry_root,
        read_agent_scope(&root_kel, &delegator_prefix),
    ) {
        // The registry root signing for itself may grant any scope — granted only because the signer
        // is the root, never because a seal happened to be absent.
        DelegatorAuthority::Root => Ok(()),
        // A delegate may only narrow the scope its delegator anchored for it.
        DelegatorAuthority::Scoped(scope) => {
            crate::domains::agents::scope::validate_capability_subset(
                &scope.capabilities,
                requested,
            )
            .map_err(|e| AgentError::OutsideDelegatorScope {
                capability: match e {
                    crate::domains::agents::scope::DelegationError::CapabilityNotGranted(cap) => {
                        cap
                    }
                    other => other.to_string(),
                },
            })
        }
        // A delegator that is not the root and presents no anchored seal has no authority to delegate
        // further, so the request is refused instead of being treated as unrestricted.
        DelegatorAuthority::NoAuthority => Err(AgentError::OutsideDelegatorScope {
            capability: format!("delegator {delegator_prefix} presents no anchored scope seal"),
        }),
    }
}

/// What a delegator is permitted to hand out, resolved from the registry. The registry root may grant
/// any scope; any other delegator is bounded by the scope seal its own delegator anchored for it; a
/// non-root delegator that presents no anchored seal has no authority to delegate further.
enum DelegatorAuthority {
    /// The registry root signing for itself — unrestricted.
    Root,
    /// Bounded by the scope seal anchored for this delegate.
    Scoped(AgentScope),
    /// Not the root and no anchored seal — the request must be refused.
    NoAuthority,
}

/// Resolve a delegator's authority from whether it is the registry root and the anchored seal read for
/// it. Only the root is unrestricted; a non-root delegator with no seal yields [`DelegatorAuthority::
/// NoAuthority`] (the caller refuses) rather than being treated as unrestricted.
fn resolve_delegator_authority(
    is_registry_root: bool,
    anchored_seal: Option<AgentScope>,
) -> DelegatorAuthority {
    match (is_registry_root, anchored_seal) {
        // A delegator that presents an anchored seal is bounded by it, whether or not it is the root.
        (_, Some(scope)) => DelegatorAuthority::Scoped(scope),
        // The registry root with no anchored seal is unrestricted.
        (true, None) => DelegatorAuthority::Root,
        // A non-root delegator with no anchored seal has no authority to delegate further.
        (false, None) => DelegatorAuthority::NoAuthority,
    }
}

/// One agent delegated by the current identity, with its revocation status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInfo {
    /// The agent's `did:keri:`.
    pub agent_did: String,
    /// Whether the delegator has revoked this agent.
    pub revoked: bool,
}

/// List the agents delegated by the current identity (the agent delegation set),
/// each tagged with whether it has been revoked. Excludes devices (filters on the
/// `agent` role marker). The live set is the non-revoked entries.
///
/// Args:
/// * `ctx`: Auths context.
///
/// Usage:
/// ```ignore
/// let live = list(&ctx)?.into_iter().filter(|a| !a.revoked).count();
/// ```
pub fn list(ctx: &AuthsContext) -> Result<Vec<AgentInfo>, AgentError> {
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        AgentError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let delegated = list_delegated_devices(ctx.registry.as_ref(), &root_prefix)
        .map_err(AgentError::DelegationError)?;
    Ok(delegated
        .into_iter()
        .filter(|d| d.role == DelegatedRole::Agent)
        .map(|d| AgentInfo {
            agent_did: format!("did:keri:{}", d.device_prefix),
            revoked: d.revoked,
        })
        .collect())
}

/// Revoke a delegated agent: the delegator anchors a revocation seal so verifiers
/// stop honouring it. Thin wrapper over the generic [`revoke_delegated_device`];
/// idempotent — revoking an already-revoked agent is a no-op `Ok`.
///
/// Args:
/// * `ctx`: Auths context.
/// * `root_alias`: Keychain alias of the delegating root identity's signing key.
/// * `agent_did`: The delegated agent's `did:keri:` to revoke.
///
/// Usage:
/// ```ignore
/// revoke(&ctx, &root_alias, "did:keri:E...")?;
/// ```
pub fn revoke(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_did: &str,
) -> Result<(), AgentError> {
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        AgentError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let agent_prefix = parse_did_keri(agent_did).map_err(|_| AgentError::AgentNotFound {
        did: agent_did.to_string(),
    })?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;

    revoke_delegated_device(
        ctx.registry.as_ref(),
        &root_prefix,
        root_alias,
        root_curve,
        &agent_prefix,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(AgentError::DelegationError)
}

/// Receipt for an atomic-batch agent revocation (the org-wide kill switch).
#[derive(Debug, Clone)]
pub struct BatchRevocation {
    /// The agents that are revoked as of this batch (all requested).
    pub revoked: Vec<String>,
    /// The KEL position the batch revocation was anchored at, or `None` if every
    /// requested agent was already revoked (no new event written).
    pub anchored_at_seq: Option<u128>,
}

/// Revoke an enumerated set of agents in a **single** KEL event — the org-wide kill
/// switch. Anchors one revocation seal per still-live agent in one atomic `ixn`, so the
/// whole set's authority ends at the same KEL position; subsequent actions are rejected
/// positionally. Idempotent: already-revoked agents are skipped (still reported as
/// revoked); if all were already revoked, no event is written.
///
/// This is an atomic batch over an explicit set, not a class-by-predicate event.
///
/// Args:
/// * `ctx`: Auths context.
/// * `root_alias`: Keychain alias of the delegating root identity's signing key.
/// * `agent_dids`: The agents' `did:keri:` to revoke.
///
/// Usage:
/// ```ignore
/// let receipt = revoke_batch(&ctx, &root_alias, &[a.clone(), b.clone()])?;
/// ```
pub fn revoke_batch(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_dids: &[String],
) -> Result<BatchRevocation, AgentError> {
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        AgentError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;

    let mut prefixes = Vec::with_capacity(agent_dids.len());
    for did in agent_dids {
        prefixes
            .push(parse_did_keri(did).map_err(|_| AgentError::AgentNotFound { did: did.clone() })?);
    }

    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;

    let (_newly, ixn) = revoke_delegated_devices_batch(
        ctx.registry.as_ref(),
        &root_prefix,
        root_alias,
        root_curve,
        &prefixes,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(AgentError::DelegationError)?;

    Ok(BatchRevocation {
        revoked: agent_dids.to_vec(),
        anchored_at_seq: ixn.map(|e| e.s.value()),
    })
}

/// Rotate a delegated agent's own key (`drt`), anchored by the root.
///
/// Thin wrapper over the generic [`rotate_delegated_device`]: the agent reveals its
/// pre-committed next key, signs a `drt` advancing its own KEL (carrying the E.1
/// `-G` source seal), and the root anchors it. Persists the agent's new current key
/// and a fresh next commitment.
///
/// Custody note (local-add MVP): the engine requires the **root key in-process** to
/// anchor the `drt` — single-host only. A remote agent rotating while the delegator
/// is offline needs a queued-anchor handshake (tracked as remote-provisioning
/// follow-on in E.9).
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, identity storage, passphrase).
/// * `root_alias`: Keychain alias of the delegating root identity's signing key.
/// * `agent_did`: The delegated agent's `did:keri:` to rotate.
///
/// Usage:
/// ```ignore
/// rotate(&ctx, &root_alias, "did:keri:E...")?;
/// ```
pub fn rotate(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    agent_did: &str,
) -> Result<(), AgentError> {
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| AgentError::IdentityNotFound {
                did: format!("identity load failed: {e}"),
            })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        AgentError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let agent_prefix = parse_did_keri(agent_did).map_err(|_| AgentError::AgentNotFound {
        did: agent_did.to_string(),
    })?;

    // Refuse rotating an agent the root has revoked.
    let delegated = list_delegated_devices(ctx.registry.as_ref(), &root_prefix)
        .map_err(AgentError::DelegationError)?;
    let info = delegated
        .iter()
        .find(|d| d.device_prefix.as_str() == agent_prefix.as_str())
        .ok_or_else(|| AgentError::AgentNotFound {
            did: agent_did.to_string(),
        })?;
    if info.revoked {
        return Err(AgentError::Revoked {
            did: agent_did.to_string(),
        });
    }

    // Resolve the agent's keychain alias (its current key) and curves.
    let agent_did_typed =
        IdentityDID::try_from(&agent_prefix).map_err(|e| AgentError::AgentNotFound {
            did: format!("invalid agent did:keri: {e}"),
        })?;
    let agent_alias = ctx
        .key_storage
        .list_aliases_for_identity(&agent_did_typed)
        .map_err(AgentError::CryptoError)?
        .into_iter()
        .find(|a| !a.as_str().contains("--next-"))
        .ok_or_else(|| AgentError::AgentNotFound {
            did: format!("no local key for agent {agent_did}"),
        })?;
    let (_pk, agent_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &agent_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(AgentError::CryptoError)?;

    rotate_delegated_device(
        ctx.registry.as_ref(),
        &root_prefix,
        root_alias,
        root_curve,
        &agent_prefix,
        &agent_alias,
        agent_curve,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(AgentError::DelegationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_root_delegator_without_a_seal_has_no_authority() {
        // Only the registry root is unrestricted. A delegator that is not the root and presents no
        // anchored seal cannot delegate further, so it resolves to NoAuthority and the caller refuses
        // rather than treating it as unrestricted.
        assert!(matches!(
            resolve_delegator_authority(false, None),
            DelegatorAuthority::NoAuthority
        ));
        // The root is unrestricted even with no anchored seal.
        assert!(matches!(
            resolve_delegator_authority(true, None),
            DelegatorAuthority::Root
        ));
    }
}
