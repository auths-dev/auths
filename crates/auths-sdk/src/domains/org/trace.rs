//! Multi-hop delegation chain walker — accountability as a query.
//!
//! Given a signer AID, follow its `di` (delegator) links up to the chain root,
//! classifying each hop's authority at the artifact's signing position. Generic and
//! N-hop: each link is `child` delegated-by `parent` (AID→AID); there is no semantic
//! "team" layer (none is modeled). Pure over the registry — the same inputs always
//! yield the same chain, so the audit answer equals the enforcement answer.
//!
//! **Point-in-time, fail-closed.** Only the leaf→immediate-delegator hop carries an
//! in-band signing position (a commit's `Auths-Anchor-Seq` is a position in the
//! *immediate* delegator's KEL); upstream hops are classified position-unknown, so
//! **any** upstream revocation rejects the chain (a revoked intermediate invalidates
//! everything below it, regardless of wall-clock). Per-hop classification reuses the
//! shipped [`classify_authority_at_signing`], which orders strictly by KEL position.

use std::collections::HashSet;
use std::ops::ControlFlow;

use auths_id::keri::types::Prefix;
use serde::Serialize;

use crate::context::AuthsContext;
use crate::domains::org::audit::{AuthorityAtSigning, classify_authority_at_signing};
use crate::domains::org::delegation::resolve_member_authority;
use crate::domains::org::error::OrgError;

/// Maximum delegation hops the walker follows before failing closed. Matches the
/// policy engine's chain-depth ceiling (`auths_policy` `MAX_CHAIN_DEPTH_LIMIT`).
pub const MAX_CHAIN_DEPTH: u32 = 16;

/// One link in a delegation chain: `child_did` delegated by `delegator_did`, with the
/// child's role/capabilities (from the delegator-anchored scope seal) and its
/// authority verdict at the artifact's signing position.
#[derive(Debug, Clone, Serialize)]
pub struct ChainHop {
    /// The delegated identifier's `did:keri:`.
    pub child_did: String,
    /// The delegator's `did:keri:` (the `di` of the child's `dip`).
    pub delegator_did: String,
    /// The child's role under the delegator (from the scope seal), if any.
    pub role: Option<String>,
    /// Capabilities the delegator granted the child.
    pub capabilities: Vec<String>,
    /// Whether the child's authority was live at the signing position — ordered by
    /// KEL position, never wall-clock.
    pub authority_at_signing: AuthorityAtSigning,
}

/// A reconstructed delegation chain from a leaf signer up to the chain root.
#[derive(Debug, Clone, Serialize)]
pub struct DelegationChain {
    /// The signer's `did:keri:` (the leaf).
    pub leaf_did: String,
    /// The chain root's `did:keri:` (the topmost identifier with no delegator).
    pub root_did: String,
    /// The hops, ordered leaf → root.
    pub hops: Vec<ChainHop>,
    /// The number of delegation hops (0 if the signer is itself a root).
    pub depth: u32,
    /// True iff every hop's authority was live at the signing position. Vacuously
    /// true for a root signer (no delegation to revoke).
    pub live_at_signing: bool,
}

/// Format a prefix as a `did:keri:`.
fn did(prefix: &Prefix) -> String {
    format!("did:keri:{}", prefix.as_str())
}

/// Read a prefix's immediate delegator (`di`) from the inception event of its KEL, or
/// `None` if it is a root (an `icp`, not a `dip`). Errors if the KEL is absent.
fn immediate_delegator(ctx: &AuthsContext, prefix: &Prefix) -> Result<Option<Prefix>, OrgError> {
    let mut delegator: Option<Prefix> = None;
    let mut found = false;
    ctx.registry
        .visit_events(prefix, 0, &mut |event| {
            // The first event is the inception (icp → root; dip → delegated, di set).
            delegator = event.delegator().cloned();
            found = true;
            ControlFlow::Break(())
        })
        .map_err(OrgError::Storage)?;
    if !found {
        return Err(OrgError::ChainBrokenHop { did: did(prefix) });
    }
    Ok(delegator)
}

/// Walk a delegation chain from `leaf_prefix` up to its root, classifying each hop's
/// authority at the artifact's signing position.
///
/// `signed_at` is the artifact's in-band signing position in the **immediate**
/// delegator's KEL (e.g. a commit's `Auths-Anchor-Seq`); it applies only to the
/// leaf→immediate-delegator hop. Upstream hops are classified position-unknown, so any
/// upstream revocation fails closed. `None` classifies every hop position-unknown.
///
/// Fail-closed: a cycle ([`OrgError::ChainCycle`]), an over-deep chain
/// ([`OrgError::ChainTooDeep`]), or a missing KEL ([`OrgError::ChainBrokenHop`]) is a
/// hard error rather than a partial/looping result.
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `leaf_prefix`: The signer's KEL prefix (the leaf of the chain).
/// * `signed_at`: The artifact's in-band signing position, if any.
///
/// Usage:
/// ```ignore
/// let chain = walk_delegation_chain(&ctx, &agent_prefix, Some(41))?;
/// if !chain.live_at_signing { /* reject — an authority in the chain was revoked */ }
/// ```
pub fn walk_delegation_chain(
    ctx: &AuthsContext,
    leaf_prefix: &Prefix,
    signed_at: Option<u128>,
) -> Result<DelegationChain, OrgError> {
    let leaf_did = did(leaf_prefix);
    let mut hops: Vec<ChainHop> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = leaf_prefix.clone();

    loop {
        if !seen.insert(current.as_str().to_string()) {
            return Err(OrgError::ChainCycle { did: did(&current) });
        }
        let Some(parent) = immediate_delegator(ctx, &current)? else {
            break; // `current` has no delegator → it is the chain root.
        };
        if hops.len() as u32 >= MAX_CHAIN_DEPTH {
            return Err(OrgError::ChainTooDeep {
                max: MAX_CHAIN_DEPTH,
            });
        }

        // Only the leaf→immediate-delegator hop has an in-band signing position;
        // upstream hops are position-unknown (any upstream revocation fails closed).
        let position = if hops.is_empty() { signed_at } else { None };
        let authority_at_signing = classify_authority_at_signing(ctx, &parent, &current, position)?;
        let (role, capabilities) = match resolve_member_authority(ctx, &parent, &current)? {
            Some(authority) => (
                authority.role.map(|r| r.as_str().to_string()),
                authority.capabilities,
            ),
            None => (None, Vec::new()),
        };

        hops.push(ChainHop {
            child_did: did(&current),
            delegator_did: did(&parent),
            role,
            capabilities,
            authority_at_signing,
        });
        current = parent;
    }

    let live_at_signing = hops.iter().all(|h| {
        matches!(
            h.authority_at_signing,
            AuthorityAtSigning::AuthorizedBeforeRevocation
        )
    });

    Ok(DelegationChain {
        leaf_did,
        root_did: did(&current),
        depth: hops.len() as u32,
        hops,
        live_at_signing,
    })
}
