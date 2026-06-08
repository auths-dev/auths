//! Agent-passport control-plane handlers: issue / list / revoke over the shipped SDK
//! agent workflows. Typed request/response DTOs; idempotent issuance; cursor
//! pagination over KEL order; a revocation receipt carrying the KEL position.

// HTTP boundary: samples the wall clock as the injected expiry base (CLAUDE.md "the
// CLI/API call Utc::now() at the presentation boundary").
#![allow(clippy::disallowed_methods)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ops::ControlFlow;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;
use auths_id::keri::types::Prefix;
use auths_id::keri::{parse_did_keri, Event};
use auths_sdk::domains::agents::{add_scoped, list, revoke, revoke_batch};
use auths_sdk::domains::org::offboarding::find_revocation_event;
use auths_sdk::workflows::org::{resolve_member_authority, walk_delegation_chain};

use crate::app::{AppState, IdempotencyHit};
use crate::error::ApiError;

/// Default + maximum page size for fleet listing.
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;

/// Request to issue (delegate) a new agent passport.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuePassportRequest {
    /// Keychain alias to store the new agent key under (must be fresh).
    pub label: String,
    /// Capabilities to grant the agent (must be non-empty).
    pub capabilities: Vec<String>,
    /// Optional lifetime in seconds; the passport expires `now + expires_in_secs`.
    pub expires_in_secs: Option<u64>,
}

/// A summary of one agent passport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportSummary {
    /// The agent's `did:keri:`.
    pub agent: String,
    /// Capabilities granted by the delegator-anchored scope seal.
    pub capabilities: Vec<String>,
    /// Delegator-anchored expiry (Unix epoch seconds), if any.
    pub expires_at: Option<i64>,
    /// Whether the delegator has revoked this agent.
    pub revoked: bool,
}

/// A page of agent passports plus an opaque cursor for the next page.
#[derive(Debug, Clone, Serialize)]
pub struct PassportListResponse {
    /// The agents in this page (KEL/delegation order).
    pub agents: Vec<PassportSummary>,
    /// Cursor for the next page (the last agent DID), or `null` at the end.
    pub next_cursor: Option<String>,
}

/// Proof that a revocation was anchored: the agent and the KEL position after which
/// its authority is gone.
#[derive(Debug, Clone, Serialize)]
pub struct RevocationReceipt {
    /// The revoked agent's `did:keri:`.
    pub agent: String,
    /// The KEL sequence at which the revocation was anchored (positional, not wall-clock).
    pub anchored_at_seq: u128,
}

/// Request to revoke an enumerated set of agents in one atomic event (kill switch).
#[derive(Debug, Clone, Deserialize)]
pub struct BatchRevokeRequest {
    /// The agents' `did:keri:` to revoke together.
    pub agents: Vec<String>,
}

/// Receipt for an atomic-batch revocation.
#[derive(Debug, Clone, Serialize)]
pub struct BatchRevocationResponse {
    /// The agents revoked as of this batch.
    pub revoked: Vec<String>,
    /// The single KEL position the batch was anchored at (`null` if all were already
    /// revoked, so no new event was written).
    pub anchored_at_seq: Option<u128>,
}

/// One fleet member with its chain to the authorizing root and live status.
#[derive(Debug, Clone, Serialize)]
pub struct FleetMember {
    /// The agent's `did:keri:`.
    pub agent: String,
    /// Capabilities granted by the delegator-anchored scope seal.
    pub capabilities: Vec<String>,
    /// Delegator-anchored expiry (Unix epoch seconds), if any.
    pub expires_at: Option<i64>,
    /// Whether the delegator has revoked this agent.
    pub revoked: bool,
    /// The delegation chain DIDs from the agent up to the root (agent first, root last).
    pub chain_to_human: Vec<String>,
    /// Whether every link in the chain is currently live (no revoked authority).
    pub live: bool,
    /// Why the chain could not be fully reconstructed, if applicable (fail-closed:
    /// such a member is reported `live = false`, never silently dropped).
    pub chain_error: Option<String>,
}

/// A page of fleet members (each with its chain to the authorizing root).
#[derive(Debug, Clone, Serialize)]
pub struct FleetResponse {
    /// The fleet members in this page.
    pub members: Vec<FleetMember>,
    /// Cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
}

/// Query parameters for fleet listing (keyset cursor over KEL order).
#[derive(Debug, Clone, Deserialize)]
pub struct ListParams {
    /// Return agents after this DID (the previous page's `next_cursor`).
    pub cursor: Option<String>,
    /// Page size (default 50, max 200).
    pub limit: Option<usize>,
}

/// Stable fingerprint of an issuance request, for idempotency-key body matching.
fn fingerprint(org: &str, req: &IssuePassportRequest) -> u64 {
    let mut hasher = DefaultHasher::new();
    org.hash(&mut hasher);
    req.label.hash(&mut hasher);
    let mut caps = req.capabilities.clone();
    caps.sort();
    caps.hash(&mut hasher);
    req.expires_in_secs.hash(&mut hasher);
    hasher.finish()
}

/// Compute the `[start, end)` window and next cursor for keyset pagination over `ids`.
///
/// `Err(())` if a cursor is supplied but not found (stale/unknown). The next cursor is
/// the last id of the page when more remain, else `None`.
fn page_window(
    ids: &[String],
    cursor: Option<&str>,
    limit: usize,
) -> Result<(usize, usize, Option<String>), ()> {
    let start = match cursor {
        Some(c) => ids.iter().position(|d| d == c).map(|i| i + 1).ok_or(())?,
        None => 0,
    };
    let limit = limit.clamp(1, MAX_PAGE);
    let end = (start + limit).min(ids.len());
    let next = if end < ids.len() {
        ids.get(end - 1).cloned()
    } else {
        None
    };
    Ok((start, end, next))
}

/// Collect an org's KEL into a `Vec<Event>` (oldest first).
fn collect_kel(state: &AppState, org_prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    let _ = state.ctx.registry.visit_events(org_prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    events
}

/// `POST /v1/org/{org}/agents` — issue (delegate) a new agent passport.
///
/// Idempotent on the `Idempotency-Key` header: a replay with the same body returns the
/// original result; a different body under the same key is `409`. An empty capability
/// set is rejected `400` before any KEL write.
pub async fn issue_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(req): Json<IssuePassportRequest>,
) -> Result<Json<PassportSummary>, ApiError> {
    state.ensure_org(&org)?;
    if req.capabilities.is_empty() || req.capabilities.iter().all(|c| c.trim().is_empty()) {
        return Err(ApiError::BadRequest(
            "capabilities must not be empty".to_string(),
        ));
    }

    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let fp = fingerprint(&org, &req);
    if let Some(key) = &idem_key {
        match state.idempotency_lookup(key, fp) {
            IdempotencyHit::Replay(json) => return Ok(Json(serde_json::from_str(&json)?)),
            IdempotencyHit::Conflict => {
                return Err(ApiError::Conflict(
                    "idempotency key reused with a different request body".to_string(),
                ));
            }
            IdempotencyHit::Miss => {}
        }
    }

    let expires_at = req
        .expires_in_secs
        .map(|s| (chrono::Utc::now() + chrono::Duration::seconds(s as i64)).timestamp());

    let result = add_scoped(
        &state.ctx,
        &state.org_alias,
        &KeyAlias::new_unchecked(req.label.clone()),
        CurveType::P256,
        &req.capabilities,
        expires_at,
    )?;

    let summary = PassportSummary {
        agent: result.agent_did,
        capabilities: req.capabilities.clone(),
        expires_at,
        revoked: false,
    };
    if let Some(key) = idem_key {
        state.idempotency_store(key, fp, serde_json::to_string(&summary)?);
    }
    Ok(Json(summary))
}

/// `GET /v1/org/{org}/agents` — list the fleet (cursor-paginated over KEL order).
///
/// Revoked agents remain listed with `revoked = true`, so a cursor stays stable under
/// concurrent revocation. A stale/unknown cursor is `400`.
pub async fn list_agents(
    State(state): State<AppState>,
    Path(org): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<PassportListResponse>, ApiError> {
    state.ensure_org(&org)?;
    let all = list(&state.ctx)?;
    let ids: Vec<String> = all.iter().map(|a| a.agent_did.clone()).collect();

    let (start, end, next_cursor) = page_window(
        &ids,
        params.cursor.as_deref(),
        params.limit.unwrap_or(DEFAULT_PAGE),
    )
    .map_err(|()| ApiError::BadRequest("stale or unknown cursor".to_string()))?;

    let org_prefix = Prefix::new_unchecked(state.org_prefix.clone());
    let mut agents = Vec::with_capacity(end - start);
    for info in &all[start..end] {
        let agent_prefix = parse_did_keri(&info.agent_did).map_err(|_| ApiError::InternalError)?;
        let (capabilities, expires_at) =
            match resolve_member_authority(&state.ctx, &org_prefix, &agent_prefix)? {
                Some(a) => (a.capabilities, a.expires_at),
                None => (Vec::new(), None),
            };
        agents.push(PassportSummary {
            agent: info.agent_did.clone(),
            capabilities,
            expires_at,
            revoked: info.revoked,
        });
    }

    Ok(Json(PassportListResponse {
        agents,
        next_cursor,
    }))
}

/// `GET /v1/org/{org}/fleet` — list the fleet with each agent's chain to the
/// authorizing root and current live status (via the multi-hop delegation walker).
///
/// A member whose chain cannot be reconstructed (a broken/forked hop) is reported with
/// `live = false` and a `chain_error` — surfaced, never silently dropped.
pub async fn list_fleet(
    State(state): State<AppState>,
    Path(org): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<FleetResponse>, ApiError> {
    state.ensure_org(&org)?;
    let all = list(&state.ctx)?;
    let ids: Vec<String> = all.iter().map(|a| a.agent_did.clone()).collect();
    let (start, end, next_cursor) = page_window(
        &ids,
        params.cursor.as_deref(),
        params.limit.unwrap_or(DEFAULT_PAGE),
    )
    .map_err(|()| ApiError::BadRequest("stale or unknown cursor".to_string()))?;

    let org_prefix = Prefix::new_unchecked(state.org_prefix.clone());
    let mut members = Vec::with_capacity(end - start);
    for info in &all[start..end] {
        let agent_prefix = parse_did_keri(&info.agent_did).map_err(|_| ApiError::InternalError)?;
        let (capabilities, expires_at) =
            match resolve_member_authority(&state.ctx, &org_prefix, &agent_prefix)? {
                Some(a) => (a.capabilities, a.expires_at),
                None => (Vec::new(), None),
            };

        // Current-state chain view (no in-band signing position → any revoked link is
        // not live). A broken hop is surfaced per-member, fail-closed.
        let (chain_to_human, live, chain_error) =
            match walk_delegation_chain(&state.ctx, &agent_prefix, None) {
                Ok(chain) => {
                    let mut path = vec![chain.leaf_did.clone()];
                    path.extend(chain.hops.iter().map(|h| h.delegator_did.clone()));
                    (path, chain.live_at_signing, None)
                }
                Err(e) => (Vec::new(), false, Some(e.to_string())),
            };

        members.push(FleetMember {
            agent: info.agent_did.clone(),
            capabilities,
            expires_at,
            revoked: info.revoked,
            chain_to_human,
            live,
            chain_error,
        });
    }

    Ok(Json(FleetResponse {
        members,
        next_cursor,
    }))
}

/// `POST /v1/org/{org}/agents/{id}/revoke` — revoke an agent (idempotent), returning a
/// receipt with the KEL position the revocation was anchored at.
pub async fn revoke_agent(
    State(state): State<AppState>,
    Path((org, id)): Path<(String, String)>,
) -> Result<Json<RevocationReceipt>, ApiError> {
    state.ensure_org(&org)?;
    revoke(&state.ctx, &state.org_alias, &id)?;

    let agent_prefix =
        parse_did_keri(&id).map_err(|_| ApiError::NotFound(format!("agent '{id}' not found")))?;
    let org_prefix = Prefix::new_unchecked(state.org_prefix.clone());
    let org_kel = collect_kel(&state, &org_prefix);
    let (_seal, anchored_at_seq) = find_revocation_event(&org_kel, &agent_prefix)
        .ok_or_else(|| ApiError::NotFound(format!("agent '{id}' not found")))?;

    Ok(Json(RevocationReceipt {
        agent: id,
        anchored_at_seq,
    }))
}

/// `POST /v1/org/{org}/agents/revoke-batch` — the kill switch: revoke an enumerated
/// set of agents in one atomic KEL event. Idempotent; rejects an empty set (`400`).
pub async fn batch_revoke_agents(
    State(state): State<AppState>,
    Path(org): Path<String>,
    Json(req): Json<BatchRevokeRequest>,
) -> Result<Json<BatchRevocationResponse>, ApiError> {
    state.ensure_org(&org)?;
    if req.agents.is_empty() {
        return Err(ApiError::BadRequest("agents must not be empty".to_string()));
    }
    let receipt = revoke_batch(&state.ctx, &state.org_alias, &req.agents)?;
    Ok(Json(BatchRevocationResponse {
        revoked: receipt.revoked,
        anchored_at_seq: receipt.anchored_at_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("did:keri:E{i}")).collect()
    }

    #[test]
    fn page_window_first_page_and_cursor() {
        let ids = ids(5);
        // First page of 2 → items 0,1 ; next cursor = the 2nd id (index 1).
        let (start, end, next) = page_window(&ids, None, 2).unwrap();
        assert_eq!((start, end), (0, 2));
        assert_eq!(next.as_deref(), Some("did:keri:E1"));

        // Next page after that cursor → items 2,3 ; next = index 3.
        let (start, end, next) = page_window(&ids, Some("did:keri:E1"), 2).unwrap();
        assert_eq!((start, end), (2, 4));
        assert_eq!(next.as_deref(), Some("did:keri:E3"));

        // Last page → item 4 ; no next cursor.
        let (start, end, next) = page_window(&ids, Some("did:keri:E3"), 2).unwrap();
        assert_eq!((start, end), (4, 5));
        assert_eq!(next, None);
    }

    #[test]
    fn page_window_stale_cursor_is_error() {
        assert!(page_window(&ids(3), Some("did:keri:Eghost"), 10).is_err());
    }

    #[test]
    fn page_window_clamps_limit() {
        let ids = ids(10);
        // Zero clamps to 1.
        let (s, e, _) = page_window(&ids, None, 0).unwrap();
        assert_eq!(e - s, 1);
        // Over-max clamps to MAX_PAGE (here just bounded by len).
        let (s, e, next) = page_window(&ids, None, MAX_PAGE + 1000).unwrap();
        assert_eq!((s, e), (0, 10));
        assert_eq!(next, None);
    }

    #[test]
    fn fingerprint_is_stable_and_body_sensitive() {
        let a = IssuePassportRequest {
            label: "agent-1".into(),
            capabilities: vec!["sign_commit".into(), "open-PR".into()],
            expires_in_secs: Some(3600),
        };
        // Same logical request (capability order does not matter) → same fingerprint.
        let b = IssuePassportRequest {
            label: "agent-1".into(),
            capabilities: vec!["open-PR".into(), "sign_commit".into()],
            expires_in_secs: Some(3600),
        };
        assert_eq!(
            fingerprint("did:keri:Eorg", &a),
            fingerprint("did:keri:Eorg", &b)
        );

        // A different capability set → different fingerprint (idempotency-key reuse is a conflict).
        let c = IssuePassportRequest {
            capabilities: vec!["deploy".into()],
            ..a.clone()
        };
        assert_ne!(
            fingerprint("did:keri:Eorg", &a),
            fingerprint("did:keri:Eorg", &c)
        );
    }
}
