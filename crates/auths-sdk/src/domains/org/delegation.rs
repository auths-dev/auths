//! KERI-native org membership — a member as a `dip` delegated by the org AID.
//!
//! An org member is a KERI delegated identifier: its own KEL is incepted with a
//! `dip` naming the **org AID** as delegator, and the org anchors it via an `ixn`
//! (the same generic engine devices and agents use). The member's role and
//! capabilities ride a **delegator-anchored** scope seal in the org's own KEL — the
//! org admin asserts the member's role; a compromised member cannot widen it.
//!
//! Authority is therefore provable by KEL replay and is read **fail-closed**: a
//! member the org revoked on its KEL is unauthorized even if a stale attestation
//! says otherwise. This is the keripy-native replacement for the attestation
//! `delegated_by` org-membership model.
//!
//! Single-author only: `author_root_anchor_ixn` signs the org's anchoring `ixn`
//! with one key, so the org must be single-signature (`kt=1`). A `kt≥2` org is
//! rejected with [`OrgError::OrgThresholdDelegationUnsupported`]; multi-sig org
//! anchoring is a tracked follow-up.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::keri::Event;
use auths_id::keri::delegation::{
    anchor_received_dip, incept_delegated_device, list_delegated_devices, mark_agent_scope,
    read_agent_scope, revoke_delegated_device,
};
use auths_id::keri::parse_did_keri;
use auths_id::keri::types::Prefix;
use auths_id::policy::{EvalContext, context_from_delegated_member};
use auths_keri::{AgentScope, DipEvent};
use auths_verifier::core::Role;
use chrono::{DateTime, Utc};

use crate::audit::emit_audit;
use crate::context::AuthsContext;
use crate::domains::org::error::OrgError;
use crate::domains::org::offboarding::{
    OffboardingRecord, SignedOffboardingRecord, find_revocation_event, sign_offboarding_record,
    store_offboarding_record,
};

/// Scope-seal marker prefix carrying the member's org role (`role:admin`).
const ROLE_MARKER_PREFIX: &str = "role:";

/// Encode a role as its scope-seal marker capability (`role:{role}`).
fn role_marker(role: Role) -> String {
    format!("{ROLE_MARKER_PREFIX}{}", role.as_str())
}

/// Parse a role string (`admin` / `member` / `readonly`) back into a [`Role`].
fn parse_role(s: &str) -> Option<Role> {
    match s {
        "admin" => Some(Role::Admin),
        "member" => Some(Role::Member),
        "readonly" => Some(Role::Readonly),
        _ => None,
    }
}

/// Split a scope seal into its role marker and the real capability set.
fn split_role_and_caps(scope: Option<&AgentScope>) -> (Option<Role>, Vec<String>) {
    let Some(scope) = scope else {
        return (None, Vec::new());
    };
    let mut role = None;
    let mut caps = Vec::new();
    for cap in &scope.capabilities {
        match cap.strip_prefix(ROLE_MARKER_PREFIX) {
            Some(r) => role = parse_role(r),
            None => caps.push(cap.clone()),
        }
    }
    (role, caps)
}

/// Collect a KEL into a `Vec<Event>` (oldest first) via the registry.
fn collect_kel(ctx: &AuthsContext, prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    let _ = ctx.registry.visit_events(prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    events
}

/// Reject a `kt≥2` (multi-signature) org delegator — the anchoring `ixn` is
/// single-author. `kt=1` orgs (the documented pre-launch baseline) pass.
fn ensure_single_sig_org(ctx: &AuthsContext, org_prefix: &Prefix) -> Result<(), OrgError> {
    let state = ctx
        .registry
        .get_key_state(org_prefix)
        .map_err(OrgError::Storage)?;
    if state.threshold.simple_value() == Some(1) {
        Ok(())
    } else {
        Err(OrgError::OrgThresholdDelegationUnsupported {
            org: org_prefix.as_str().to_string(),
        })
    }
}

/// Result of minting a KERI-native org member.
#[derive(Debug, Clone)]
pub struct OrgMemberResult {
    /// The new member's `did:keri:` (self-addressing — derived from its `dip` SAID).
    pub member_did: String,
    /// The new member's KEL prefix.
    pub member_prefix: String,
}

/// Add a member to an organization as a `dip` delegated by the org AID.
///
/// Mints a fresh delegated identifier on this host (the org's host generates the
/// member key, like `auths id agent add`), has the org anchor it via an `ixn`, and
/// anchors a delegator-side scope seal carrying the member's role + capabilities.
/// The member's `did:keri` derives from its `dip` SAID. KERI delegation carries no
/// timestamps, so no clock is needed.
///
/// Rejects a `kt≥2` org delegator ([`OrgError::OrgThresholdDelegationUnsupported`])
/// and a reused member alias ([`OrgError::MemberKeyExists`]).
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, passphrase).
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `member_alias`: Keychain alias to store the new member key under.
/// * `member_curve`: Curve for the new member key.
/// * `role`: The member's org role (asserted by the org admin).
/// * `capabilities`: Capability strings to grant the member.
/// * `expires_at`: Optional delegator-anchored expiry (Unix epoch seconds).
///
/// Usage:
/// ```ignore
/// let member = add_member(&ctx, &org_prefix, &org_alias, &member_alias,
///     CurveType::Ed25519, Role::Member, &["sign_commit".into()], None)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    member_alias: &KeyAlias,
    member_curve: auths_crypto::CurveType,
    role: Role,
    capabilities: &[String],
    expires_at: Option<i64>,
) -> Result<OrgMemberResult, OrgError> {
    ensure_single_sig_org(ctx, org_prefix)?;

    if ctx.key_storage.load_key(member_alias).is_ok() {
        return Err(OrgError::MemberKeyExists {
            alias: member_alias.as_str().to_string(),
        });
    }

    let (_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    let member = incept_delegated_device(
        Arc::clone(&ctx.registry),
        org_prefix,
        org_alias,
        org_curve,
        member_alias,
        member_curve,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    // Role + capabilities ride a delegator-anchored scope seal — the org admin
    // asserts the member's role; it never lives in the member's own KEL.
    let mut scope_caps = vec![role_marker(role)];
    scope_caps.extend(capabilities.iter().cloned());
    mark_agent_scope(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        &member.device_prefix,
        &AgentScope {
            capabilities: scope_caps,
            expires_at,
        },
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    Ok(OrgMemberResult {
        member_did: member.device_did.as_str().to_string(),
        member_prefix: member.device_prefix.as_str().to_string(),
    })
}

/// Delegate org membership to a member's **own existing** delegated identity.
///
/// The off-boarding-grade path: the member generated their own key and built a
/// delegated inception (`dip`) naming this org as delegator — the org never holds
/// the member's private key. The org anchors that member-signed `dip` (bilateral
/// `validate_delegation` binding) and a delegator-anchored role + capability scope
/// seal in its own KEL. Use [`add_member`] instead to mint a fresh member key for
/// quick demos.
///
/// Idempotent: re-delegating a member already present in the org's delegation set
/// (live or revoked) is a no-op `Ok` — it never re-appends the `dip`. A revoked
/// member is **not** resurrected; re-instating one requires a fresh delegated
/// identity. Rejects a `kt≥2` org ([`OrgError::OrgThresholdDelegationUnsupported`])
/// and a `dip` that does not name this org as delegator
/// ([`OrgError::MemberNotDelegable`]).
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, passphrase).
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `member_dip`: The member-signed delegated inception (its `di` must equal `org_prefix`).
/// * `member_attachment`: The member's CESR signature attachment over `member_dip`.
/// * `role`: The member's org role (asserted by the org admin).
/// * `capabilities`: Capability strings to grant the member.
/// * `expires_at`: Optional delegator-anchored expiry (Unix epoch seconds).
///
/// Usage:
/// ```ignore
/// // member side (their own key): let bundle = build_device_dip(&org_prefix, curve)?;
/// let member = add_existing_member(&ctx, &org_prefix, &org_alias,
///     &bundle.dip, &bundle.attachment, Role::Member, &["sign_commit".into()], None)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn add_existing_member(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    member_dip: &DipEvent,
    member_attachment: &[u8],
    role: Role,
    capabilities: &[String],
    expires_at: Option<i64>,
) -> Result<OrgMemberResult, OrgError> {
    ensure_single_sig_org(ctx, org_prefix)?;

    let member_prefix = member_dip.i.clone();
    let member_did = format!("did:keri:{}", member_prefix.as_str());

    if member_dip.di.as_str() != org_prefix.as_str() {
        return Err(OrgError::MemberNotDelegable {
            did: member_did,
            org: org_prefix.as_str().to_string(),
        });
    }

    // Idempotent: a member already in the org's delegation set is a no-op (its dip
    // is already anchored — re-appending would duplicate). A revoked member is not
    // resurrected here.
    if resolve_member_authority(ctx, org_prefix, &member_prefix)?.is_some() {
        return Ok(OrgMemberResult {
            member_did,
            member_prefix: member_prefix.as_str().to_string(),
        });
    }

    let (_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    // Anchor the member's own-signed dip on the org KEL (bilateral binding; the
    // org's key signs only the anchoring ixn, never the member key).
    anchor_received_dip(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        member_dip,
        member_attachment,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    let mut scope_caps = vec![role_marker(role)];
    scope_caps.extend(capabilities.iter().cloned());
    mark_agent_scope(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        &member_prefix,
        &AgentScope {
            capabilities: scope_caps,
            expires_at,
        },
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    Ok(OrgMemberResult {
        member_did,
        member_prefix: member_prefix.as_str().to_string(),
    })
}

/// Revoke an org member and emit durable off-boarding evidence.
///
/// Anchors a revocation seal in the org KEL (so verifiers stop honouring the member)
/// and produces a signed, seal-bound [`SignedOffboardingRecord`] — who off-boarded
/// whom, at which **KEL position** (never wall-clock), why, and a snapshot of the
/// role + capabilities the subject lost. Also emits a SIEM `AuditEvent`
/// (`org:offboard-member`) for stream consumers.
///
/// Idempotent: revoking an already-revoked member is a no-op that returns `Ok(None)`
/// without writing a duplicate record. A member the org never delegated is
/// [`OrgError::MemberNotFound`].
///
/// Args:
/// * `ctx`: Auths context.
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `member_did`: The member's `did:keri:` to revoke.
/// * `reason`: Optional operator-supplied reason recorded in the off-boarding record.
///
/// Usage:
/// ```ignore
/// let record = revoke_member(&ctx, &org_prefix, &org_alias, "did:keri:E...", Some("left the company".into()))?;
/// ```
pub fn revoke_member(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    member_did: &str,
    reason: Option<String>,
) -> Result<Option<SignedOffboardingRecord>, OrgError> {
    let member_prefix = parse_did_keri(member_did).map_err(|_| OrgError::MemberNotFound {
        org: org_prefix.as_str().to_string(),
        did: member_did.to_string(),
    })?;

    // Snapshot the member's authority BEFORE revoking — this is "what they lost" —
    // and decide idempotency from the same read.
    let authority =
        resolve_member_authority(ctx, org_prefix, &member_prefix)?.ok_or_else(|| {
            OrgError::MemberNotFound {
                org: org_prefix.as_str().to_string(),
                did: member_did.to_string(),
            }
        })?;
    if authority.revoked {
        // Already off-boarded — no duplicate record.
        return Ok(None);
    }

    let (_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    revoke_delegated_device(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        &member_prefix,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    // Bind the record to the revocation event we just anchored (KEL position + SAID).
    let org_kel = collect_kel(ctx, org_prefix);
    let (revocation_seal_said, revoked_at_seq) = find_revocation_event(&org_kel, &member_prefix)
        .ok_or_else(|| {
            OrgError::Signing("revocation event not found after anchoring".to_string())
        })?;

    let org_did = format!("did:keri:{}", org_prefix.as_str());
    let record = OffboardingRecord {
        org_did: org_did.clone(),
        member_did: member_did.to_string(),
        revoked_at_seq,
        revocation_seal_said,
        reason,
        operator_did: org_did,
        prior_role: authority.role.map(|r| r.as_str().to_string()),
        prior_caps: authority.capabilities,
        recorded_at: ctx.clock.now().to_rfc3339(),
    };

    let signed = sign_offboarding_record(ctx, org_alias, org_curve, record)?;
    store_offboarding_record(ctx, org_prefix, &member_prefix, &signed)?;
    emit_audit(
        ctx,
        &signed.record.operator_did,
        "org:offboard-member",
        "Success",
    );

    Ok(Some(signed))
}

/// A member's KEL-authoritative authority within an org.
#[derive(Debug, Clone)]
pub struct OrgMemberAuthority {
    /// The member's `did:keri:`.
    pub member_did: String,
    /// The member's KEL prefix.
    pub member_prefix: String,
    /// The delegating org's `did:keri:` (KEL-authoritative delegator).
    pub delegated_by_org: String,
    /// Whether the org has revoked the member on its KEL.
    pub revoked: bool,
    /// The member's role (from the delegator-anchored scope seal), if set.
    pub role: Option<Role>,
    /// Capabilities granted by the scope seal.
    pub capabilities: Vec<String>,
    /// Delegator-anchored expiry (Unix epoch seconds), if set.
    pub expires_at: Option<i64>,
}

/// Resolve a member's authority from the org KEL, fail-closed.
///
/// Returns `None` if the org never delegated `member_prefix` (unauthorized) — the
/// KEL is authoritative; an attestation is never consulted. A revoked member
/// resolves to `Some` with `revoked = true` so callers can fail closed.
///
/// Args:
/// * `ctx`: Auths context.
/// * `org_prefix`: The org's KEL prefix.
/// * `member_prefix`: The member's KEL prefix to resolve.
///
/// Usage:
/// ```ignore
/// let authorized = resolve_member_authority(&ctx, &org_prefix, &member_prefix)?
///     .is_some_and(|a| !a.revoked);
/// ```
pub fn resolve_member_authority(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    member_prefix: &Prefix,
) -> Result<Option<OrgMemberAuthority>, OrgError> {
    let delegated =
        list_delegated_devices(ctx.registry.as_ref(), org_prefix).map_err(OrgError::Delegation)?;
    let Some(info) = delegated
        .into_iter()
        .find(|d| d.device_prefix.as_str() == member_prefix.as_str())
    else {
        return Ok(None);
    };

    let org_kel = collect_kel(ctx, org_prefix);
    let scope = read_agent_scope(&org_kel, member_prefix);
    let (role, capabilities) = split_role_and_caps(scope.as_ref());

    Ok(Some(OrgMemberAuthority {
        member_did: format!("did:keri:{}", member_prefix.as_str()),
        member_prefix: member_prefix.as_str().to_string(),
        delegated_by_org: format!("did:keri:{}", org_prefix.as_str()),
        revoked: info.revoked,
        role,
        capabilities,
        expires_at: scope.and_then(|s| s.expires_at),
    }))
}

/// List every member the org has delegated, each with its KEL-authoritative
/// authority (role, capabilities, revocation status). The live set is the
/// non-revoked entries.
///
/// Args:
/// * `ctx`: Auths context.
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// let live = list_members(&ctx, &org_prefix)?.into_iter().filter(|m| !m.revoked).count();
/// ```
pub fn list_members(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
) -> Result<Vec<OrgMemberAuthority>, OrgError> {
    let delegated =
        list_delegated_devices(ctx.registry.as_ref(), org_prefix).map_err(OrgError::Delegation)?;
    let org_kel = collect_kel(ctx, org_prefix);
    let org_did = format!("did:keri:{}", org_prefix.as_str());

    Ok(delegated
        .into_iter()
        .map(|info| {
            let scope = read_agent_scope(&org_kel, &info.device_prefix);
            let (role, capabilities) = split_role_and_caps(scope.as_ref());
            OrgMemberAuthority {
                member_did: format!("did:keri:{}", info.device_prefix.as_str()),
                member_prefix: info.device_prefix.as_str().to_string(),
                delegated_by_org: org_did.clone(),
                revoked: info.revoked,
                role,
                capabilities,
                expires_at: scope.and_then(|s| s.expires_at),
            }
        })
        .collect())
}

/// Build a policy [`EvalContext`] for a member from the org KEL, fail-closed.
///
/// Bridges KEL-authoritative org authority into the policy engine: the context's
/// `delegated_by` is the org AID read from the KEL, and `revoked` reflects the org's
/// KEL revocation — so a policy denies a revoked member regardless of any stale
/// attestation. A member the org never delegated yields a revoked, delegator-less
/// context (policy denies).
///
/// Args:
/// * `ctx`: Auths context.
/// * `org_prefix`: The org's KEL prefix.
/// * `member_prefix`: The member's KEL prefix.
/// * `now`: Current time (injected at the presentation boundary).
///
/// Usage:
/// ```ignore
/// let eval_ctx = member_policy_context(&ctx, &org_prefix, &member_prefix, now)?;
/// let decision = auths_id::policy::evaluate_strict(&policy, &eval_ctx);
/// ```
pub fn member_policy_context(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    member_prefix: &Prefix,
    now: DateTime<Utc>,
) -> Result<EvalContext, OrgError> {
    let org_did = format!("did:keri:{}", org_prefix.as_str());
    let member_did = format!("did:keri:{}", member_prefix.as_str());

    match resolve_member_authority(ctx, org_prefix, member_prefix)? {
        Some(auth) => {
            let expires_at = auth.expires_at.and_then(|s| DateTime::from_timestamp(s, 0));
            context_from_delegated_member(
                &org_did,
                &member_did,
                auth.revoked,
                auth.role.as_ref().map(Role::as_str),
                &auth.capabilities,
                expires_at,
                now,
            )
            .map_err(|e| OrgError::InvalidDid(e.to_string()))
        }
        None => EvalContext::try_from_strings(now, &org_did, &member_did)
            .map(|c| c.revoked(true))
            .map_err(|e| OrgError::InvalidDid(e.to_string())),
    }
}
