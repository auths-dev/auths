//! Organization membership workflows: Role definitions and member sorting.

use std::ops::ControlFlow;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_id::ports::registry::RegistryBackend;
use auths_verifier::Capability;
use auths_verifier::core::{Attestation, Ed25519PublicKey};
pub use auths_verifier::core::Role;
use auths_verifier::core::ResourceId;
use auths_verifier::types::{DeviceDID, IdentityDID};

use crate::error::OrgError;

/// Ordering key for org member display: admin < member < readonly < unknown.
///
/// Args:
/// * `role`: Optional role as stored in an attestation.
///
/// Usage:
/// ```ignore
/// members.sort_by(|a, b| member_role_order(&a.role).cmp(&member_role_order(&b.role)));
/// ```
pub fn member_role_order(role: &Option<Role>) -> u8 {
    match role {
        Some(Role::Admin) => 0,
        Some(Role::Member) => 1,
        Some(Role::Readonly) => 2,
        None => 3,
    }
}

/// Find the first org-member attestation whose device public key matches `public_key_hex`
/// and which holds the `manage_members` capability.
///
/// O(n) scan — acceptable because `RegistryBackend` is frozen and the visitor
/// short-circuits on the first match via `ControlFlow::Break`.
///
/// Args:
/// * `backend`: Registry backend to query.
/// * `org_prefix`: The KERI method-specific ID of the organization (e.g. `EOrg1234567890`).
/// * `public_key_hex`: Hex-encoded device public key of the candidate admin.
///
/// Usage:
/// ```ignore
/// let admin = find_admin(backend, "EOrg1234567890", &pubkey_hex)?;
/// ```
pub(crate) fn find_admin(
    backend: &dyn RegistryBackend,
    org_prefix: &str,
    public_key_hex: &str,
) -> Result<Attestation, OrgError> {
    let signer_bytes = hex::decode(public_key_hex)
        .map_err(|e| OrgError::InvalidPublicKey(format!("hex decode failed: {e}")))?;

    let mut found: Option<Attestation> = None;

    backend
        .visit_org_member_attestations(org_prefix, &mut |entry| {
            if let Ok(att) = &entry.attestation
                && att.device_public_key.as_bytes().as_slice() == signer_bytes.as_slice()
                && !att.is_revoked()
                && att.capabilities.contains(&Capability::manage_members())
            {
                found = Some(att.clone());
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    found.ok_or_else(|| OrgError::AdminNotFound {
        org: org_prefix.to_owned(),
    })
}

/// Find a member's current attestation by their DID within an org.
///
/// O(n) scan — short-circuits on first match via `ControlFlow::Break`.
///
/// Args:
/// * `backend`: Registry backend to query.
/// * `org_prefix`: The KERI method-specific ID of the organization (e.g. `EOrg1234567890`).
/// * `member_did`: Full DID of the member to look up (e.g. `did:key:z6Mk...`).
///
/// Usage:
/// ```ignore
/// let att = find_member(backend, "EOrg1234567890", "did:key:z6Mk...")?;
/// ```
pub(crate) fn find_member(
    backend: &dyn RegistryBackend,
    org_prefix: &str,
    member_did: &str,
) -> Result<Option<Attestation>, OrgError> {
    let mut found: Option<Attestation> = None;

    backend
        .visit_org_member_attestations(org_prefix, &mut |entry| {
            if entry.did.to_string() == member_did
                && let Ok(att) = &entry.attestation
            {
                found = Some(att.clone());
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(found)
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

fn parse_capabilities(raw: &[String]) -> Result<Vec<Capability>, OrgError> {
    raw.iter()
        .map(|s| {
            Capability::try_from(s.clone()).map_err(|e| OrgError::InvalidCapability {
                cap: s.clone(),
                reason: e.to_string(),
            })
        })
        .collect()
}

// ── Command structs ───────────────────────────────────────────────────────────

/// Command to add a new member to an organization.
pub struct AddMemberCommand {
    /// KERI method-specific ID of the org (e.g. `EOrg1234567890`).
    pub org_prefix: String,
    /// Full DID of the member being added (e.g. `did:key:z6Mk...`).
    pub member_did: String,
    /// Role to assign.
    pub role: Role,
    /// Capability strings to grant (e.g. `["sign_commit"]`).
    pub capabilities: Vec<String>,
    /// Hex-encoded device public key of the signing admin.
    pub public_key_hex: String,
}

/// Command to revoke an existing org member.
pub struct RevokeMemberCommand {
    /// KERI method-specific ID of the org (e.g. `EOrg1234567890`).
    pub org_prefix: String,
    /// Full DID of the member to revoke.
    pub member_did: String,
    /// Hex-encoded device public key of the signing admin.
    pub public_key_hex: String,
}

/// Command to update the capability set of an org member.
pub struct UpdateCapabilitiesCommand {
    /// KERI method-specific ID of the org (e.g. `EOrg1234567890`).
    pub org_prefix: String,
    /// Full DID of the member whose capabilities will be updated.
    pub member_did: String,
    /// New capability strings (replaces existing set).
    pub capabilities: Vec<String>,
    /// Hex-encoded device public key of the signing admin.
    pub public_key_hex: String,
}

// ── Workflow functions ────────────────────────────────────────────────────────

/// Add a new member to an organization.
///
/// Verifies that the signer holds the `manage_members` capability, then
/// stores a new org-member attestation. The attestation is intentionally
/// unsigned (empty `identity_signature`, `device_signature`, `device_public_key`).
///
/// Args:
/// * `backend`: Registry backend for storage.
/// * `clock`: Clock provider for the attestation timestamp.
/// * `id_provider`: UUID provider for the `rid` field.
/// * `cmd`: Add-member command containing org prefix, member DID, role, and capabilities.
///
/// Usage:
/// ```ignore
/// let att = add_organization_member(backend, clock, uuid_provider, cmd)?;
/// ```
pub fn add_organization_member(
    backend: &dyn RegistryBackend,
    clock: &dyn ClockProvider,
    id_provider: &dyn UuidProvider,
    cmd: AddMemberCommand,
) -> Result<Attestation, OrgError> {
    let admin_att = find_admin(backend, &cmd.org_prefix, &cmd.public_key_hex)?;
    let parsed_caps = parse_capabilities(&cmd.capabilities)?;

    let member = Attestation {
        version: 1,
        rid: ResourceId::new(id_provider.new_id().to_string()),
        issuer: admin_att.issuer.clone(),
        subject: DeviceDID::new(&cmd.member_did),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        identity_signature: vec![],
        device_signature: vec![],
        revoked_at: None,
        expires_at: None,
        timestamp: Some(clock.now()),
        note: None,
        payload: None,
        role: Some(cmd.role),
        capabilities: parsed_caps,
        delegated_by: Some(IdentityDID::new(admin_att.subject.to_string())),
        signer_type: None,
    };

    backend
        .store_org_member(&cmd.org_prefix, &member)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(member)
}

/// Revoke an existing org member.
///
/// Verifies that the signer holds `manage_members`, checks the member exists
/// and is not already revoked, then sets `revoked_at` and re-stores.
///
/// Args:
/// * `backend`: Registry backend for storage.
/// * `clock`: Clock provider for the revocation timestamp.
/// * `cmd`: Revoke-member command containing org prefix and member DID.
///
/// Usage:
/// ```ignore
/// let revoked = revoke_organization_member(backend, clock, cmd)?;
/// ```
pub fn revoke_organization_member(
    backend: &dyn RegistryBackend,
    clock: &dyn ClockProvider,
    cmd: RevokeMemberCommand,
) -> Result<Attestation, OrgError> {
    find_admin(backend, &cmd.org_prefix, &cmd.public_key_hex)?;

    let existing = find_member(backend, &cmd.org_prefix, &cmd.member_did)?.ok_or_else(|| {
        OrgError::MemberNotFound {
            org: cmd.org_prefix.clone(),
            did: cmd.member_did.clone(),
        }
    })?;

    if existing.is_revoked() {
        return Err(OrgError::AlreadyRevoked {
            did: cmd.member_did.clone(),
        });
    }

    let now = clock.now();
    let mut revoked = existing;
    revoked.revoked_at = Some(now);
    revoked.timestamp = Some(now);
    revoked.note = Some("Revoked by admin".to_owned());

    backend
        .store_org_member(&cmd.org_prefix, &revoked)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(revoked)
}

/// Update the capability set of an org member.
///
/// Verifies that the signer holds `manage_members`, checks the member exists
/// and is not revoked, replaces their capability set, and re-stores.
///
/// Args:
/// * `backend`: Registry backend for storage.
/// * `clock`: Clock provider for the update timestamp.
/// * `cmd`: Update-capabilities command containing org prefix, member DID, and new capabilities.
///
/// Usage:
/// ```ignore
/// let updated = update_member_capabilities(backend, clock, cmd)?;
/// ```
pub fn update_member_capabilities(
    backend: &dyn RegistryBackend,
    clock: &dyn ClockProvider,
    cmd: UpdateCapabilitiesCommand,
) -> Result<Attestation, OrgError> {
    find_admin(backend, &cmd.org_prefix, &cmd.public_key_hex)?;

    let existing = find_member(backend, &cmd.org_prefix, &cmd.member_did)?.ok_or_else(|| {
        OrgError::MemberNotFound {
            org: cmd.org_prefix.clone(),
            did: cmd.member_did.clone(),
        }
    })?;

    if existing.is_revoked() {
        return Err(OrgError::AlreadyRevoked {
            did: cmd.member_did.clone(),
        });
    }

    let parsed_caps = parse_capabilities(&cmd.capabilities)?;
    let mut updated = existing;
    updated.capabilities = parsed_caps;
    updated.timestamp = Some(clock.now());

    backend
        .store_org_member(&cmd.org_prefix, &updated)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(updated)
}
