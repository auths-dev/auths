//! Organization membership workflows: add, revoke, update, and list members.
//!
//! All workflows accept an [`OrgContext`] carrying injected infrastructure
//! adapters (registry, clock, signer, passphrase provider). The CLI constructs
//! this context at the presentation boundary; tests inject fakes.

use std::ops::ControlFlow;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_id::attestation::create::create_signed_attestation;
use auths_id::attestation::revoke::create_signed_revocation;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_verifier::Capability;
pub use auths_verifier::core::Role;
use auths_verifier::core::{Attestation, Ed25519PublicKey};
use auths_verifier::types::{DeviceDID, IdentityDID};

use crate::error::OrgError;

/// Runtime dependency container for organization workflows.
///
/// Bundles all injected infrastructure adapters needed by org operations.
/// The CLI constructs this from real implementations; tests inject fakes.
///
/// Args:
/// * `registry`: Backend for reading/writing org member attestations.
/// * `clock`: Wall-clock provider (use `SystemClock` in production, `MockClock` in tests).
/// * `uuid_provider`: UUID generator for attestation resource IDs.
/// * `signer`: Signing backend for creating cryptographic signatures.
/// * `passphrase_provider`: Provider for obtaining key decryption passphrases.
///
/// Usage:
/// ```ignore
/// let ctx = OrgContext {
///     registry: &backend,
///     clock: &SystemClock,
///     uuid_provider: &uuid_provider,
///     signer: &signer,
///     passphrase_provider: passphrase_provider.as_ref(),
/// };
/// let att = add_organization_member(&ctx, cmd)?;
/// ```
pub struct OrgContext<'a> {
    /// Backend for reading/writing org member attestations.
    pub registry: &'a dyn RegistryBackend,
    /// Wall-clock provider (use `SystemClock` in production, `MockClock` in tests).
    pub clock: &'a dyn ClockProvider,
    /// UUID generator for attestation resource IDs.
    pub uuid_provider: &'a dyn UuidProvider,
    /// Signing backend for creating cryptographic signatures.
    pub signer: &'a dyn SecureSigner,
    /// Provider for obtaining key decryption passphrases.
    pub passphrase_provider: &'a dyn PassphraseProvider,
}

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
/// Args:
/// * `backend`: Registry backend to query.
/// * `org_prefix`: The KERI method-specific ID of the organization.
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
/// Args:
/// * `backend`: Registry backend to query.
/// * `org_prefix`: The KERI method-specific ID of the organization.
/// * `member_did`: Full DID of the member to look up.
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
///
/// Args:
/// * `org_prefix`: KERI method-specific ID of the org.
/// * `member_did`: Full DID of the member being added.
/// * `member_public_key`: Ed25519 public key of the member.
/// * `role`: Role to assign.
/// * `capabilities`: Capability strings to grant.
/// * `admin_public_key_hex`: Hex-encoded public key of the signing admin.
/// * `signer_alias`: Keychain alias of the admin's signing key.
/// * `note`: Optional note for the attestation.
///
/// Usage:
/// ```ignore
/// let cmd = AddMemberCommand {
///     org_prefix: "EOrg1234567890".into(),
///     member_did: "did:key:z6Mk...".into(),
///     member_public_key: Ed25519PublicKey::from_bytes(pk_bytes),
///     role: Role::Member,
///     capabilities: vec!["sign_commit".into()],
///     admin_public_key_hex: hex::encode(&admin_pk),
///     signer_alias: KeyAlias::new_unchecked("org-myorg"),
///     note: Some("Added by admin".into()),
/// };
/// ```
pub struct AddMemberCommand {
    /// KERI method-specific ID of the org.
    pub org_prefix: String,
    /// Full DID of the member being added.
    pub member_did: String,
    /// Ed25519 public key of the member.
    pub member_public_key: Ed25519PublicKey,
    /// Role to assign.
    pub role: Role,
    /// Capability strings to grant.
    pub capabilities: Vec<String>,
    /// Hex-encoded public key of the signing admin.
    pub admin_public_key_hex: String,
    /// Keychain alias of the admin's signing key.
    pub signer_alias: KeyAlias,
    /// Optional note for the attestation.
    pub note: Option<String>,
}

/// Command to revoke an existing org member.
///
/// Args:
/// * `org_prefix`: KERI method-specific ID of the org.
/// * `member_did`: Full DID of the member to revoke.
/// * `member_public_key`: Ed25519 public key of the member (from existing attestation).
/// * `admin_public_key_hex`: Hex-encoded public key of the signing admin.
/// * `signer_alias`: Keychain alias of the admin's signing key.
/// * `note`: Optional reason for revocation.
///
/// Usage:
/// ```ignore
/// let cmd = RevokeMemberCommand {
///     org_prefix: "EOrg1234567890".into(),
///     member_did: "did:key:z6Mk...".into(),
///     member_public_key: Ed25519PublicKey::from_bytes(pk_bytes),
///     admin_public_key_hex: hex::encode(&admin_pk),
///     signer_alias: KeyAlias::new_unchecked("org-myorg"),
///     note: Some("Policy violation".into()),
/// };
/// ```
pub struct RevokeMemberCommand {
    /// KERI method-specific ID of the org.
    pub org_prefix: String,
    /// Full DID of the member to revoke.
    pub member_did: String,
    /// Ed25519 public key of the member (from existing attestation).
    pub member_public_key: Ed25519PublicKey,
    /// Hex-encoded public key of the signing admin.
    pub admin_public_key_hex: String,
    /// Keychain alias of the admin's signing key.
    pub signer_alias: KeyAlias,
    /// Optional reason for revocation.
    pub note: Option<String>,
}

/// Command to update the capability set of an org member.
pub struct UpdateCapabilitiesCommand {
    /// KERI method-specific ID of the org.
    pub org_prefix: String,
    /// Full DID of the member whose capabilities are being updated.
    pub member_did: String,
    /// New capability strings to replace the existing set.
    pub capabilities: Vec<String>,
    /// Hex-encoded public key of the admin performing the update.
    pub public_key_hex: String,
}

/// Command to atomically update a member's role and capabilities.
///
/// Unlike separate revoke+add, this is a single atomic operation that
/// prevents partial state if one step fails.
pub struct UpdateMemberCommand {
    /// KERI method-specific ID of the org.
    pub org_prefix: String,
    /// Full DID of the member being updated.
    pub member_did: String,
    /// New role (if changing).
    pub role: Option<Role>,
    /// New capability strings (if changing).
    pub capabilities: Option<Vec<String>>,
    /// Hex-encoded public key of the admin performing the update.
    pub admin_public_key_hex: String,
}

/// Accepts either a KERI prefix or a full DID.
///
/// Auto-detected by whether the string starts with `did:`.
#[derive(Debug, Clone)]
pub enum OrgIdentifier {
    /// Bare KERI prefix (e.g. `EOrg1234567890`).
    Prefix(String),
    /// Full DID (e.g. `did:keri:EOrg1234567890`).
    Did(String),
}

impl OrgIdentifier {
    /// Parse a string into an `OrgIdentifier`, auto-detecting the format.
    pub fn parse(s: &str) -> Self {
        if s.starts_with("did:") {
            OrgIdentifier::Did(s.to_owned())
        } else {
            OrgIdentifier::Prefix(s.to_owned())
        }
    }

    /// Extract the KERI prefix regardless of format.
    pub fn prefix(&self) -> &str {
        match self {
            OrgIdentifier::Prefix(p) => p,
            OrgIdentifier::Did(d) => d.strip_prefix("did:keri:").unwrap_or(d),
        }
    }
}

impl From<&str> for OrgIdentifier {
    fn from(s: &str) -> Self {
        OrgIdentifier::parse(s)
    }
}

// ── Workflow functions ────────────────────────────────────────────────────────

/// Add a new member to an organization with a cryptographically signed attestation.
///
/// Verifies that the signer holds the `manage_members` capability, creates a
/// signed attestation via `create_signed_attestation` from auths-id, and stores
/// the result in the registry backend.
///
/// Args:
/// * `ctx`: Organization context with injected infrastructure adapters.
/// * `cmd`: Add-member command with org prefix, member DID, role, and capabilities.
///
/// Usage:
/// ```ignore
/// let att = add_organization_member(&ctx, cmd)?;
/// println!("Added member: {}", att.subject);
/// ```
pub fn add_organization_member(
    ctx: &OrgContext,
    cmd: AddMemberCommand,
) -> Result<Attestation, OrgError> {
    let admin_att = find_admin(ctx.registry, &cmd.org_prefix, &cmd.admin_public_key_hex)?;
    let parsed_caps = parse_capabilities(&cmd.capabilities)?;
    let now = ctx.clock.now();
    let rid = ctx.uuid_provider.new_id().to_string();

    let member_did = DeviceDID::new_unchecked(&cmd.member_did);
    let meta = AttestationMetadata {
        note: cmd
            .note
            .or_else(|| Some(format!("Added as {} by {}", cmd.role, admin_att.subject))),
        timestamp: Some(now),
        expires_at: None,
    };

    let attestation = create_signed_attestation(
        now,
        &rid,
        &admin_att.issuer,
        &member_did,
        cmd.member_public_key.as_bytes(),
        Some(serde_json::json!({
            "org_role": cmd.role.to_string(),
            "org_did": format!("did:keri:{}", cmd.org_prefix),
        })),
        &meta,
        ctx.signer,
        ctx.passphrase_provider,
        Some(&cmd.signer_alias),
        None,
        parsed_caps,
        Some(cmd.role),
        Some(IdentityDID::new_unchecked(admin_att.subject.to_string())),
    )
    .map_err(|e| OrgError::Signing(e.to_string()))?;

    ctx.registry
        .store_org_member(&cmd.org_prefix, &attestation)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(attestation)
}

/// Revoke an existing org member with a cryptographically signed revocation.
///
/// Verifies that the signer holds `manage_members`, checks the member exists
/// and is not already revoked, then creates a signed revocation attestation
/// via `create_signed_revocation` from auths-id.
///
/// Args:
/// * `ctx`: Organization context with injected infrastructure adapters.
/// * `cmd`: Revoke-member command with org prefix and member DID.
///
/// Usage:
/// ```ignore
/// let revoked = revoke_organization_member(&ctx, cmd)?;
/// assert!(revoked.is_revoked());
/// ```
pub fn revoke_organization_member(
    ctx: &OrgContext,
    cmd: RevokeMemberCommand,
) -> Result<Attestation, OrgError> {
    let admin_att = find_admin(ctx.registry, &cmd.org_prefix, &cmd.admin_public_key_hex)?;

    let existing =
        find_member(ctx.registry, &cmd.org_prefix, &cmd.member_did)?.ok_or_else(|| {
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

    let now = ctx.clock.now();
    let member_did = DeviceDID::new_unchecked(&cmd.member_did);

    let revocation = create_signed_revocation(
        admin_att.rid.as_str(),
        &admin_att.issuer,
        &member_did,
        cmd.member_public_key.as_bytes(),
        cmd.note,
        None,
        now,
        ctx.signer,
        ctx.passphrase_provider,
        &cmd.signer_alias,
    )
    .map_err(|e| OrgError::Signing(e.to_string()))?;

    ctx.registry
        .store_org_member(&cmd.org_prefix, &revocation)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(revocation)
}

/// Update the capability set of an org member.
///
/// Verifies that the signer holds `manage_members`, checks the member exists
/// and is not revoked, replaces their capability set, and re-stores.
///
/// Args:
/// * `backend`: Registry backend for storage.
/// * `clock`: Clock provider for the update timestamp.
/// * `cmd`: Update-capabilities command with org prefix, member DID, and new capabilities.
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

/// Atomically update a member's role and/or capabilities in a single operation.
///
/// Unlike the current pattern of revoke+re-add, this performs an in-place update
/// to prevent partial state on failure.
pub fn update_organization_member(
    backend: &dyn RegistryBackend,
    clock: &dyn ClockProvider,
    cmd: UpdateMemberCommand,
) -> Result<Attestation, OrgError> {
    find_admin(backend, &cmd.org_prefix, &cmd.admin_public_key_hex)?;

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

    let mut updated = existing;

    if let Some(caps) = cmd.capabilities {
        updated.capabilities = parse_capabilities(&caps)?;
    }
    if let Some(role) = cmd.role {
        updated.role = Some(role);
    }
    updated.timestamp = Some(clock.now());

    backend
        .store_org_member(&cmd.org_prefix, &updated)
        .map_err(|e| OrgError::Storage(e.to_string()))?;

    Ok(updated)
}

/// Look up a single org member by DID (O(1) with the right backend).
pub fn get_organization_member(
    backend: &dyn RegistryBackend,
    org_prefix: &str,
    member_did: &str,
) -> Result<Attestation, OrgError> {
    find_member(backend, org_prefix, member_did)?.ok_or_else(|| OrgError::MemberNotFound {
        org: org_prefix.to_owned(),
        did: member_did.to_owned(),
    })
}
