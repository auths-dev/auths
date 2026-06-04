//! Organization member capability/role updates and lookups.
//!
//! KERI-native membership — adding, revoking, listing, and authority resolution —
//! lives in [`crate::domains::org::delegation`], where a member is a `dip`
//! delegated by the org AID (authority is KEL-authoritative and fail-closed). This
//! module retains the attestation-based capability/role *update* helpers, which
//! accept an [`OrgContext`] carrying injected infrastructure adapters (registry,
//! clock, signer, passphrase provider).

use std::ops::ControlFlow;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_id::keri::anchor_and_persist_via_backend;
use auths_id::ports::registry::RegistryBackend;
use auths_id::witness_config::WitnessParams;
use auths_verifier::Capability;
use auths_verifier::PublicKeyHex;
use auths_verifier::core::Attestation;
pub use auths_verifier::core::Role;

use crate::domains::org::error::OrgError;

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
/// let att = update_organization_member(&ctx, cmd)?;
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
    /// Witness receipting configuration for KEL event anchoring.
    pub witness_params: WitnessParams<'a>,
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
    public_key_hex: &PublicKeyHex,
) -> Result<Attestation, OrgError> {
    let signer_bytes = hex::decode(public_key_hex.as_str())
        .map_err(|e| OrgError::InvalidPublicKey(format!("hex decode failed: {e}")))?;

    let mut found: Option<Attestation> = None;

    backend
        .visit_org_member_attestations(org_prefix, &mut |entry| {
            if let Ok(att) = &entry.attestation
                && {
                    use subtle::ConstantTimeEq;
                    bool::from(
                        att.device_public_key
                            .as_bytes()
                            .ct_eq(signer_bytes.as_slice()),
                    )
                }
                && !att.is_revoked()
                && att.capabilities.contains(&Capability::manage_members())
            {
                found = Some(att.clone());
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .map_err(OrgError::Storage)?;

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
            if entry.did.as_str() == member_did
                && let Ok(att) = &entry.attestation
            {
                found = Some(att.clone());
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .map_err(OrgError::Storage)?;

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

/// Command to update the capability set of an org member.
pub struct UpdateCapabilitiesCommand {
    /// KERI method-specific ID of the org.
    pub org_prefix: String,
    /// Full DID of the member whose capabilities are being updated.
    pub member_did: String,
    /// New capability strings to replace the existing set.
    pub capabilities: Vec<String>,
    /// Hex-encoded public key of the admin performing the update.
    pub public_key_hex: PublicKeyHex,
    /// Keychain alias of the admin's signing key (for KEL anchoring).
    pub signer_alias: KeyAlias,
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
    pub admin_public_key_hex: PublicKeyHex,
    /// Keychain alias of the admin's signing key (for KEL anchoring).
    pub signer_alias: KeyAlias,
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
    ctx: &OrgContext,
    cmd: UpdateCapabilitiesCommand,
) -> Result<Attestation, OrgError> {
    find_admin(ctx.registry, &cmd.org_prefix, &cmd.public_key_hex)?;

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

    let parsed_caps = parse_capabilities(&cmd.capabilities)?;
    let mut updated = existing;
    updated.capabilities = parsed_caps;
    let now = ctx.clock.now();
    updated.timestamp = Some(now);

    let org_keri_prefix = auths_id::keri::Prefix::new_unchecked(cmd.org_prefix);
    let mut batch = auths_id::storage::registry::backend::AtomicWriteBatch::new();
    batch.stage_org_member(org_keri_prefix.as_str(), updated.clone());
    anchor_and_persist_via_backend(
        ctx.registry,
        ctx.signer,
        &cmd.signer_alias,
        ctx.passphrase_provider,
        &org_keri_prefix,
        &updated,
        &mut batch,
        &ctx.witness_params,
        now,
    )?;

    Ok(updated)
}

/// Atomically update a member's role and/or capabilities in a single operation.
///
/// Unlike the current pattern of revoke+re-add, this performs an in-place update
/// to prevent partial state on failure.
pub fn update_organization_member(
    ctx: &OrgContext,
    cmd: UpdateMemberCommand,
) -> Result<Attestation, OrgError> {
    find_admin(ctx.registry, &cmd.org_prefix, &cmd.admin_public_key_hex)?;

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

    let mut updated = existing;

    if let Some(caps) = cmd.capabilities {
        updated.capabilities = parse_capabilities(&caps)?;
    }
    if let Some(role) = cmd.role {
        updated.role = Some(role);
    }
    let now = ctx.clock.now();
    updated.timestamp = Some(now);

    let org_keri_prefix = auths_id::keri::Prefix::new_unchecked(cmd.org_prefix);
    let mut batch = auths_id::storage::registry::backend::AtomicWriteBatch::new();
    batch.stage_org_member(org_keri_prefix.as_str(), updated.clone());
    anchor_and_persist_via_backend(
        ctx.registry,
        ctx.signer,
        &cmd.signer_alias,
        ctx.passphrase_provider,
        &org_keri_prefix,
        &updated,
        &mut batch,
        &ctx.witness_params,
        now,
    )?;

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
