//! Organization member lookups.
//!
//! KERI-native membership — adding, revoking, listing, and authority resolution —
//! lives in [`crate::domains::org::delegation`], where a member is a `dip`
//! delegated by the org AID (authority is KEL-authoritative and fail-closed). This
//! module retains member-lookup helpers that accept an [`OrgContext`] carrying
//! injected infrastructure adapters (registry, clock, signer, passphrase provider).

use std::ops::ControlFlow;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_id::ports::registry::RegistryBackend;
use auths_id::witness_config::WitnessParams;
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

// ── Command structs ───────────────────────────────────────────────────────────

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
