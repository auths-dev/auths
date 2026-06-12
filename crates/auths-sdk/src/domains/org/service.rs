//! Organization member lookups.
//!
//! KERI-native membership — adding, revoking, listing, and authority resolution —
//! lives in [`crate::domains::org::delegation`], where a member is a `dip`
//! delegated by the org AID (authority is KEL-authoritative and fail-closed). This
//! module retains member-lookup helpers that accept an [`OrgContext`] carrying
//! injected infrastructure adapters (registry, clock, signer, passphrase provider).

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::attestation::create::{AttestationInput, create_signed_attestation};
use auths_id::keri::{parse_did_keri, try_stage_anchor};
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::backend::AtomicWriteBatch;
use auths_id::witness_config::WitnessParams;
use auths_verifier::core::Attestation;
pub use auths_verifier::core::Role;
use auths_verifier::types::CanonicalDid;
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::domains::org::error::OrgError;
use crate::identity::initialize_registry_identity;

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

/// Outcome of creating a new organization identity.
#[derive(Debug, Clone)]
pub struct OrgCreated {
    /// The org's `did:keri:` (self-certifying — derived from its inception SAID).
    pub org_did: String,
    /// The org's KEL prefix.
    pub org_prefix: String,
    /// The admin DID anchored by the self-attestation (equal to `org_did` for a
    /// single-controller org).
    pub admin_did: String,
    /// Keychain alias the org's signing key was stored under.
    pub key_alias: String,
    /// Resolved org metadata (`type`/`name`/`created_at` plus any merged extras).
    pub metadata: serde_json::Value,
}

/// Build the org's descriptive metadata, merging caller-supplied extras.
///
/// `type` and `name` are reserved and never overwritten by `extra`.
fn build_org_metadata(
    name: &str,
    now: DateTime<Utc>,
    extra: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "type": "org",
        "name": name,
        "created_at": now.to_rfc3339(),
    });
    if let Some(serde_json::Value::Object(add)) = extra
        && let Some(base) = metadata.as_object_mut()
    {
        for (k, v) in add {
            if k != "type" && k != "name" {
                base.insert(k, v);
            }
        }
    }
    metadata
}

/// Create a new organization as a self-certifying KERI identity.
///
/// Mints a `kt=1` org AID via the registry backend and anchors a self-signed admin
/// attestation in the org's KEL — the same on-disk layout the inline CLI path
/// produced, now reusable by the CLI, Node, and Python surfaces and by the
/// deployment kit for programmatic provisioning. The clock is read from
/// `ctx.clock`; no `Utc::now()` is called in domain code. Fails closed if an
/// identity already exists in the context's registry.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, clock, passphrase provider).
/// * `name`: Human-readable organization name (recorded in the admin attestation).
/// * `admin_alias`: Keychain alias to store the org's signing key under.
/// * `curve`: Signing curve for the org's inception key.
/// * `metadata`: Optional extra metadata merged into the org descriptor.
///
/// Usage:
/// ```ignore
/// let created = create_org(&ctx, "Acme Security", &alias, CurveType::default(), None)?;
/// println!("org: {}", created.org_did);
/// ```
pub fn create_org(
    ctx: &AuthsContext,
    name: &str,
    admin_alias: &KeyAlias,
    curve: auths_crypto::CurveType,
    metadata: Option<serde_json::Value>,
) -> Result<OrgCreated, OrgError> {
    let now = ctx.clock.now();

    if ctx.identity_storage.load_identity().is_ok() {
        return Err(OrgError::IdentityExists {
            location: ctx
                .repo_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "the registry".to_string()),
        });
    }

    let metadata_json = build_org_metadata(name, now, metadata);

    let (controller_did, alias) = initialize_registry_identity(
        Arc::clone(&ctx.registry),
        admin_alias,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
        ctx.witness_config.as_ref(),
        curve,
    )
    .map_err(OrgError::IdentityInit)?;

    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| OrgError::Identity(e.to_string()))?;
    let rid = managed.storage_id;

    let (org_pk_bytes, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        admin_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    let signer = StorageSigner::new(Arc::clone(&ctx.key_storage));

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: controller_did is freshly minted by inception — a valid did:keri
    let org_did = CanonicalDid::new_unchecked(controller_did.to_string());

    let meta = AttestationMetadata {
        note: Some(format!("Organization '{name}' root admin")),
        timestamp: Some(now),
        expires_at: None,
    };

    let attestation = create_signed_attestation(
        now,
        AttestationInput {
            rid: &rid,
            identity_did: &controller_did,
            subject: &org_did,
            device_public_key: &org_pk_bytes,
            device_curve: org_curve,
            payload: Some(serde_json::json!({ "org_role": "admin", "org_name": name })),
            meta: &meta,
            identity_alias: Some(&alias),
            device_alias: None,
            delegated_by: None,
            commit_sha: None,
            signer_type: None,
            oidc_binding: None,
        },
        &signer,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::Attestation)?;

    let org_prefix =
        parse_did_keri(controller_did.as_str()).map_err(|e| OrgError::InvalidDid(e.to_string()))?;

    let mut batch = AtomicWriteBatch::new();
    batch.stage_attestation(attestation);
    try_stage_anchor(
        ctx.registry.as_ref(),
        &signer,
        &alias,
        ctx.passphrase_provider.as_ref(),
        &org_prefix,
        &serde_json::json!({}),
        &mut batch,
    )?;
    ctx.registry
        .commit_batch(&batch)
        .map_err(OrgError::Storage)?;

    Ok(OrgCreated {
        org_did: controller_did.to_string(),
        org_prefix: org_prefix.as_str().to_string(),
        admin_did: org_did.to_string(),
        key_alias: alias.as_str().to_string(),
        metadata: metadata_json,
    })
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
