//! KEL-anchored OIDC-subject policy — the org's witnessed log as the policy's
//! source of truth.
//!
//! An [`OidcSubjectPolicy`] states WHICH workload identity may sign keylessly
//! for the org. Handing it to verifiers as a pinned file gives policy
//! distribution and rotation no audit trail; anchoring it on the org KEL does:
//! the policy JSON is stored as a **content-addressed blob** in the org's
//! credential namespace, and only its SHA-256 digest rides the KEL (an
//! `oidcpolicy:{digest}` seal). Every policy change is a witnessed KEL event,
//! and the binding is **tamper-evident**: [`load_org_oidc_policy`] recomputes
//! the loaded blob's digest and refuses a mismatch.
//!
//! Parse, don't validate: a policy that does not parse as an
//! [`OidcSubjectPolicy`] is never anchored, and a load returns the parsed type
//! — callers never re-check raw JSON.
//!
//! Anchoring requires a single-signature (`kt=1`) org — the anchoring `ixn` is
//! single-author, matching [`super::policy`] and [`super::delegation`].

use std::ops::ControlFlow;

use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::keri::delegation::{mark_org_oidc_policy, read_org_oidc_policy_digest};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Said};
use auths_id::ports::registry::RegistryBackend;
use auths_verifier::oidc_policy::OidcSubjectPolicy;
use sha2::{Digest, Sha256};

use crate::context::AuthsContext;
use crate::domains::org::delegation::ensure_single_sig_org;
use crate::domains::org::error::OrgError;

/// The result of anchoring an org's OIDC-subject policy.
#[derive(Debug, Clone)]
pub struct OrgOidcPolicySet {
    /// The org's `did:keri:`.
    pub org_did: String,
    /// Lowercase-hex SHA-256 digest of the policy source. Anchored on the KEL.
    pub policy_digest: String,
    /// The parsed policy that was anchored.
    pub policy: OidcSubjectPolicy,
}

/// An OIDC-subject policy resolved from the org KEL, digest-checked and parsed.
#[derive(Debug, Clone)]
pub struct LoadedOrgOidcPolicy {
    /// The parsed policy, ready to JOIN against a signed OIDC binding.
    pub policy: OidcSubjectPolicy,
    /// Lowercase-hex SHA-256 digest (matches the on-KEL `oidcpolicy:` seal).
    pub policy_digest: String,
    /// The raw policy source JSON (for display).
    pub source_json: String,
}

/// Lowercase-hex SHA-256 of a policy's exact source bytes — the ONE digest both
/// the anchor writer and the loader compute.
fn oidc_policy_digest(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

/// Content-addressed blob key for an OIDC-subject policy of the given digest.
/// Namespaced (`oidcpolicy-{digest}`) so it never collides with the `policy-`
/// blobs or the member-prefix-keyed off-boarding records in the same store.
fn oidc_policy_blob_key(digest_hex: &str) -> Said {
    Said::new_unchecked(format!("oidcpolicy-{digest_hex}"))
}

/// Anchor an org's OIDC-subject policy: parse it, store the source JSON as a
/// content-addressed blob, and seal its digest on the org KEL.
///
/// Fail-closed: a policy that does not parse is **never** anchored
/// ([`OrgError::OidcPolicyInvalid`]). Re-anchoring seals a new digest; the
/// latest wins on load — rotation is an auditable KEL event. Requires a
/// single-signature org.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, passphrase).
/// * `org_prefix`: The org's KEL prefix (the policy authority).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `policy_json`: The policy JSON (issuer + repository, optional workflow_ref).
///
/// Usage:
/// ```ignore
/// let set = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, policy_json)?;
/// println!("anchored OIDC policy {}", set.policy_digest);
/// ```
pub fn set_org_oidc_policy(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    policy_json: &[u8],
) -> Result<OrgOidcPolicySet, OrgError> {
    ensure_single_sig_org(ctx, org_prefix)?;

    // Parse first — an invalid policy is never anchored.
    let source = std::str::from_utf8(policy_json).map_err(|e| OrgError::OidcPolicyInvalid {
        reason: e.to_string(),
    })?;
    let policy = OidcSubjectPolicy::parse(source).map_err(|e| OrgError::OidcPolicyInvalid {
        reason: e.to_string(),
    })?;
    let digest_hex = oidc_policy_digest(policy_json);

    // The source JSON lives off-KEL in a content-addressed blob; only the digest
    // is sealed, so the append-only KEL stays lean.
    ctx.registry
        .store_credential(org_prefix, &oidc_policy_blob_key(&digest_hex), policy_json)
        .map_err(OrgError::Storage)?;

    let (_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    mark_org_oidc_policy(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        &digest_hex,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    Ok(OrgOidcPolicySet {
        org_did: format!("did:keri:{}", org_prefix.as_str()),
        policy_digest: digest_hex,
        policy,
    })
}

/// Load the org's current (latest-anchored) OIDC-subject policy from the KEL +
/// blob, fail-closed.
///
/// Takes the registry **port** directly — resolution is read-only, so verifiers
/// need no key custody to call it. Returns `Ok(None)` if the org never anchored
/// an OIDC-subject policy. A KEL that references a missing blob is
/// [`OrgError::PolicyBlobMissing`]; a blob that does not hash to the sealed
/// digest is [`OrgError::PolicyIntegrity`] (tampered); an unparseable blob is
/// [`OrgError::OidcPolicyInvalid`].
///
/// Args:
/// * `registry`: Registry backend holding the org KEL + credential blobs.
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// if let Some(loaded) = load_org_oidc_policy(&registry, &org_prefix)? {
///     let join = loaded.policy.join(&binding)?;
/// }
/// ```
pub fn load_org_oidc_policy(
    registry: &(dyn RegistryBackend + Send + Sync),
    org_prefix: &Prefix,
) -> Result<Option<LoadedOrgOidcPolicy>, OrgError> {
    let mut events: Vec<Event> = Vec::new();
    let _ = registry.visit_events(org_prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    let Some(digest_hex) = read_org_oidc_policy_digest(&events) else {
        return Ok(None);
    };

    let bytes = registry
        .load_credential(org_prefix, &oidc_policy_blob_key(&digest_hex))
        .map_err(OrgError::Storage)?
        .ok_or_else(|| OrgError::PolicyBlobMissing {
            hash: digest_hex.clone(),
        })?;

    // Tamper check: the loaded blob must hash to the value the KEL sealed.
    let actual = oidc_policy_digest(&bytes);
    if actual != digest_hex {
        return Err(OrgError::PolicyIntegrity {
            expected: digest_hex,
            actual,
        });
    }

    let source = String::from_utf8_lossy(&bytes).into_owned();
    let policy = OidcSubjectPolicy::parse(&source).map_err(|e| OrgError::OidcPolicyInvalid {
        reason: e.to_string(),
    })?;

    Ok(Some(LoadedOrgOidcPolicy {
        policy,
        policy_digest: digest_hex,
        source_json: source,
    }))
}
