//! Credential issuance / revocation / listing orchestration (Epic F.4).
//!
//! These are the SDK-orchestrates workflows over F.3's `credential_registry`
//! engine: the SDK sequences the steps (guard the issuee, ensure the registry,
//! build + issuer-sign the ACDC, author the `iss`/`rev` TEL event + KEL anchor)
//! while the *how* (TEL building, atomic anchoring) stays in `auths-id`. No KEL or
//! crypto is reimplemented here.

use auths_core::storage::keychain::{KeyAlias, sign_with_key};
use auths_id::keri::credential_registry::{
    anchor_tel_event, build_iss, build_rev, ensure_registry, find_registry, read_credential_tel,
};
use auths_id::keri::parse_did_keri;
use auths_id::keri::types::Prefix;
use auths_keri::{Acdc, Capability, Said, TelEvent, compute_capability_schema_said, validate_tel};
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;
use crate::domains::credentials::stored::StoredCredential;

/// The capability claim field the F.1 schema requires (`a.capability`, single string).
const CAPABILITY_FIELD: &str = "capability";
/// Optional ISO-8601 expiry claim (`a.expiry`) the verifier checks against `now`.
const EXPIRY_FIELD: &str = "expiry";
/// Optional informational role claim (`a.role`).
const ROLE_FIELD: &str = "role";

/// The result of issuing a credential.
#[derive(Debug, Clone)]
pub struct CredentialIssuance {
    /// The issued credential's SAID (`acdc.d`).
    pub credential_said: String,
    /// The registry SAID the credential belongs to (`acdc.ri`).
    pub registry_said: String,
    /// The issuer AID (`did:keri:`).
    pub issuer_did: String,
    /// The issuee/subject AID (`did:keri:`).
    pub issuee_did: String,
}

/// Resolve the local issuer's KEL prefix from the loaded managed identity.
///
/// The issuer is the loaded root/managed identity; the alias selects which signing
/// key authors the anchoring `ixn`s (resolved separately by [`resolve_issuer`]).
///
/// Args:
/// * `ctx`: Auths context.
/// * `_issuer_alias`: Reserved for multi-identity selection (currently the managed identity).
///
/// Usage:
/// ```ignore
/// let prefix = resolve_issuer_prefix(&ctx, &issuer)?;
/// ```
pub fn resolve_issuer_prefix(
    ctx: &AuthsContext,
    _issuer_alias: &KeyAlias,
) -> Result<Prefix, CredentialError> {
    let managed =
        ctx.identity_storage
            .load_identity()
            .map_err(|e| CredentialError::IssueeNotFound {
                did: format!("issuer identity load failed: {e}"),
            })?;
    parse_did_keri(managed.controller_did.as_str()).map_err(|e| CredentialError::IssueeNotFound {
        did: format!("invalid issuer did:keri: {e}"),
    })
}

/// Resolve the local issuer's KEL prefix and current signing curve from its alias.
///
/// The issuer is the loaded root/managed identity; the alias selects which signing
/// key authors the anchoring `ixn`s.
fn resolve_issuer(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
) -> Result<(Prefix, auths_crypto::CurveType), CredentialError> {
    let issuer_prefix = resolve_issuer_prefix(ctx, issuer_alias)?;
    let (_pk, curve) = auths_core::storage::keychain::extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        issuer_alias,
        ctx.passphrase_provider.as_ref(),
    )?;
    Ok((issuer_prefix, curve))
}

/// Guard that the issuee has an incepted KEL — an issuee is never lazily created.
fn guard_issuee_exists(ctx: &AuthsContext, issuee_did: &str) -> Result<Prefix, CredentialError> {
    let issuee_prefix =
        parse_did_keri(issuee_did).map_err(|_| CredentialError::IssueeNotFound {
            did: issuee_did.to_string(),
        })?;
    ctx.registry
        .get_event(&issuee_prefix, 0)
        .map_err(|_| CredentialError::IssueeNotFound {
            did: issuee_did.to_string(),
        })?;
    Ok(issuee_prefix)
}

/// Build the capability ACDC attributes map (`capability`, optional `role`/`expiry`).
fn build_attributes(
    capabilities: &[Capability],
    role: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut data = serde_json::Map::new();
    let capability = capabilities
        .iter()
        .map(Capability::as_str)
        .collect::<Vec<_>>()
        .join(",");
    data.insert(
        CAPABILITY_FIELD.to_string(),
        serde_json::Value::String(capability),
    );
    if let Some(role) = role {
        data.insert(
            ROLE_FIELD.to_string(),
            serde_json::Value::String(role.to_string()),
        );
    }
    if let Some(exp) = expires_at {
        data.insert(
            EXPIRY_FIELD.to_string(),
            serde_json::Value::String(exp.to_rfc3339()),
        );
    }
    data
}

/// Issue a capability credential to an issuee, anchored to the issuer's KEL.
///
/// Orchestrates F.3: guards the issuee KEL exists ([`CredentialError::IssueeNotFound`]),
/// lazily ensures the issuer's backerless registry (`vcp`), builds the ACDC
/// `{v,d,i,ri,s,a}`, issuer-signs over `acdc.to_wire_bytes()`, persists the signed
/// envelope as the credential blob, and authors the `iss` TEL event + KEL anchor — all
/// in one atomic batch. A `kt≥2` issuer is rejected ([`CredentialError::KtThresholdUnsupported`]).
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, identity storage, passphrase).
/// * `issuer_alias`: Keychain alias of the issuer's current signing key.
/// * `issuee_did`: The subject/holder `did:keri:` (its KEL must already exist).
/// * `capabilities`: The capabilities granted (joined into the single `a.capability` claim).
/// * `role`: Optional informational role claim (`a.role`).
/// * `expires_at`: Optional expiry (`a.expiry`); injected by the caller (clock at the boundary).
///
/// Usage:
/// ```ignore
/// let issued = issue(&ctx, &issuer, "did:keri:E…", &[Capability::parse("sign")?], Some("deployer"), None)?;
/// println!("{}", issued.credential_said);
/// ```
pub fn issue(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
    issuee_did: &str,
    capabilities: &[Capability],
    role: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<CredentialIssuance, CredentialError> {
    let (issuer_prefix, issuer_curve) = resolve_issuer(ctx, issuer_alias)?;
    let issuee_prefix = guard_issuee_exists(ctx, issuee_did)?;

    let registry = ensure_registry(
        ctx.registry.as_ref(),
        &issuer_prefix,
        issuer_alias,
        issuer_curve,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )?;

    let schema = compute_capability_schema_said().map_err(|_| CredentialError::SchemaUnknown)?;
    let now = ctx.clock.now();
    let data = build_attributes(capabilities, role, expires_at);
    let acdc = Acdc::new(
        issuer_prefix.clone(),
        registry.clone(),
        schema,
        issuee_prefix.clone(),
        now.to_rfc3339(),
        data,
    )
    .saidify()
    .map_err(|_| CredentialError::SchemaUnknown)?;

    let credential_said = Said::new_unchecked(acdc.d.as_str().to_string());

    let wire = acdc
        .to_wire_bytes()
        .map_err(|_| CredentialError::SchemaUnknown)?;
    let (signature, _pk, _curve) = sign_with_key(
        ctx.key_storage.as_ref(),
        issuer_alias,
        ctx.passphrase_provider.as_ref(),
        &wire,
    )?;

    let stored = StoredCredential {
        acdc: acdc.clone(),
        signature,
    };
    let blob = stored
        .to_bytes()
        .map_err(|_| CredentialError::SchemaUnknown)?;

    let iss = build_iss(&credential_said, &registry, now.to_rfc3339())?;
    anchor_tel_event(
        ctx.registry.as_ref(),
        &issuer_prefix,
        issuer_alias,
        issuer_curve,
        &TelEvent::Iss(iss),
        Some((credential_said.clone(), blob)),
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )?;

    Ok(CredentialIssuance {
        credential_said: credential_said.as_str().to_string(),
        registry_said: registry.as_str().to_string(),
        issuer_did: format!("did:keri:{issuer_prefix}"),
        issuee_did: format!("did:keri:{issuee_prefix}"),
    })
}

/// Revoke a previously issued credential — authors a `rev` TEL event + KEL anchor.
///
/// Idempotent: if the credential's TEL already carries a `rev`, the call returns
/// `Ok(())` without authoring a second revocation (per the named test
/// `revoke_already_revoked_idempotent`). The `rev` back-links to the prior `iss`.
///
/// Args:
/// * `ctx`: Auths context.
/// * `issuer_alias`: Keychain alias of the issuer's current signing key.
/// * `credential_said`: The SAID of the credential to revoke.
///
/// Usage:
/// ```ignore
/// revoke(&ctx, &issuer, "ECredentialSaid…")?;
/// ```
pub fn revoke(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
    credential_said: &str,
) -> Result<(), CredentialError> {
    let (issuer_prefix, issuer_curve) = resolve_issuer(ctx, issuer_alias)?;
    let registry = find_registry(ctx.registry.as_ref(), &issuer_prefix)?.ok_or(
        CredentialError::RegistryError(
            auths_id::keri::credential_registry::CredentialRegistryError::Tel(
                "issuer has no registry".to_string(),
            ),
        ),
    )?;
    let cred = Said::new_unchecked(credential_said.to_string());

    let tel = read_credential_tel(ctx.registry.as_ref(), &issuer_prefix, &registry, &cred)?;
    let iss_said = tel
        .iter()
        .find_map(|e| match e {
            TelEvent::Iss(iss) if iss.i == cred => Some(iss.d.clone()),
            _ => None,
        })
        .ok_or(CredentialError::RegistryError(
            auths_id::keri::credential_registry::CredentialRegistryError::Tel(
                "credential has no iss event".to_string(),
            ),
        ))?;

    // Idempotent: a rev already in the TEL means this credential is revoked.
    if tel
        .iter()
        .any(|e| matches!(e, TelEvent::Rev(rev) if rev.i == cred))
    {
        return Ok(());
    }

    let now = ctx.clock.now();
    let rev = build_rev(&cred, &registry, &iss_said, now.to_rfc3339())?;
    anchor_tel_event(
        ctx.registry.as_ref(),
        &issuer_prefix,
        issuer_alias,
        issuer_curve,
        &TelEvent::Rev(rev),
        None,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )?;
    Ok(())
}

/// One issued credential with its live/revoked status.
#[derive(Debug, Clone)]
pub struct CredentialSummary {
    /// The credential SAID (`acdc.d`).
    pub credential_said: String,
    /// The subject/holder AID (`did:keri:`).
    pub subject_did: String,
    /// The capabilities granted (`a.capability`, comma-split).
    pub capabilities: Vec<Capability>,
    /// Whether a `rev` is anchored for this credential.
    pub revoked: bool,
}

/// List an issuer's live credentials (issued − revoked).
///
/// Walks the issuer's registry TEL, replays each credential's `iss`/`rev` chain via
/// `validate_tel`, and reports those still issued. Revoked credentials are excluded
/// from the live set (their `revoked` flag is `true` if included).
///
/// Args:
/// * `ctx`: Auths context.
/// * `issuer_alias`: Keychain alias of the issuer whose credentials to list.
///
/// Usage:
/// ```ignore
/// let live = list(&ctx, &issuer)?;
/// ```
pub fn list(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
) -> Result<Vec<CredentialSummary>, CredentialError> {
    let (issuer_prefix, _curve) = resolve_issuer(ctx, issuer_alias)?;
    let Some(registry) = find_registry(ctx.registry.as_ref(), &issuer_prefix)? else {
        return Ok(Vec::new());
    };

    let credential_saids = collect_credential_saids(ctx, &issuer_prefix, &registry)?;

    let mut summaries = Vec::new();
    for cred in credential_saids {
        let tel = read_credential_tel(ctx.registry.as_ref(), &issuer_prefix, &registry, &cred)?;
        let state = validate_tel(&tel).map_err(|e| {
            CredentialError::RegistryError(
                auths_id::keri::credential_registry::CredentialRegistryError::Tel(e.to_string()),
            )
        })?;
        let revoked = !state.is_valid(&cred);
        let (subject_did, capabilities) = credential_claims(ctx, &issuer_prefix, &cred);
        summaries.push(CredentialSummary {
            credential_said: cred.as_str().to_string(),
            subject_did,
            capabilities,
            revoked,
        });
    }
    Ok(summaries)
}

/// Collect the distinct credential SAIDs anchored under an issuer's registry.
///
/// Reads the issuer KEL for `iss`-anchoring `ixn` seals — each carries the credential
/// SAID as the seal's `i`. The `vcp` anchor (seal `i` == registry SAID) is skipped.
fn collect_credential_saids(
    ctx: &AuthsContext,
    issuer_prefix: &Prefix,
    registry: &Said,
) -> Result<Vec<Said>, CredentialError> {
    use auths_id::keri::Seal;
    use std::ops::ControlFlow;

    let mut saids: Vec<Said> = Vec::new();
    ctx.registry
        .visit_events(issuer_prefix, 0, &mut |event| {
            for seal in event.anchors() {
                if let Seal::KeyEvent { i, .. } = seal
                    && i.as_str() != registry.as_str()
                {
                    let said = Said::new_unchecked(i.as_str().to_string());
                    if !saids.contains(&said) {
                        saids.push(said);
                    }
                }
            }
            ControlFlow::Continue(())
        })
        .map_err(|e| {
            CredentialError::RegistryError(
                auths_id::keri::credential_registry::CredentialRegistryError::Tel(e.to_string()),
            )
        })?;
    Ok(saids)
}

/// The `(subject_did, capabilities)` of a credential, read from its stored ACDC.
///
/// Best-effort: a credential whose blob is missing or unparseable reports an empty
/// subject and no capabilities (the listing still shows its SAID + revoked status).
fn credential_claims(
    ctx: &AuthsContext,
    issuer_prefix: &Prefix,
    credential_said: &Said,
) -> (String, Vec<Capability>) {
    let Ok(Some(blob)) = ctx.registry.load_credential(issuer_prefix, credential_said) else {
        return (String::new(), Vec::new());
    };
    let Ok(stored) = StoredCredential::from_bytes(&blob) else {
        return (String::new(), Vec::new());
    };
    let subject = format!("did:keri:{}", stored.acdc.a.i);
    let caps = stored
        .acdc
        .a
        .data
        .get(CAPABILITY_FIELD)
        .and_then(|v| v.as_str())
        .and_then(|c| {
            c.split(',')
                .map(Capability::parse)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        })
        .unwrap_or_default();
    (subject, caps)
}
