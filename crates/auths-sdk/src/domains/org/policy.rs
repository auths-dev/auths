//! Org-wide authorization policy: author / store / load + the fail-closed gate.
//!
//! An org's policy is a serialized [`Expr`] compiled to a [`CompiledPolicy`]. The
//! source JSON is stored as a **content-addressed blob** in the org's credential
//! namespace; only its BLAKE3 source-hash is anchored on the org KEL (a
//! `policy:{hash}` seal). The append-only KEL therefore stays lean — a rich policy
//! never bloats every replay — and the binding is **tamper-evident**:
//! [`load_org_policy`] recomputes the loaded blob's hash and refuses a mismatch.
//!
//! The gate is the shipped `evaluate_strict` (Indeterminate → Deny; RequiresApproval
//! preserved). This module adds storage, load, and a thin policy-hash-pinning
//! wrapper; the per-call wiring into the commit and request verify paths lives in the
//! enforcement tasks that consume it.
//!
//! Authoring requires a single-signature (`kt=1`) org — the anchoring `ixn` is
//! single-author, matching [`super::delegation`].

use std::ops::ControlFlow;

use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::keri::delegation::{mark_org_policy, read_org_policy_hash};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Said};
use auths_id::policy::{CompiledPolicy, Decision, EvalContext, compile_from_json, evaluate_strict};

use crate::context::AuthsContext;
use crate::domains::org::delegation::ensure_single_sig_org;
use crate::domains::org::error::OrgError;

/// The serializable policy expression authored into an org policy. Re-exported so
/// callers (and tests) can build policies without depending on `auths-policy`.
pub use auths_id::policy::Expr;

/// The result of authoring an org policy.
#[derive(Debug, Clone)]
pub struct OrgPolicySet {
    /// The org's `did:keri:`.
    pub org_did: String,
    /// Lowercase-hex BLAKE3 source-hash of the compiled policy. Anchored on the KEL
    /// and pinned into every decision this policy produces, for audit.
    pub policy_hash: String,
    /// Human-readable summary of the policy's requirements.
    pub description: String,
}

/// An org policy loaded from the KEL + content-addressed blob, ready to evaluate.
#[derive(Debug, Clone)]
pub struct LoadedOrgPolicy {
    /// The compiled, ready-to-evaluate policy.
    pub compiled: CompiledPolicy,
    /// Lowercase-hex BLAKE3 source-hash (matches the on-KEL `policy:` seal).
    pub policy_hash: String,
    /// The raw policy source JSON (for `show`).
    pub source_json: String,
}

/// Collect an org's KEL into a `Vec<Event>` (oldest first) via the registry.
fn collect_org_kel(ctx: &AuthsContext, org_prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    let _ = ctx.registry.visit_events(org_prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    events
}

/// Content-addressed blob key for an org policy of the given source-hash. Namespaced
/// (`policy-{hash}`) so it never collides with the member-prefix-keyed off-boarding
/// records in the same credential store.
fn policy_blob_key(source_hash_hex: &str) -> Said {
    Said::new_unchecked(format!("policy-{source_hash_hex}"))
}

/// Join compile errors into one message for [`OrgError::PolicyCompile`].
fn compile_err(errs: Vec<auths_id::policy::CompileError>) -> OrgError {
    OrgError::PolicyCompile {
        reason: errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// Author an org-wide authorization policy: validate + compile it, store the source
/// JSON as a content-addressed blob, and anchor its hash on the org KEL.
///
/// Fail-closed: a policy that does not parse or compile is **never** anchored
/// ([`OrgError::PolicyCompile`]). `compile_from_json` also enforces the policy
/// size/complexity bounds. Re-setting anchors a new seal; the latest wins on load.
/// Requires a single-signature org.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, passphrase).
/// * `org_prefix`: The org's KEL prefix (the policy authority).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `policy_json`: The policy as a serialized [`Expr`] (JSON bytes).
///
/// Usage:
/// ```ignore
/// let set = set_org_policy(&ctx, &org_prefix, &org_alias, policy_json)?;
/// println!("anchored policy {}", set.policy_hash);
/// ```
pub fn set_org_policy(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    policy_json: &[u8],
) -> Result<OrgPolicySet, OrgError> {
    ensure_single_sig_org(ctx, org_prefix)?;

    // Validate + compile first — a policy that does not compile is never anchored.
    let compiled = compile_from_json(policy_json).map_err(compile_err)?;
    let hash_hex = hex::encode(compiled.source_hash());

    // The source JSON lives off-KEL in a content-addressed blob; only the hash is
    // anchored, so the append-only KEL stays lean.
    ctx.registry
        .store_credential(org_prefix, &policy_blob_key(&hash_hex), policy_json)
        .map_err(OrgError::Storage)?;

    let (_pk, org_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(OrgError::CryptoError)?;

    mark_org_policy(
        ctx.registry.as_ref(),
        org_prefix,
        org_alias,
        org_curve,
        &hash_hex,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(OrgError::Delegation)?;

    Ok(OrgPolicySet {
        org_did: format!("did:keri:{}", org_prefix.as_str()),
        policy_hash: hash_hex,
        description: compiled.describe(),
    })
}

/// Load the org's current (latest-anchored) policy from the KEL + blob, fail-closed.
///
/// Returns `Ok(None)` if the org never anchored a policy (the caller decides whether
/// a missing policy means allow or deny, and records that choice). A KEL that
/// references a missing blob is [`OrgError::PolicyBlobMissing`]; a blob that does not
/// hash to the committed value is [`OrgError::PolicyIntegrity`] (tampered); an
/// uncompilable blob is [`OrgError::PolicyCompile`].
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// if let Some(policy) = load_org_policy(&ctx, &org_prefix)? {
///     let decision = evaluate_with_org_policy(&policy, &eval_ctx);
/// }
/// ```
pub fn load_org_policy(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
) -> Result<Option<LoadedOrgPolicy>, OrgError> {
    let kel = collect_org_kel(ctx, org_prefix);
    let Some(hash_hex) = read_org_policy_hash(&kel) else {
        return Ok(None);
    };

    let bytes = ctx
        .registry
        .load_credential(org_prefix, &policy_blob_key(&hash_hex))
        .map_err(OrgError::Storage)?
        .ok_or_else(|| OrgError::PolicyBlobMissing {
            hash: hash_hex.clone(),
        })?;

    let compiled = compile_from_json(&bytes).map_err(compile_err)?;

    // Tamper check: the loaded blob must hash to the value the KEL committed.
    let actual = hex::encode(compiled.source_hash());
    if actual != hash_hex {
        return Err(OrgError::PolicyIntegrity {
            expected: hash_hex,
            actual,
        });
    }

    Ok(Some(LoadedOrgPolicy {
        compiled,
        policy_hash: hash_hex,
        source_json: String::from_utf8_lossy(&bytes).into_owned(),
    }))
}

/// The fail-closed gate: evaluate a context against a loaded org policy, pinning the
/// policy's source-hash into the decision for audit.
///
/// `evaluate_strict` maps Indeterminate → Deny and preserves RequiresApproval. Pure:
/// no I/O, no clock — the same inputs always yield the same decision, so the SDK, the
/// CLI, and the GitHub App agree by construction.
///
/// Args:
/// * `policy`: The loaded org policy.
/// * `eval_ctx`: The typed evaluation context (built from a verified principal).
///
/// Usage:
/// ```ignore
/// let decision = evaluate_with_org_policy(&policy, &eval_ctx);
/// if decision.is_denied() { /* reject with decision.reason */ }
/// ```
pub fn evaluate_with_org_policy(policy: &LoadedOrgPolicy, eval_ctx: &EvalContext) -> Decision {
    evaluate_strict(&policy.compiled, eval_ctx).with_policy_hash(*policy.compiled.source_hash())
}
