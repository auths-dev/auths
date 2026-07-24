//! Local signer-identity resolution — "who am I, and what root do I chain to" on
//! this machine, for the in-band commit-signing identity (the `Auths-Id` /
//! `Auths-Device` trailer).
//!
//! Uniform across machines:
//! - **Root machine**: an icp-rooted controller exists in the registry → the
//!   controller signs directly, so `signer == root == controller`.
//! - **Delegate machine**: after pairing, the local registry holds only this
//!   device's `dip`-rooted KEL (no icp root). `find_first_identity` deliberately
//!   skips `dip`-rooted KELs (so a root machine resolves the icp root, not a
//!   delegate), which means `load_identity` finds nothing here — so we fall back
//!   to the local `dip` and read its delegator (`di`).

use std::ops::ControlFlow;

use auths_id::keri::Event;
use auths_id::keri::types::Prefix;
use auths_id::ports::registry::RegistryBackend;

use crate::context::AuthsContext;
use crate::domains::identity::error::SetupError;

/// This machine's signing identity and the root it chains to.
pub struct LocalSigner {
    /// This machine's signer `did:keri:` — the controller on a root machine, or the
    /// delegated device's own AID on a paired machine.
    pub signer_did: String,
    /// The root identity `did:keri:`. Equals `signer_did` when the root signs
    /// directly; on a delegate it is the delegator (`dip.di`).
    pub root_did: String,
    /// The delegator (root) KEL tip sequence observed at resolution — the in-band
    /// `Auths-Anchor-Seq` signing position. Lets a verifier order a commit against a
    /// later revocation by KEL position (a commit signed before the revocation stays
    /// valid). `None` if the root KEL tip can't be read.
    pub anchor_seq: Option<u128>,
}

impl LocalSigner {
    /// Whether this machine signs as a delegated device (signer differs from root).
    pub fn is_delegated(&self) -> bool {
        self.signer_did != self.root_did
    }
}

/// Resolve the local signer + its root, uniformly across root and delegate machines.
///
/// Args:
/// * `ctx`: Auths context supplying `identity_storage` + `registry`.
///
/// Usage:
/// ```ignore
/// let signer = resolve_local_signer(&ctx)?;
/// // commit trailer: `Auths-Id: {signer.root_did}` + `Auths-Device: {signer.signer_did}`
/// ```
pub fn resolve_local_signer(ctx: &AuthsContext) -> Result<LocalSigner, SetupError> {
    // Explicit signing key override (e.g., delegated agent `AUTHS_SIGNING_KEY="auths:agent-label"`).
    if let Ok(key_alias_str) = std::env::var("AUTHS_SIGNING_KEY") {
        let key_ref = auths_core::storage::keychain::SigningKeyRef::parse(&key_alias_str)
            .map_err(|e| SetupError::InvalidSetupConfig(e.to_string()))?;
        let alias = key_ref.bare_alias().clone();
        if let Ok(key_info) = ctx.key_storage.load_key(&alias) {
            let agent_did = key_info.0.to_string();
            let agent_prefix = auths_id::keri::parse_did_keri(&agent_did)
                .map_err(|e| SetupError::InvalidSetupConfig(format!("invalid agent DID: {e}")))?;

            let (root_did, anchor_seq) = if let Ok(managed) = ctx.identity_storage.load_identity() {
                let rd = managed.controller_did.to_string();
                let seq = root_tip_seq(ctx, &rd);
                (rd, seq)
            } else if let Ok(auths_id::keri::Event::Dip(dip)) =
                ctx.registry.get_event(&agent_prefix, 0)
            {
                let rd = format!("did:keri:{}", dip.di);
                let seq = root_tip_seq(ctx, &rd);
                (rd, seq)
            } else {
                return Err(SetupError::InvalidSetupConfig(format!(
                    "AUTHS_SIGNING_KEY '{key_alias_str}' delegation info not found in registry"
                )));
            };

            return Ok(LocalSigner {
                signer_did: agent_did,
                root_did,
                anchor_seq,
            });
        } else {
            return Err(SetupError::InvalidSetupConfig(format!(
                "AUTHS_SIGNING_KEY '{key_alias_str}' not found in key storage"
            )));
        }
    }

    // Root machine: prefer this root's delegated device #0 as the signer (its own AID,
    // distinct from the root) so identity_did != device_did. Fall back to the root
    // signing directly (a root identity with no delegated device — e.g. CI).
    if let Ok(managed) = ctx.identity_storage.load_identity() {
        let root_did = managed.controller_did.to_string();
        let anchor_seq = root_tip_seq(ctx, &root_did);
        if let Ok(root_prefix) = auths_id::keri::parse_did_keri(&root_did)
            && let Ok(devices) = auths_id::keri::delegation::list_delegated_devices(
                ctx.registry.as_ref(),
                &root_prefix,
            )
            && let Some(dev) = devices.iter().find(|d| is_local_signing_device(ctx, d))
        {
            return Ok(LocalSigner {
                signer_did: format!("did:keri:{}", dev.device_prefix),
                root_did,
                anchor_seq,
            });
        }
        // No delegated device whose key this machine actually holds: sign as the
        // root directly (whose key IS local). This is the pre-delegation default,
        // and it is what keeps the stamped `Auths-Device` equal to the key that
        // will make the signature — a device we cannot sign as must never be
        // stamped, or every commit fails `SignerKeyMismatch` at verify time.
        return Ok(LocalSigner {
            signer_did: root_did.clone(),
            root_did,
            anchor_seq,
        });
    }

    // Delegate machine: no icp root locally — find this device's `dip` + its delegator.
    let mut prefixes: Vec<String> = Vec::new();
    ctx.registry
        .visit_identities(&mut |prefix| {
            prefixes.push(prefix.to_string());
            ControlFlow::Continue(())
        })
        .map_err(|e| {
            SetupError::StorageError(
                auths_id::error::StorageError::InvalidData(e.to_string()).into(),
            )
        })?;

    for prefix_str in prefixes {
        let prefix = Prefix::new_unchecked(prefix_str);
        if let Ok(Event::Dip(dip)) = ctx.registry.get_event(&prefix, 0) {
            let root_did = format!("did:keri:{}", dip.di);
            let anchor_seq = root_tip_seq(ctx, &root_did);
            return Ok(LocalSigner {
                signer_did: format!("did:keri:{}", dip.i),
                root_did,
                anchor_seq,
            });
        }
    }

    Err(SetupError::StorageError(
        auths_id::error::StorageError::InvalidData(
            "no local signing identity found (neither a root identity nor a delegated \
             device). Run `auths init`, or pair this device with `auths pair --join`."
                .to_string(),
        )
        .into(),
    ))
}

/// Whether a delegated device may stand in as THIS machine's interactive signer.
///
/// Two conditions, both required — because the stamped `Auths-Device` must be the
/// identity whose key actually makes the signature:
/// * not revoked, and not an `agent:` role delegation (a headless agent delegated
///   for its own signing is never the human operator's interactive identity), and
/// * its signing key is present in THIS machine's keychain — a device whose key
///   lives elsewhere (or was never stored, e.g. a failed delegation's orphan `dip`)
///   cannot be signed as here, so stamping it would guarantee a verify-time
///   `SignerKeyMismatch`.
///
/// Args:
/// * `ctx`: the auths context (key storage + registry).
/// * `dev`: one delegated device from `list_delegated_devices`.
///
/// Usage:
/// ```ignore
/// let signer = devices.iter().find(|d| is_local_signing_device(ctx, d));
/// ```
fn is_local_signing_device(
    ctx: &AuthsContext,
    dev: &auths_id::keri::delegation::DelegatedDeviceInfo,
) -> bool {
    use auths_id::keri::delegation::DelegatedRole;
    if dev.revoked || matches!(dev.role, DelegatedRole::Agent) {
        return false;
    }
    let device_did = format!("did:keri:{}", dev.device_prefix);
    match auths_core::storage::keychain::IdentityDID::parse(&device_did) {
        Ok(did) => ctx
            .key_storage
            .list_aliases_for_identity(&did)
            .map(|aliases| !aliases.is_empty())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// The delegator (root) KEL tip sequence for `root_did`, or `None` if unreadable.
fn root_tip_seq(ctx: &AuthsContext, root_did: &str) -> Option<u128> {
    let parsed = auths_verifier::IdentityDID::parse(root_did).ok()?;
    ctx.registry
        .get_tip(&Prefix::new_unchecked(parsed.prefix().to_string()))
        .ok()
        .map(|tip| tip.sequence)
}
