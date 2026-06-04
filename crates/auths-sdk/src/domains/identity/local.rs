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
    // Root machine: the icp-rooted controller is the signer (signs directly).
    if let Ok(managed) = ctx.identity_storage.load_identity() {
        let did = managed.controller_did.to_string();
        let anchor_seq = root_tip_seq(ctx, &did);
        return Ok(LocalSigner {
            signer_did: did.clone(),
            root_did: did,
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

/// The delegator (root) KEL tip sequence for `root_did`, or `None` if unreadable.
fn root_tip_seq(ctx: &AuthsContext, root_did: &str) -> Option<u128> {
    let prefix = root_did.strip_prefix("did:keri:")?;
    ctx.registry
        .get_tip(&Prefix::new_unchecked(prefix.to_string()))
        .ok()
        .map(|tip| tip.sequence)
}
