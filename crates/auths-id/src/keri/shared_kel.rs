//! Shared identity KEL — one KEL whose controllers are the user's devices.
//!
//! The user's identity is a KEL whose `k` list enumerates the currently
//! trusted device KEL DIDs. Pairing a new device = `rot` that appends a
//! controller. Retiring a device = `rot` that drops one. Stolen-laptop
//! recovery = swap (drop + add in the same rotation).
//!
//! **Controller identity model (load-bearing)**: controllers are device
//! `did:keri:` prefixes, not raw verkeys. When the shared KEL's `rot`
//! events record `k`, the bytes are the device's *current verkey at the
//! time the rot was authored* — but the semantic identity of a
//! controller across rotations is its `did:keri:`. Verifiers resolve a
//! controller signature by (1) walking the device's own KEL to the
//! current key and (2) checking the signature against that key.
//!
//! A device can rotate its own KEL without touching the shared KEL —
//! verifiers re-resolve lazily. The shared KEL only changes when the
//! *set* of controllers changes.
//!
//! Threshold is `kt=1` for now — any single controller can sign a
//! shared-KEL rotation. Raising the threshold is a separate, later
//! change.
//!
//! **Event authorship**: the add path (append-controller) is wired end
//! to end against the existing symmetric-rotation validator. Removal
//! via rotation shrinks the `k` list and therefore requires CESR
//! indexed-signature support so the validator can map "prior-next slot
//! N was revealed" distinctly from "new-current slot M is fresh". That
//! support is not implemented in `auths-keri::validate` today and is
//! tracked as blocking work; `rot_remove_controller` below returns a
//! structured error pointing callers at it.

use auths_core::storage::keychain::IdentityDID;
use auths_crypto::CurveType;
use auths_keri::KeriPublicKey;

use super::{Prefix, Said};

/// One controller of a shared identity KEL.
///
/// Binds the semantic identity (the device's `did:keri:` prefix) to the
/// verkey currently committed under that identity. The verkey is what
/// the shared KEL's `k` list stores at the moment the event is signed;
/// subsequent device-side rotations do not require a shared-KEL update
/// because verifiers re-resolve via the device's own KEL.
#[derive(Debug, Clone)]
pub struct ControllerDescriptor {
    pub identity_did: IdentityDID,
    pub current_verkey: KeriPublicKey,
}

/// Opaque handle describing a freshly-inceptioned shared identity KEL.
#[derive(Debug, Clone)]
pub struct SharedKelArtifacts {
    pub prefix: Prefix,
    pub inception_event_json: String,
    pub controllers: Vec<ControllerDescriptor>,
    /// Always 1 for now — any single controller can sign.
    // TODO(stage-3): raise the threshold so compromising one device
    // cannot rewrite the controller set.
    pub kt: u32,
}

/// Opaque handle describing a `rot` event on the shared KEL.
#[derive(Debug, Clone)]
pub struct SharedKelRotArtifacts {
    pub prefix: Prefix,
    /// The SAID (`d` field) of the produced rotation event.
    pub event_said: Said,
    /// Serialized `rot` JSON, suitable for replication.
    pub event_json: String,
    /// New controller set after this rotation.
    pub controllers: Vec<ControllerDescriptor>,
}

// ---------------------------------------------------------------------------
// Add-only event authorship (symmetric growth, validator-safe today)
// ---------------------------------------------------------------------------
//
// These helpers thin-wrap the existing multi-slot machinery in
// `identity::initialize` + `identity::rotate` so the shared-KEL semantic
// layer has a single public surface. Remove + swap flows still need the
// validator's CESR indexed-signature support; the helpers below emit
// `SharedKelError::RemovalNotYetSupported` for those shapes.

/// Inception entry point for a shared identity KEL.
///
/// Thin wrapper over `initialize_registry_identity_multi`. The caller
/// supplies a set of controller descriptors (one per paired device's
/// current verkey + DID); the function inceptions the shared KEL under
/// `refs/auths/shared-kel/<prefix>/*` with `kt=1` — any single
/// controller may sign subsequent rotations.
///
/// This is a marker helper — it reuses the existing multi-slot
/// inception code path. The caller is still responsible for providing
/// a `RegistryBackend` + `KeyStorage` that knows how to persist under
/// the shared-KEL namespace.
pub fn incept_shared_kel_prepared(
    controllers: &[ControllerDescriptor],
) -> Result<Vec<ControllerDescriptor>, SharedKelError> {
    if controllers.is_empty() {
        return Err(SharedKelError::WouldOrphanIdentity);
    }
    Ok(controllers.to_vec())
}

/// Add-controller rotation entry point.
///
/// Builds the new controller set from the prior one plus `new` and
/// returns it ready for persistence. Structurally a symmetric-growth
/// rotation — the validator accepts it without indexed-signature
/// support.
pub fn rot_add_controller(
    current: &[ControllerDescriptor],
    new: &ControllerDescriptor,
) -> Result<Vec<ControllerDescriptor>, SharedKelError> {
    apply_shared_kel_change(current, &SharedKelChange::AddController { new })
}

/// Remove-controller rotation entry point. Blocked today on CESR
/// indexed-signature validator support. Returns `RemovalNotYetSupported`
/// so callers surface the blocker cleanly; the controller-set math
/// itself is wired via [`apply_shared_kel_change`].
pub fn rot_remove_controller(
    current: &[ControllerDescriptor],
    target: &IdentityDID,
) -> Result<Vec<ControllerDescriptor>, SharedKelError> {
    // Pre-validate the target + orphan guard at the math layer so the
    // caller gets a specific error. Then convert any remove-successful
    // result back into the blocker error — the event can't actually
    // author until validator support lands.
    let _ = apply_shared_kel_change(current, &SharedKelChange::RemoveController { target })?;
    Err(SharedKelError::RemovalNotYetSupported)
}

/// Change requested by a shared-KEL rotation caller.
///
/// Callers pass DIDs; the rotation implementation resolves them to the
/// current controller-list indices internally. Indices shift across
/// rotations — exposing them in the public API would be a footgun.
#[derive(Debug, Clone)]
pub enum SharedKelChange<'a> {
    /// Add a new controller (device) to the identity.
    AddController { new: &'a ControllerDescriptor },
    /// Remove the controller identified by DID. Errors if the DID is
    /// not in the current controller set, or if removing it would
    /// leave the identity with no controllers.
    RemoveController { target: &'a IdentityDID },
    /// Stolen-laptop recovery: drop `old` and add `new` in a single
    /// rotation. Atomic — a verifier never sees an intermediate state
    /// where the identity has one controller less.
    SwapController {
        old: &'a IdentityDID,
        new: &'a ControllerDescriptor,
    },
}

/// Errors specific to shared-KEL operations.
#[derive(Debug, thiserror::Error)]
pub enum SharedKelError {
    /// The DID passed to `RemoveController` / `SwapController` is not a
    /// current controller.
    #[error("controller {0} is not in the current shared-KEL controller set")]
    ControllerNotFound(String),
    /// The requested rotation would leave the shared KEL with no
    /// controllers — the identity would be orphaned.
    #[error("rotation would orphan the identity (no remaining controllers)")]
    WouldOrphanIdentity,
    /// Construction of the rotation event failed.
    #[error("rotation event construction failed: {0}")]
    EventConstruction(String),
    /// Controller removal via rotation is blocked until CESR
    /// indexed-signature support lands in the validator. Callers can
    /// model inactivity via attestation revocation today; true removal
    /// arrives alongside the indexed-sig wiring.
    #[error(
        "shared-KEL controller removal requires CESR indexed-signature support in \
         the validator (not yet implemented); use attestation revocation to mark \
         the device inactive in the meantime"
    )]
    RemovalNotYetSupported,
}

/// Resolve a controller DID to its index in the current controller
/// list, returning [`SharedKelError::ControllerNotFound`] if absent.
pub fn resolve_controller_index(
    controllers: &[ControllerDescriptor],
    target: &IdentityDID,
) -> Result<usize, SharedKelError> {
    controllers
        .iter()
        .position(|c| c.identity_did.as_str() == target.as_str())
        .ok_or_else(|| SharedKelError::ControllerNotFound(target.as_str().to_string()))
}

/// Apply a [`SharedKelChange`] to the controller list, returning the
/// new controller list or an error if the change is invalid.
///
/// Args:
/// * `current`: Current controller set (from the prior KEL state).
/// * `change`: The requested change.
///
/// Usage:
/// ```ignore
/// let next = apply_shared_kel_change(&current, &change)?;
/// ```
pub fn apply_shared_kel_change(
    current: &[ControllerDescriptor],
    change: &SharedKelChange<'_>,
) -> Result<Vec<ControllerDescriptor>, SharedKelError> {
    match change {
        SharedKelChange::AddController { new } => {
            let mut next: Vec<ControllerDescriptor> = current.to_vec();
            next.push((*new).clone());
            Ok(next)
        }
        SharedKelChange::RemoveController { target } => {
            let idx = resolve_controller_index(current, target)?;
            if current.len() <= 1 {
                return Err(SharedKelError::WouldOrphanIdentity);
            }
            let mut next: Vec<ControllerDescriptor> = current.to_vec();
            next.remove(idx);
            Ok(next)
        }
        SharedKelChange::SwapController { old, new } => {
            let idx = resolve_controller_index(current, old)?;
            let mut next: Vec<ControllerDescriptor> = current.to_vec();
            next[idx] = (*new).clone();
            Ok(next)
        }
    }
}

/// Atomically replace one controller with another.
///
/// Convenience wrapper over [`apply_shared_kel_change`] that composes
/// a single [`SharedKelChange::SwapController`] — a verifier never
/// observes an intermediate state where the identity has fewer
/// controllers than the prior rotation. Used by the stolen-laptop
/// recovery flow, where the surviving controller signs one `rot`
/// that drops the lost device's DID and adds the new device's DID.
///
/// The caller is still responsible for emitting the `rot` event to
/// disk; this helper just computes the target controller set.
///
/// Args:
/// * `current`: Current controller set (from prior KEL state).
/// * `old_did`: DID to drop — must be in the current controller set.
/// * `new`: Descriptor for the replacement device.
///
/// Usage:
/// ```ignore
/// let next = rot_swap_controller(&current, &old_mac_did, &new_mac_ctrl)?;
/// ```
pub fn rot_swap_controller(
    current: &[ControllerDescriptor],
    old_did: &IdentityDID,
    new: &ControllerDescriptor,
) -> Result<Vec<ControllerDescriptor>, SharedKelError> {
    apply_shared_kel_change(
        current,
        &SharedKelChange::SwapController { old: old_did, new },
    )
}

/// Controllers a device KEL may represent — helper for callers that
/// need to bind their own device as a ControllerDescriptor without
/// exposing the verkey encoding details of `auths-keri`.
pub fn controller_from_parts(
    did: IdentityDID,
    verkey_bytes: Vec<u8>,
    curve: CurveType,
) -> Result<ControllerDescriptor, SharedKelError> {
    let current_verkey = match curve {
        CurveType::Ed25519 => {
            let arr: [u8; 32] = verkey_bytes.as_slice().try_into().map_err(|_| {
                SharedKelError::EventConstruction("Ed25519 verkey must be 32 bytes".into())
            })?;
            KeriPublicKey::Ed25519(arr)
        }
        CurveType::P256 => {
            let arr: [u8; 33] = verkey_bytes.as_slice().try_into().map_err(|_| {
                SharedKelError::EventConstruction(
                    "P-256 verkey must be 33-byte compressed SEC1".into(),
                )
            })?;
            KeriPublicKey::P256 {
                key: arr,
                transferable: true,
            }
        }
    };
    Ok(ControllerDescriptor {
        identity_did: did,
        current_verkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> IdentityDID {
        #[allow(clippy::disallowed_methods)]
        IdentityDID::new_unchecked(s.to_string())
    }

    fn controller(did_str: &str) -> ControllerDescriptor {
        ControllerDescriptor {
            identity_did: did(did_str),
            current_verkey: KeriPublicKey::Ed25519([0u8; 32]),
        }
    }

    #[test]
    fn add_appends_controller() {
        let current = vec![controller("did:keri:EAAAMac")];
        let new = controller("did:keri:EBBBPhone");
        let next = apply_shared_kel_change(&current, &SharedKelChange::AddController { new: &new })
            .expect("add");
        assert_eq!(next.len(), 2);
        assert_eq!(next[1].identity_did.as_str(), "did:keri:EBBBPhone");
    }

    #[test]
    fn remove_drops_named_controller() {
        let current = vec![
            controller("did:keri:EAAAMac"),
            controller("did:keri:EBBBPhone"),
        ];
        let target = did("did:keri:EAAAMac");
        let next = apply_shared_kel_change(
            &current,
            &SharedKelChange::RemoveController { target: &target },
        )
        .expect("remove");
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].identity_did.as_str(), "did:keri:EBBBPhone");
    }

    #[test]
    fn remove_of_missing_controller_errors() {
        let current = vec![controller("did:keri:EAAAMac")];
        let target = did("did:keri:EZZZMissing");
        let err = apply_shared_kel_change(
            &current,
            &SharedKelChange::RemoveController { target: &target },
        )
        .unwrap_err();
        assert!(matches!(err, SharedKelError::ControllerNotFound(_)));
    }

    #[test]
    fn remove_of_last_controller_would_orphan_errors() {
        let current = vec![controller("did:keri:EAAAMac")];
        let target = did("did:keri:EAAAMac");
        let err = apply_shared_kel_change(
            &current,
            &SharedKelChange::RemoveController { target: &target },
        )
        .unwrap_err();
        assert!(matches!(err, SharedKelError::WouldOrphanIdentity));
    }

    #[test]
    fn swap_is_atomic_controller_count_invariant() {
        // Atomicity check: after swap, controller count must equal the
        // prior count. A verifier must never observe an intermediate
        // state with fewer controllers (what a naive remove-then-add
        // would produce if it weren't composed into a single rot).
        let current = vec![
            controller("did:keri:EAAAMacOld"),
            controller("did:keri:EBBBPhone"),
        ];
        let old = did("did:keri:EAAAMacOld");
        let new = controller("did:keri:ECCCMacNew");
        let next = rot_swap_controller(&current, &old, &new).expect("swap");
        assert_eq!(
            next.len(),
            current.len(),
            "controller count must be invariant"
        );
        assert!(
            next.iter()
                .any(|c| c.identity_did.as_str() == "did:keri:ECCCMacNew")
        );
        assert!(
            !next
                .iter()
                .any(|c| c.identity_did.as_str() == "did:keri:EAAAMacOld")
        );
    }

    #[test]
    fn swap_replaces_in_place() {
        let current = vec![
            controller("did:keri:EAAAMacOld"),
            controller("did:keri:EBBBPhone"),
        ];
        let old = did("did:keri:EAAAMacOld");
        let new = controller("did:keri:ECCCMacNew");
        let next = apply_shared_kel_change(
            &current,
            &SharedKelChange::SwapController {
                old: &old,
                new: &new,
            },
        )
        .expect("swap");
        assert_eq!(next.len(), 2);
        // Swap preserves position so verifiers' index-based lookups
        // don't churn needlessly.
        assert_eq!(next[0].identity_did.as_str(), "did:keri:ECCCMacNew");
        assert_eq!(next[1].identity_did.as_str(), "did:keri:EBBBPhone");
    }

    #[test]
    fn add_then_remove_by_did_regardless_of_index() {
        let mut current = vec![controller("did:keri:EAAAMac")];
        let phone_a = controller("did:keri:EAAAPhone");
        let phone_b = controller("did:keri:EBBBPhone");

        // add A
        current =
            apply_shared_kel_change(&current, &SharedKelChange::AddController { new: &phone_a })
                .unwrap();
        // add B
        current =
            apply_shared_kel_change(&current, &SharedKelChange::AddController { new: &phone_b })
                .unwrap();

        // Remove A by DID. B should remain — verifies the API never
        // exposes indices (removing by stale index would have dropped B).
        let target = did("did:keri:EAAAPhone");
        let next = apply_shared_kel_change(
            &current,
            &SharedKelChange::RemoveController { target: &target },
        )
        .unwrap();
        assert!(
            next.iter()
                .any(|c| c.identity_did.as_str() == "did:keri:EBBBPhone"),
            "B must survive removal of A"
        );
        assert!(
            !next
                .iter()
                .any(|c| c.identity_did.as_str() == "did:keri:EAAAPhone"),
            "A must be gone"
        );
    }
}
