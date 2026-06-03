//! Delegated device workflows (Model D) — add/remove a device as a KERI
//! delegated identifier of the root identity.
//!
//! A device is a KERI delegated AID: its own KEL is incepted with a `dip`
//! delegated by the root, and the root anchors it via an `ixn`. The device holds
//! its own key; the root only anchors. This is the keripy-native, single-author,
//! device-bound replacement for shared-`k[]` controllers.

use std::sync::Arc;

use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_id::keri::delegation::{
    incept_delegated_device, list_delegated_devices as id_list_delegated_devices,
    revoke_delegated_device,
};
use auths_id::keri::parse_did_keri;

use crate::context::AuthsContext;
use crate::domains::device::error::DeviceError;

/// Result of adding a delegated device.
pub struct DeviceDelegationResult {
    /// The new device's `did:keri:`.
    pub device_did: String,
    /// The new device's KEL prefix.
    pub device_prefix: String,
}

/// Add a device as a delegated identifier of the current identity.
///
/// Incepts the device's own KEL (a `dip` delegated by the root) and authors the
/// root's anchoring `ixn` via [`incept_delegated_device`]. The device holds its
/// own key; the root only anchors. KERI delegation carries no timestamps, so no
/// clock is needed.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, identity storage, passphrase).
/// * `root_alias`: Keychain alias of the root identity's signing key.
/// * `device_alias`: Keychain alias to store the new device key under.
/// * `device_curve`: Curve for the new device key.
///
/// Usage:
/// ```ignore
/// let dev = add_device(&ctx, &root_alias, &device_alias, CurveType::Ed25519)?;
/// ```
pub fn add_device(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    device_alias: &KeyAlias,
    device_curve: auths_crypto::CurveType,
) -> Result<DeviceDelegationResult, DeviceError> {
    let managed = ctx.identity_storage.load_identity().map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("identity load failed: {e}"),
        }
    })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(DeviceError::CryptoError)?;

    let dev = incept_delegated_device(
        Arc::clone(&ctx.registry),
        &root_prefix,
        root_alias,
        root_curve,
        device_alias,
        device_curve,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(DeviceError::DelegationError)?;

    Ok(DeviceDelegationResult {
        device_did: dev.device_did.as_str().to_string(),
        device_prefix: dev.device_prefix.as_str().to_string(),
    })
}

/// Remove (revoke) a delegated device.
///
/// The root anchors a revocation marker for the device's delegated AID via
/// [`revoke_delegated_device`], so verifiers stop treating it as authorized.
/// Single-author — the root's current key signs; the device's key is not needed.
///
/// Args:
/// * `ctx`: Auths context.
/// * `root_alias`: Keychain alias of the root identity's signing key.
/// * `device_did`: The delegated device's `did:keri:` to revoke.
///
/// Usage:
/// ```ignore
/// remove_device(&ctx, &root_alias, "did:keri:E...")?;
/// ```
pub fn remove_device(
    ctx: &AuthsContext,
    root_alias: &KeyAlias,
    device_did: &str,
) -> Result<(), DeviceError> {
    let managed = ctx.identity_storage.load_identity().map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("identity load failed: {e}"),
        }
    })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let device_prefix = parse_did_keri(device_did).map_err(|e| DeviceError::DeviceNotFound {
        did: format!("invalid device did:keri: {e}"),
    })?;
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(DeviceError::CryptoError)?;

    revoke_delegated_device(
        ctx.registry.as_ref(),
        &root_prefix,
        root_alias,
        root_curve,
        &device_prefix,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .map_err(DeviceError::DelegationError)
}

/// A device delegated by the current identity, with its revocation status.
pub struct DeviceDelegationInfo {
    /// The delegated device's `did:keri:`.
    pub device_did: String,
    /// Whether the root has revoked the delegation.
    pub revoked: bool,
}

/// List the devices delegated by the current identity (the delegation set), each
/// tagged with whether it has been revoked. The live set is the non-revoked
/// entries — this replaces attestation-based device aggregation for the
/// delegation model.
///
/// Args:
/// * `ctx`: Auths context.
///
/// Usage:
/// ```ignore
/// let live = list_delegated_devices(&ctx)?.into_iter().filter(|d| !d.revoked).count();
/// ```
pub fn list_delegated_devices(ctx: &AuthsContext) -> Result<Vec<DeviceDelegationInfo>, DeviceError> {
    let managed = ctx.identity_storage.load_identity().map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("identity load failed: {e}"),
        }
    })?;
    let root_prefix = parse_did_keri(managed.controller_did.as_str()).map_err(|e| {
        DeviceError::IdentityNotFound {
            did: format!("invalid root did:keri: {e}"),
        }
    })?;
    let devices = id_list_delegated_devices(ctx.registry.as_ref(), &root_prefix)
        .map_err(DeviceError::DelegationError)?;
    Ok(devices
        .into_iter()
        .map(|d| DeviceDelegationInfo {
            device_did: format!("did:keri:{}", d.device_prefix),
            revoked: d.revoked,
        })
        .collect())
}
