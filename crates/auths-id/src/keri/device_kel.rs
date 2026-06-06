//! Per-device KEL — one KEL per physical device.
//!
//! A device KEL carries the identity of a single machine (laptop, phone,
//! CI runner). Its controller is the device's own key pair; pre-rotation
//! protects against key compromise without requiring cross-device
//! coordination. The `did:keri:` prefix is stable across rotations and
//! is what the shared identity KEL (see [`super::shared_kel`]) lists as
//! a controller.
//!
//! This module is a thin naming layer over the existing KEL-creation
//! entrypoints — device KELs are structurally ordinary KERI KELs with
//! the operational role of identifying a machine rather than the user.

use auths_crypto::CurveType;

use super::Prefix;

/// Opaque handle describing a freshly-inceptioned device KEL.
///
/// `prefix` is the `did:keri:` self-addressing identifier of the device —
/// stable across rotations. `inception_event_json` is the serialized
/// `icp` suitable for pairing / replication / verification by peers.
#[derive(Debug, Clone)]
pub struct DeviceKelArtifacts {
    pub prefix: Prefix,
    pub inception_event_json: String,
    pub curve: CurveType,
}

impl DeviceKelArtifacts {
    /// The device's `did:keri:` string.
    ///
    /// Usage:
    /// ```ignore
    /// let did = artifacts.did();
    /// ```
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix.as_str())
    }
}
