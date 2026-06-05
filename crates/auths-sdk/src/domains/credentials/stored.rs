//! The persisted credential envelope (`{acdc, signature}`).
//!
//! F.3's `anchor_tel_event` stores an opaque credential blob keyed by the credential
//! SAID. The pure verifier (F.5) needs both the ACDC *and* the issuer's detached
//! signature over `acdc.to_wire_bytes()` ([`auths_verifier::SignedAcdc`]), but that
//! type is not serializable. This module owns the on-disk blob format: a serializable
//! envelope the issue path writes and the verify path reads back into a `SignedAcdc`.

use auths_keri::Acdc;
use serde::{Deserialize, Serialize};

/// The credential blob stored under the issuer's namespace.
///
/// Serializes the ACDC body alongside the issuer's detached signature so the SDK
/// resolution layer can reconstruct the [`auths_verifier::SignedAcdc`] the pure
/// verifier consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The credential body.
    pub acdc: Acdc,
    /// The issuer's signature over `acdc.to_wire_bytes()`.
    pub signature: Vec<u8>,
}

impl StoredCredential {
    /// Serialize the envelope to its JSON blob bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let blob = StoredCredential { acdc, signature }.to_bytes()?;
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse a stored envelope back from its JSON blob bytes.
    ///
    /// Args:
    /// * `bytes`: The blob previously written by [`StoredCredential::to_bytes`].
    ///
    /// Usage:
    /// ```ignore
    /// let stored = StoredCredential::from_bytes(&blob)?;
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
