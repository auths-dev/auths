//! Transport-agnostic pairing protocol for the auths identity system.
//!
//! This crate implements the cryptographic pairing protocol that allows
//! cross-device identity linking. It is intentionally free of transport
//! dependencies (no axum, tower-http, mdns-sd, reqwest) so that mobile
//! apps can use it with their own transport layer.
//!
//! ## Curve choice
//!
//! The device's long-term **signing** curve (Ed25519 or P-256, carried via
//! the `curve` wire field on [`PairingResponse`]) is independent of the
//! **ephemeral ECDH** curve used for key agreement.
//!
//! We use **P-256 ECDH unconditionally**, regardless of signing curve.
//! Ephemeral keys are generated fresh per session (`p256::ecdh::EphemeralSecret::random`),
//! never reused, and have zero cryptographic relationship to the device's
//! long-term signing seed. There is no "signing-curve-to-ECDH-curve mapper"
//! and no need for one.
//!
//! **Why P-256 for ECDH:**
//! - P-256 is the workspace default curve, already a dependency for signing.
//! - iOS Secure Enclave is P-256 exclusively; Android StrongBox supports
//!   P-256 only for EC.
//! - Removes the X25519 dependency and the 32-byte pubkey ambiguity
//!   (X25519 and Ed25519 both produce 32-byte keys).
//! - Constant-time P-256 ECDH via the `p256` crate (RustCrypto, audited).
//!
//! See `docs/architecture/cryptography.md` → Wire-format Curve Tagging for
//! the workspace-wide curve-agnosticism rule.

mod error;
mod protocol;
mod response;
pub mod sas;
mod token;
pub mod types;

pub use error::ProtocolError;
pub use protocol::{CompletedPairing, PairingProtocol, ResponderResult, respond_to_pairing};
pub use response::PairingResponse;
pub use sas::{
    TransportKey, decrypt_from_transport, derive_sas, derive_transport_key, format_sas_emoji,
    format_sas_numeric,
};
pub use token::{PairingSession, PairingToken, normalize_short_code};
pub use types::*;
