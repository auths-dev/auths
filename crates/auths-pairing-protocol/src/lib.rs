//! Transport-agnostic pairing protocol for the auths identity system.
//!
//! This crate implements the cryptographic pairing protocol that allows
//! cross-device identity linking. It is intentionally free of transport
//! dependencies (no axum, tower-http, mdns-sd, reqwest) so that mobile
//! apps can use it with their own transport layer.

mod error;
mod response;
mod token;
pub mod types;

pub use error::ProtocolError;
pub use response::PairingResponse;
pub use token::{PairingSession, PairingToken, normalize_short_code};
pub use types::*;
