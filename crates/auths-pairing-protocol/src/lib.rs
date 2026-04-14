// fn-114: crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]

//! Transport-agnostic pairing protocol for the auths identity system.
//!
//! This crate implements the cryptographic pairing protocol that allows
//! cross-device identity linking. It is intentionally free of transport
//! dependencies (no axum, tower-http, mdns-sd, reqwest) so that mobile
//! apps can use it with their own transport layer.

mod error;
mod protocol;
mod response;
pub mod sas;
mod token;
pub mod types;
mod x25519_pubkey;

pub use error::ProtocolError;
pub use protocol::{CompletedPairing, PairingProtocol, ResponderResult, respond_to_pairing};
pub use response::PairingResponse;
pub use sas::{
    TransportKey, decrypt_from_transport, derive_sas, derive_transport_key, format_sas_emoji,
    format_sas_numeric,
};
pub use token::{PairingSession, PairingToken, normalize_short_code};
pub use types::*;
pub use x25519_pubkey::X25519PublicKey;
