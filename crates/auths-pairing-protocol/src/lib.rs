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

// fn-129.T1: statically forbid `unsafe` in this crate. The pairing protocol
// has no `unsafe` today; this attribute freezes that invariant so future
// code cannot accidentally introduce a soundness hole around the ephemeral
// ECDH secret or the transport key.
#![forbid(unsafe_code)]

pub mod domain_separation;
pub mod envelope;
mod error;
#[cfg(feature = "pq-hybrid")]
pub mod pq_hybrid;
mod protocol;
mod response;
pub mod sas;
mod token;
pub mod types;

pub use envelope::{
    Envelope, EnvelopeError, EnvelopeSession, MAX_MESSAGES_PER_SESSION, Open, Sealed,
};
pub use error::ProtocolError;
pub use protocol::{
    CompletedPairing, Confirmed, Init, Paired, PairingFlow, PairingProtocol, Responded,
    ResponderResult, SasMatch, respond_to_pairing,
};
pub use response::{CurveTag, PairingResponse};
// The `SubkeyChain` wire type is always compiled in so every builder
// that constructs a `SubmitResponseRequest` can spell the field — a
// feature-gated field would require `#[cfg]` at every call site. The
// verifier logic (`verify_subkey_chain`, `build_binding_message_v1`,
// and the domain separator) is gated behind `subkey-chain-v1`. A
// daemon compiled without the feature that receives a request with
// `subkey_chain.is_some()` must reject with an explicit unsupported
// error — silent ignore is a security regression.
pub mod subkey_chain;
pub use sas::{
    TransportKey, decrypt_from_transport, derive_sas, derive_transport_key, format_sas_emoji,
    format_sas_numeric,
};
pub use subkey_chain::SubkeyChain;
#[cfg(feature = "subkey-chain-v1")]
pub use subkey_chain::{
    SUBKEY_CHAIN_V1_DOMAIN, SubkeyChainError, build_binding_message_v1, verify_subkey_chain,
};
pub use token::{KemSlot, PairingSession, PairingToken, normalize_short_code};
pub use types::*;
