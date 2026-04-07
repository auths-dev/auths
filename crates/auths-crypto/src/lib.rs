//! Cryptographic primitives for Auths.
//!
//! This crate isolates key parsing, DID encoding, and pluggable verification
//! from concrete backends, keeping the core dependency-light.
//!
//! - [`provider`] — Pluggable [`CryptoProvider`] trait for Ed25519 verification
//! - [`did_key`] — DID:key ↔ Ed25519 encoding (`DidKeyError`, `did_key_to_ed25519`, etc.)

pub mod did_key;
pub mod error;
pub mod key_material;
pub mod pkcs8;
pub mod provider;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod ring_provider;
pub mod ssh;
#[cfg(feature = "wasm")]
pub mod webcrypto_provider;

pub use did_key::{
    DidKeyError, did_key_to_ed25519, ed25519_pubkey_to_did_keri, ed25519_pubkey_to_did_key,
};
pub use error::AuthsErrorInfo;
pub use key_material::{build_ed25519_pkcs8_v2, parse_ed25519_key_material, parse_ed25519_seed};
pub use pkcs8::Pkcs8Der;
pub use provider::{
    CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, SecureSeed,
    SeedDecodeError, decode_seed_hex,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use ring_provider::RingCryptoProvider;
pub use ssh::{SshKeyError, openssh_pub_to_raw_ed25519};
#[cfg(all(any(test, feature = "test-utils"), not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testing;

#[cfg(feature = "wasm")]
pub use webcrypto_provider::WebCryptoProvider;
