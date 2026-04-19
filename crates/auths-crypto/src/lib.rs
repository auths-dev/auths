//! Cryptographic primitives for Auths.
//!
//! This crate isolates key parsing, DID encoding, and pluggable verification
//! from concrete backends, keeping the core dependency-light.
//!
//! - [`provider`] — Pluggable [`CryptoProvider`] trait for Ed25519 verification
//! - [`did_key`] — DID:key ↔ Ed25519 encoding (`DidKeyError`, `did_key_to_ed25519`, etc.)

#[cfg(all(feature = "fips", not(target_arch = "wasm32")))]
pub mod aws_lc_provider;
#[cfg(all(feature = "cnsa", not(target_arch = "wasm32")))]
pub mod cnsa_provider;
pub mod did_key;
pub mod error;
pub mod hash256;
pub mod key_material;
pub mod key_ops;
pub mod pkcs8;
pub mod provider;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod ring_provider;
pub mod secret;
pub mod ssh;
#[cfg(feature = "wasm")]
pub mod webcrypto_provider;

#[cfg(all(feature = "fips", not(target_arch = "wasm32")))]
pub use aws_lc_provider::AwsLcProvider;
#[cfg(all(feature = "cnsa", not(target_arch = "wasm32")))]
pub use cnsa_provider::CnsaProvider;
pub use did_key::{
    DecodedDidKey, DidKeyError, did_key_decode, did_key_to_p256, ed25519_pubkey_to_did_keri,
};
pub use error::AuthsErrorInfo;
pub use hash256::Hash256;
pub use key_material::{build_ed25519_pkcs8_v2, parse_ed25519_key_material, parse_ed25519_seed};
pub use key_ops::{ParsedKey, TypedSeed, TypedSignerKey, parse_key_material};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use key_ops::{public_key as typed_public_key, sign as typed_sign};
pub use pkcs8::Pkcs8Der;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use provider::default_provider;
pub use provider::{
    CryptoError, CryptoProvider, CurveType, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN, SecureSeed, SeedDecodeError, decode_seed_hex,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use ring_provider::RingCryptoProvider;
pub use secret::Secret;
#[allow(deprecated)]
pub use ssh::openssh_pub_to_raw_ed25519;
pub use ssh::{SshKeyError, openssh_pub_to_raw};
#[cfg(all(any(test, feature = "test-utils"), not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testing;

#[cfg(feature = "wasm")]
pub use webcrypto_provider::WebCryptoProvider;
