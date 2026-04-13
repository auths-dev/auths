// fn-114: allow during curve-agnostic refactor; removed in fn-114.40.
#![allow(clippy::disallowed_methods)]

use std::sync::OnceLock;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Returns a shared, lazily initialized PKCS8-encoded Ed25519 keypair.
///
/// The keypair is generated once on first call and reused for all subsequent
/// calls within the same test binary. This eliminates the cost of repeated
/// key generation across tests.
///
/// Args:
/// * None
///
/// Usage:
/// ```ignore
/// let pkcs8_bytes = get_shared_keypair();
/// let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();
/// ```
pub fn get_shared_keypair() -> &'static [u8] {
    static KEYPAIR: OnceLock<Vec<u8>> = OnceLock::new();

    KEYPAIR.get_or_init(|| {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    })
}

/// Creates a deterministic Ed25519 keypair from a 32-byte seed.
///
/// Useful when tests need multiple distinct keypairs with reproducible output.
/// Returns both the `Ed25519KeyPair` (ring) and the raw 32-byte public key.
///
/// Args:
/// * `seed`: A 32-byte array used as the private key seed.
///
/// Usage:
/// ```ignore
/// let (keypair, public_key) = create_test_keypair(&[1u8; 32]);
/// ```
pub fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}

/// Generates a fresh random Ed25519 keypair.
///
/// Convenience wrapper for tests that need a unique keypair but don't care
/// about reproducibility.
///
/// Args:
/// * None
///
/// Usage:
/// ```ignore
/// let keypair = gen_keypair();
/// ```
pub fn gen_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}
