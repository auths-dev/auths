//! Shared test utilities for Auths crates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod crypto {
    pub use auths_crypto::testing::{create_test_keypair, get_shared_keypair};
    // `seeded_p256_keypair` is intentionally NOT re-exported here: it is a
    // curve-specific helper and curve-specific names are confined to
    // `auths-crypto` (the curve-agnostic lint forbids them in higher layers).
    // Import it directly from `auths_crypto::testing` where a P-256 fixture is needed.
}

pub mod git;
