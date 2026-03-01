//! Test utilities for auths-core.
//!
//! This module provides in-memory implementations of key storage
//! and builders for creating test identities.
//!
//! # Feature Flag
//!
//! This module is only available when the `test-utils` feature is enabled:
//!
//! ```toml
//! [dev-dependencies]
//! auths_core = { version = "0.0.2", features = ["test-utils"] }
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use auths_core::testing::{get_test_memory_keychain, MemoryStorage, MemoryKeychainHandle};
//! use auths_core::storage::KeyStorage;
//!
//! // Get a fresh, cleared in-memory keychain for testing
//! let keychain = get_test_memory_keychain();
//!
//! // Use it like any other KeyStorage implementation
//! keychain.store_key("test-alias", &identity_did, &encrypted_data)?;
//! let (did, data) = keychain.load_key("test-alias")?;
//! ```
//!
//! # Components
//!
//! - [`MemoryStorage`] - The underlying in-memory storage struct
//! - [`MemoryKeychainHandle`] - A handle implementing [`KeyStorage`] trait
//! - [`get_test_memory_keychain`] - Factory function returning a cleared keychain
//! - [`TestIdentityBuilder`] - Fluent builder for creating test identities
//! - [`TestPassphraseProvider`] - Mock passphrase provider for tests
//!
//! [`KeyStorage`]: crate::storage::KeyStorage

mod builder;

// Re-export test utilities from storage::memory
pub use crate::storage::memory::{
    MEMORY_KEYCHAIN, MemoryKeychainHandle, MemoryStorage, get_test_memory_keychain,
};

// Re-export builder types
pub use builder::{TestIdentity, TestIdentityBuilder, TestPassphraseProvider};
