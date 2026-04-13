// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
#![warn(missing_docs)]
//! # auths-core
//!
//! Core cryptographic primitives and secure key storage for Auths.
//!
//! This crate provides:
//! - **Secure key storage** via platform keychains (macOS, Windows, Linux)
//! - **Signing operations** through the [`signing::SecureSigner`] trait
//! - **Passphrase handling** with [`signing::PassphraseProvider`] abstraction
//! - **Error types** for all failure modes
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use auths_core::storage::keychain::get_platform_keychain;
//! use auths_core::signing::{StorageSigner, SecureSigner};
//!
//! // Get the platform-appropriate keychain
//! let keychain = get_platform_keychain()?;
//! let signer = StorageSigner::new(keychain);
//!
//! // Sign with a stored key
//! let signature = signer.sign_with_alias("my-key", &provider, b"message")?;
//! ```
//!
//! ## Feature Flags
//!
//! - `keychain-linux-secretservice` — Enable Linux Secret Service backend
//! - `keychain-windows` — Enable Windows Credential Manager backend
//! - `keychain-file-fallback` — Enable encrypted file storage fallback
//! - `crypto-secp256k1` — Enable secp256k1/BIP340 for Nostr
//! - `test-utils` — Export test utilities (e.g., in-memory keychain for testing)
//!
//! ## Platform Support
//!
//! | Platform | Keychain | Feature Required |
//! |----------|----------|-----------------|
//! | macOS/iOS | Keychain Services | (default) |
//! | Linux | Secret Service | `keychain-linux-secretservice` |
//! | Windows | Credential Manager | `keychain-windows` |
//! | Any | Encrypted file | `keychain-file-fallback` |

pub mod agent;
pub mod api;
pub mod config;
pub mod crypto;
pub mod error;
pub mod pairing;
pub mod paths;
pub mod policy;
pub mod ports;
pub mod proto;
pub mod server;
pub mod signing;
pub mod storage;
#[cfg(any(test, feature = "test-utils"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testing;
pub mod trust;
pub mod utils;
pub mod witness;

pub use agent::{AgentCore, AgentHandle, AgentSession};
// IMPORTANT: These agent client functions use Unix domain sockets and are only
// available on Unix. Do NOT remove this #[cfg(unix)] — it will break Windows CI.
#[cfg(unix)]
pub use agent::{
    AgentStatus, add_identity, agent_sign, check_agent_status, list_identities,
    remove_all_identities,
};
pub use crypto::{EncryptionAlgorithm, SignerKey};
pub use error::{AgentError, AuthsErrorInfo};
pub use signing::{KeychainPassphraseProvider, PrefilledPassphraseProvider};
