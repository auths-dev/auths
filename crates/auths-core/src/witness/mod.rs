//! Witness infrastructure for split-view defense.
//!
//! This module provides the trait and types for implementing witnesses
//! that help detect split-view attacks on identity KELs.
//!
//! # Split-View Attack
//!
//! A **split-view attack** occurs when a malicious node shows different
//! versions of a Key Event Log (KEL) to different peers. Without witnesses,
//! there's no way to detect this equivocation.
//!
//! ```text
//! Attacker shows:
//!   KEL A → Peer 1    (key1 is current)
//!   KEL B → Peer 2    (key2 is current)
//!
//! Both peers think they have the "correct" view.
//! ```
//!
//! # Witness Role
//!
//! Witnesses observe identity heads and can report if they've seen
//! a different head for the same identity. This enables detection of
//! equivocation:
//!
//! ```text
//! Peer asks Witness: "What's the head of identity E123?"
//! Witness: "I see commit abc123"
//! Peer: "But my local copy shows def456..."
//! → Split-view detected!
//! ```
//!
//! # Sync vs Async Providers
//!
//! Two witness traits are provided:
//!
//! - [`WitnessProvider`]: Synchronous trait for local/cached operations
//! - [`AsyncWitnessProvider`]: Async trait for network-based operations
//!
//! Use the sync trait when blocking is acceptable (e.g., in-memory cache).
//! Use the async trait for HTTP-based witness servers.
//!
//! # Receipts
//!
//! When a witness accepts an event, it issues a [`Receipt`] - a signed
//! acknowledgment that can be verified later. Receipts enable:
//!
//! - Proof that an event was witnessed
//! - Duplicity detection (witnesses disagree on history)
//! - Threshold-based security (k-of-n witnesses must agree)
//!
//! # Limitations
//!
//! **Witnesses are NOT Byzantine fault tolerant.**
//!
//! - A single witness can be compromised or collude with the attacker
//! - Multiple witnesses (quorum) reduce risk but don't eliminate it
//! - Witnesses must be trusted to some degree
//!
//! For full BFT guarantees, consider transparency logs or blockchain anchoring.
//!
//! # Default: Disabled
//!
//! By default, witness checking is disabled via [`NoOpWitness`]. This is
//! appropriate for:
//! - Private repositories
//! - Single-user setups
//! - Systems with existing consistency mechanisms (e.g., Radicle gossip)
//!
//! Enable witness checks for public ecosystems where split-view attacks
//! are a concern.

mod async_provider;
mod collector;
mod duplicity;
mod error;
mod hash;
mod noop;
mod provider;
mod receipt;

// Feature-gated modules
#[cfg(feature = "witness-server")]
mod server;
#[cfg(feature = "witness-server")]
mod storage;

// Sync provider (backward compat)
pub use hash::{EventHash, EventHashParseError};
pub use noop::NoOpWitness;
pub use provider::WitnessProvider;

// Async provider and types
pub use async_provider::{AsyncWitnessProvider, NoOpAsyncWitness};
pub use error::{DuplicityEvidence, WitnessError, WitnessReport};
pub use receipt::{KERI_VERSION, RECEIPT_TYPE, Receipt, ReceiptBuilder};

// Collection and duplicity detection
pub use collector::{CollectionError, ReceiptCollector, ReceiptCollectorBuilder};
pub use duplicity::DuplicityDetector;

// Witness server (feature-gated)
#[cfg(feature = "witness-server")]
pub use server::{
    ErrorResponse, HeadResponse, HealthResponse, SubmitEventRequest, WitnessServerConfig,
    WitnessServerState, router as witness_router, run_server,
};
#[cfg(feature = "witness-server")]
pub use storage::WitnessStorage;
