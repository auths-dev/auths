//! The address — a self-certifying identifier (AID), not a phone number.
//!
//! An AID is the destination of every message. It is an identity, not a network
//! location, so routing (where the bytes actually go) is resolved separately —
//! see [`crate::relay`]. A pairwise AID can be handed to each contact so nothing
//! on the wire links a person's contacts to each other.

use serde::{Deserialize, Serialize};

/// A self-certifying identifier used as a Murmur address. SKELETON: this wraps
/// the textual `did:keri:…` / `did:webs:…` form; the cryptographic derivation
/// and KEL replay live in the auths engine and are not wired here yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Aid(String);

impl Aid {
    /// Wrap a textual AID. SKELETON: no validation of the self-addressing form.
    pub fn new(text: impl Into<String>) -> Self {
        Aid(text.into())
    }

    /// The textual form (`did:keri:…` or a projected `did:webs:…` name).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A stand-in AID for tests and skeleton call sites.
    pub fn placeholder() -> Self {
        Aid("did:keri:placeholder".into())
    }
}

impl std::fmt::Display for Aid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
