//! Witness type conversions for git2 integration.
//!
//! This module provides conversions between [`EventHash`] and [`git2::Oid`]
//! to bridge the backend-agnostic core types with the git2-based storage layer.
//!
//! # Architecture
//!
//! ```text
//! auths-core (no git2)     auths-id (has git2)
//! ┌─────────────────┐      ┌───────────────────┐
//! │   EventHash     │ ←──→ │    git2::Oid      │
//! │  (20 bytes)     │      │   (20 bytes)      │
//! └─────────────────┘      └───────────────────┘
//! ```
//!
//! The [`EventHash`] type lives in `auths-core` and is backend-agnostic.
//! This module provides conversion functions needed to work with git2.
//!
//! # Why Functions Instead of From Traits?
//!
//! Rust's orphan rule prevents implementing `From<Oid> for EventHash` in this
//! crate because neither type is defined here. Instead, we provide explicit
//! conversion functions.

use auths_core::witness::EventHash;
use git2::Oid;

/// Convert a git2 OID to an EventHash.
///
/// # Example
///
/// ```rust,ignore
/// use git2::Oid;
/// use auths_id::witness::oid_to_event_hash;
///
/// let oid = Oid::from_str("0123456789abcdef0123456789abcdef01234567").unwrap();
/// let hash = oid_to_event_hash(oid);
/// ```
pub fn oid_to_event_hash(oid: Oid) -> EventHash {
    // INVARIANT: git2::Oid is always 20 bytes
    #[allow(clippy::expect_used)]
    let bytes: [u8; 20] = oid.as_bytes().try_into().expect("git2::Oid is 20 bytes");
    EventHash::from_bytes(bytes)
}

/// Convert an EventHash to a git2 OID.
///
/// # Example
///
/// ```rust,ignore
/// use git2::Oid;
/// use auths_core::witness::EventHash;
/// use auths_id::witness::event_hash_to_oid;
///
/// let hash = EventHash::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap();
/// let oid = event_hash_to_oid(hash);
/// ```
pub fn event_hash_to_oid(hash: EventHash) -> Oid {
    // INVARIANT: EventHash is always 20 bytes
    #[allow(clippy::expect_used)]
    Oid::from_bytes(hash.as_bytes()).expect("EventHash is 20 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_to_event_hash_works() {
        let oid = Oid::from_str("0123456789abcdef0123456789abcdef01234567").unwrap();
        let hash = oid_to_event_hash(oid);
        assert_eq!(hash.to_hex(), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn event_hash_to_oid_works() {
        let hash = EventHash::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap();
        let oid = event_hash_to_oid(hash);
        assert_eq!(oid.to_string(), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn roundtrip_oid_to_hash_to_oid() {
        let original = Oid::from_str("fedcba9876543210fedcba9876543210fedcba98").unwrap();
        let hash = oid_to_event_hash(original);
        let back = event_hash_to_oid(hash);
        assert_eq!(original, back);
    }

    #[test]
    fn roundtrip_hash_to_oid_to_hash() {
        let original = EventHash::from_hex("abcdef0123456789abcdef0123456789abcdef01").unwrap();
        let oid = event_hash_to_oid(original);
        let back = oid_to_event_hash(oid);
        assert_eq!(original, back);
    }
}
