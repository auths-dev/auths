//! The address — a self-certifying identifier (AID), not a phone number.
//!
//! An AID is the destination of every message. It is an identity, not a network
//! location, so routing (where the bytes actually go) is resolved separately —
//! see [`crate::relay`]. A pairwise AID can be handed to each contact so nothing
//! on the wire links a person's contacts to each other.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A self-certifying identifier used as a Murmur address.
///
/// The address is *derived from the controlling public key*: [`from_public_key`]
/// digests the key into the textual `did:keri:…` form, so the AID and the key
/// are bound by construction — you cannot mint an AID for a key you do not hold,
/// and a resolver can check a presented key against the AID it claims (see
/// [`crate::identity::verify_sender`]). The full KERI form is the inception
/// event's self-addressing identifier over the same key material; this is the
/// digest binding the engine round-trips against until witnessed key-log replay
/// is wired. A human-readable `did:webs:…` name projects to the same key-state
/// and is still carried as the textual form via [`new`].
///
/// [`from_public_key`]: Aid::from_public_key
/// [`new`]: Aid::new
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Aid(String);

impl Aid {
    /// Wrap an already-textual AID (`did:keri:…`, or a projected `did:webs:…`
    /// name). Used when an address arrives over the wire or from a contact list;
    /// authentication still binds it to a key via [`Aid::from_public_key`].
    pub fn new(text: impl Into<String>) -> Self {
        Aid(text.into())
    }

    /// Derive the self-certifying AID from a controlling public key. The digest
    /// is deterministic, so the same key always yields the same address, and a
    /// different key never does — this is what makes the identifier *self*-
    /// certifying rather than assigned.
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let digest = Sha256::digest(public_key);
        // Lowercase hex of the digest as the method-specific id. A real KERI AID
        // is CESR base64url over the inception event; the property the engine
        // relies on — a stable, collision-resistant key→id binding — is the same.
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        Aid(format!("did:keri:{hex}"))
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
