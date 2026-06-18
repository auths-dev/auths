//! Real end-to-end messaging across the FFI — mint an identity, publish a prekey
//! bundle, establish a pairwise session with a contact, and seal/open authenticated
//! messages. This replaces the stateless `seal_message` skeleton seam: the engine's
//! `Endpoint`/X3DH/relay are all built; this is the projection the SwiftUI shells drive.
//!
//! ## Security contract carried across the FFI
//! - **First-contact MITM is closed in the engine** ([`murmur_core::establish_initiator`]):
//!   the published signing key MUST derive the *scanned* AID, so an untrusted relay that
//!   swaps a bundle is rejected before any key agreement. The app passes the AID it
//!   scanned out-of-band; the bundle bytes come from the relay.
//! - **Open authenticates or rejects** — [`MurmurSession::open`] is the engine's
//!   `Endpoint::open`, which returns a uniform error for tamper / wrong key / unresolved
//!   sender / bad signature. The FFI never returns unverified plaintext and never
//!   distinguishes the failure cause (no decryption oracle).
//! - **Seed handling (DEMO build).** This path materialises the 32-byte device seed in
//!   the app and passes it across the FFI. That is acceptable for the demo only; the
//!   shipping path holds the seed in the Secure Enclave and signs off-Rust (mirroring
//!   `pairing.rs`). The seed is the single secret a device persists (Keychain); the X3DH
//!   prekey seeds are derived from it inside the engine.

use std::sync::Arc;

use murmur_core::{
    Handshake, Identity, OuterEnvelope, PrekeyBundle, establish_initiator_seeded,
    establish_responder_seeded, publish_bundle_seeded,
};
use serde::{Deserialize, Serialize};

use crate::MurmurError;

/// A freshly minted (or reloaded) identity. The `seed` is the single secret the app
/// persists (Keychain); `aid` + `signing_key` are public. (DEMO seed handling — see
/// the module note.)
#[derive(uniffi::Record)]
pub struct MintedIdentity {
    /// The self-certifying `did:keri:…` address derived from `signing_key`.
    pub aid: String,
    /// The KERI signing public key the AID commits to (`aid = SHA256(signing_key)`).
    pub signing_key: Vec<u8>,
    /// The 32-byte device seed to persist. DEMO: in production this never leaves the SE.
    pub seed: Vec<u8>,
}

/// An authenticated message opened from the relay: the cryptographically-verified
/// sender AID and the plaintext body.
#[derive(uniffi::Record)]
pub struct SealedMessage {
    /// The authenticated sender AID (post signature-verification — never the claimed one).
    pub from: String,
    /// The decrypted, authenticated message body.
    pub body: String,
    /// The stable 16-byte message id (authenticated). For recipient-side dedup + receipts
    /// + edit/delete once built; available to read today.
    pub message_id: Vec<u8>,
    /// The body's content type (`"text"` by default; authenticated).
    pub content_type: String,
    /// Per-message flags (0 by default; authenticated).
    pub flags: u32,
}

/// The mailbox + ciphertext decoded from an envelope frame (for the inbox-handshake path,
/// so Swift never hand-rolls the binary frame).
#[derive(uniffi::Record)]
pub struct EnvelopeParts {
    pub mailbox: String,
    pub ciphertext: Vec<u8>,
}

/// What gets published to the relay's prekey directory for an AID: the AID's signing
/// public key plus the signed bundle. A fetcher checks `signing_key` derives the AID it
/// scanned, then verifies the bundle under it — so the relay cannot substitute either.
#[derive(Serialize, Deserialize)]
struct PublishedBundle {
    signing_key: Vec<u8>,
    bundle: PrekeyBundle,
}

/// Fill a 32-byte buffer from the OS CSPRNG (via the p256 dep already linked).
fn random_seed() -> [u8; 32] {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// A fresh random 8-byte message id (when the app does not supply a stable one).
fn random_message_id() -> Vec<u8> {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    let mut id = [0u8; 8];
    OsRng.fill_bytes(&mut id);
    id.to_vec()
}

/// Encode an `(mailbox, ciphertext)` into the binary `OuterEnvelope` frame the relay
/// speaks — so the app builds the first-contact handshake envelope without hand-rolling
/// the frame format.
#[uniffi::export]
pub fn encode_envelope(mailbox: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, MurmurError> {
    let envelope = OuterEnvelope {
        to_mailbox: murmur_core::MailboxId::new(mailbox),
        ciphertext,
    };
    envelope.to_frame().map_err(MurmurError::from)
}

/// Decode a binary `OuterEnvelope` frame into its mailbox + ciphertext.
#[uniffi::export]
pub fn decode_envelope(frame: Vec<u8>) -> Result<EnvelopeParts, MurmurError> {
    let envelope = OuterEnvelope::from_frame(&frame).map_err(MurmurError::from)?;
    Ok(EnvelopeParts {
        mailbox: envelope.to_mailbox.as_str().to_string(),
        ciphertext: envelope.ciphertext,
    })
}

/// Coerce a Swift `Vec<u8>` into a 32-byte seed, or a malformed error.
fn seed32(bytes: &[u8]) -> Result<[u8; 32], MurmurError> {
    bytes
        .try_into()
        .map_err(|_| MurmurError::Malformed("seed must be 32 bytes".into()))
}

/// Mint a brand-new identity (random seed). The app persists `seed` and shows `aid`.
#[uniffi::export]
pub fn mint_identity() -> Result<MintedIdentity, MurmurError> {
    identity_from_seed(random_seed().to_vec())
}

/// Reload an identity from a persisted seed — returns the same AID every time.
#[uniffi::export]
pub fn identity_from_seed(seed: Vec<u8>) -> Result<MintedIdentity, MurmurError> {
    let seed = seed32(&seed)?;
    let identity = Identity::from_seed(seed)?;
    Ok(MintedIdentity {
        aid: identity.aid().as_str().to_string(),
        signing_key: identity.public_key().to_vec(),
        seed: seed.to_vec(),
    })
}

/// Build the bytes to publish to the relay's prekey directory for this device, so a
/// contact who scanned this AID can establish a session with it.
#[uniffi::export]
pub fn publish_bundle(seed: Vec<u8>) -> Result<Vec<u8>, MurmurError> {
    let seed = seed32(&seed)?;
    let (identity, bundle) = publish_bundle_seeded(seed)?;
    let published = PublishedBundle {
        signing_key: identity.public_key().to_vec(),
        bundle,
    };
    serde_json::to_vec(&published).map_err(|e| MurmurError::Malformed(e.to_string()))
}

/// A live pairwise session with one contact, driven by the app: seal outgoing messages,
/// open incoming ones, and read the two directional mailbox ids for the relay.
#[derive(uniffi::Object)]
pub struct MurmurSession {
    inner: murmur_core::ContactSession,
    /// The initiator's handshake bytes to deposit so the peer can establish its side.
    /// Empty for a session built as the responder.
    handshake: Vec<u8>,
}

#[uniffi::export]
impl MurmurSession {
    /// Establish as the **initiator**: the device scanned `scanned_peer_aid` out-of-band
    /// and fetched `published_bundle` (bytes from [`publish_bundle`]) from the relay.
    /// Rejects closed if the published key does not derive the scanned AID (MITM).
    #[uniffi::constructor]
    pub fn initiator(
        my_seed: Vec<u8>,
        scanned_peer_aid: String,
        published_bundle: Vec<u8>,
    ) -> Result<Arc<Self>, MurmurError> {
        let my_seed = seed32(&my_seed)?;
        let published: PublishedBundle = serde_json::from_slice(&published_bundle)
            .map_err(|e| MurmurError::Malformed(format!("published bundle: {e}")))?;
        let peer_aid = murmur_core::Aid::new(scanned_peer_aid);
        let ephemeral = random_seed();
        let (session, handshake) = establish_initiator_seeded(
            my_seed,
            ephemeral,
            &peer_aid,
            &published.signing_key,
            &published.bundle,
        )?;
        let handshake_bytes =
            serde_json::to_vec(&handshake).map_err(|e| MurmurError::Malformed(e.to_string()))?;
        Ok(Arc::new(Self {
            inner: session,
            handshake: handshake_bytes,
        }))
    }

    /// Establish as the **responder** from a drained handshake (the bytes the initiator
    /// deposited). Rejects closed if the handshake's key does not derive its claimed AID.
    #[uniffi::constructor]
    pub fn responder(my_seed: Vec<u8>, handshake_bytes: Vec<u8>) -> Result<Arc<Self>, MurmurError> {
        let my_seed = seed32(&my_seed)?;
        let handshake: Handshake = serde_json::from_slice(&handshake_bytes)
            .map_err(|e| MurmurError::Malformed(format!("handshake: {e}")))?;
        let session = establish_responder_seeded(my_seed, &handshake)?;
        Ok(Arc::new(Self {
            inner: session,
            handshake: Vec::new(),
        }))
    }

    /// The handshake bytes to deposit to the relay (initiator only; empty for responder).
    pub fn handshake(&self) -> Vec<u8> {
        self.handshake.clone()
    }

    /// Seal `body` for the peer — returns the JSON `OuterEnvelope` to `POST /deposit`.
    pub fn seal(&self, body: String) -> Result<Vec<u8>, MurmurError> {
        let envelope = self.inner.seal(&body)?;
        envelope.to_frame().map_err(MurmurError::from)
    }

    /// Seal with explicit end-to-end metadata. An empty `message_id` mints a fresh 16-byte
    /// one; a non-empty one MUST be 16 bytes (e.g. a stable id from the app's outbox so a
    /// re-send carries the same id for recipient dedup). `content_type`/`flags` are signed.
    pub fn seal_with(
        &self,
        body: String,
        content_type: String,
        flags: u32,
        message_id: Vec<u8>,
    ) -> Result<Vec<u8>, MurmurError> {
        let id = if message_id.is_empty() {
            random_message_id()
        } else {
            message_id
        };
        let envelope = self.inner.seal_with(&body, id, &content_type, flags)?;
        envelope.to_frame().map_err(MurmurError::from)
    }

    /// Open a JSON `OuterEnvelope` drained from this session's mailbox — authenticate or
    /// reject (uniform error; never unverified plaintext).
    pub fn open(&self, envelope_bytes: Vec<u8>) -> Result<SealedMessage, MurmurError> {
        let envelope = OuterEnvelope::from_frame(&envelope_bytes).map_err(MurmurError::from)?;
        let message = self.inner.open(&envelope)?;
        Ok(SealedMessage {
            from: message.from.as_str().to_string(),
            body: message.body,
            message_id: message.message_id.to_vec(),
            content_type: message.content_type,
            flags: message.flags,
        })
    }

    /// The mailbox id this side deposits under (the peer drains it). For `POST /deposit`
    /// the relay reads the mailbox from the envelope; this is exposed for diagnostics.
    pub fn deposit_mailbox(&self) -> String {
        self.inner.deposit_mailbox().to_string()
    }

    /// The mailbox id this side drains (`GET /drain/{mailbox}`).
    pub fn drain_mailbox(&self) -> String {
        self.inner.drain_mailbox().to_string()
    }

    /// The peer AID this session is with.
    pub fn peer_aid(&self) -> String {
        self.inner.peer().as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mint two identities, publish one bundle, establish both sides over the FFI types,
    /// and round-trip an authenticated message — the whole app-facing path in one test.
    #[test]
    fn ffi_session_round_trips_an_authenticated_message() {
        let alice = mint_identity().unwrap();
        let bob = mint_identity().unwrap();

        let bob_bundle = publish_bundle(bob.seed.clone()).unwrap();
        let alice_session =
            MurmurSession::initiator(alice.seed.clone(), bob.aid.clone(), bob_bundle).unwrap();
        let handshake = alice_session.handshake();
        assert!(!handshake.is_empty());

        let bob_session = MurmurSession::responder(bob.seed.clone(), handshake).unwrap();

        let envelope = alice_session.seal("hello bob".into()).unwrap();
        let opened = bob_session.open(envelope).unwrap();
        assert_eq!(opened.body, "hello bob");
        assert_eq!(opened.from, alice.aid);

        // Tampered ciphertext is rejected with a uniform error (no oracle).
        let mut bad = alice_session.seal("hello again".into()).unwrap();
        let n = bad.len();
        bad[n - 5] ^= 0xff;
        assert!(bob_session.open(bad).is_err());
    }

    /// A relay that serves a DIFFERENT identity's bundle for the scanned AID is rejected.
    #[test]
    fn ffi_rejects_a_mitm_bundle() {
        let alice = mint_identity().unwrap();
        let bob = mint_identity().unwrap();
        let mallory = mint_identity().unwrap();

        // The relay serves Mallory's published bundle while Alice scanned Bob's AID.
        let mallory_bundle = publish_bundle(mallory.seed.clone()).unwrap();
        let attempt = MurmurSession::initiator(alice.seed, bob.aid, mallory_bundle);
        assert!(attempt.is_err(), "a bundle not bound to the scanned AID must be rejected");
    }
}
