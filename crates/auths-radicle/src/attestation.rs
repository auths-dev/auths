//! RIP-X 2-blob attestation format.
//!
//! Radicle stores attestation signatures as two separate Git blobs:
//! - `did-key`: device signature (Ed25519)
//! - `did-keri`: identity signature (Ed25519)
//!
//! The canonical signing payload is `(RID, other_DID)` serialized via
//! JSON Canonicalization Scheme (RFC 8785).
//!
//! This module keeps `RadAttestation` separate from the core `Attestation`
//! to prevent the core from becoming a "God Object." The bridge converts
//! between formats at the boundary.

use ring::signature::UnparsedPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical signing payload for RIP-X 2-way attestations.
///
/// Fields are ordered alphabetically for JCS (RFC 8785) stability:
/// `did` before `rid` lexicographically.
///
/// Args:
/// * `did`: The DID of the "other" party (device signs identity DID, identity signs device DID).
/// * `rid`: The Radicle Repository ID binding this attestation to a specific repo.
///
/// Usage:
/// ```ignore
/// let payload = RadCanonicalPayload {
///     did: "did:keri:EXq5abc".into(),
///     rid: "rad:z3gqabc".into(),
/// };
/// let bytes = payload.canonicalize();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadCanonicalPayload {
    pub did: String,
    pub rid: String,
}

impl RadCanonicalPayload {
    /// Produces the JCS-canonical byte representation for signing/verification.
    pub fn canonicalize(&self) -> Vec<u8> {
        json_canon::to_vec(self).expect("RadCanonicalPayload is always serializable")
    }
}

/// Errors from RIP-X attestation operations.
#[derive(Debug, Error)]
pub enum RadAttestationError {
    #[error("device signature verification failed")]
    DeviceSignatureFailed,

    #[error("identity signature verification failed")]
    IdentitySignatureFailed,

    #[error("empty blob: {0}")]
    EmptyBlob(String),
}

/// RIP-X 2-blob attestation.
///
/// Represents a mutual attestation between a device key (`did:key`) and a
/// KERI identity (`did:keri`), stored as two separate Git blobs under
/// `refs/keys/<nid>/signatures/`.
///
/// Usage:
/// ```ignore
/// let att = RadAttestation::from_blobs(&did_key_bytes, &did_keri_bytes, payload);
/// att.verify(&device_pubkey, &identity_pubkey)?;
/// ```
#[derive(Debug, Clone)]
pub struct RadAttestation {
    pub device_signature: Vec<u8>,
    pub identity_signature: Vec<u8>,
    pub canonical_payload: RadCanonicalPayload,
}

impl RadAttestation {
    /// Constructs from raw blob contents and the signing payload.
    ///
    /// Args:
    /// * `did_key_blob`: Raw bytes from the `did-key` Git blob (device signature).
    /// * `did_keri_blob`: Raw bytes from the `did-keri` Git blob (identity signature).
    /// * `payload`: The canonical payload that was signed.
    ///
    /// Usage:
    /// ```ignore
    /// let att = RadAttestation::from_blobs(&dk_bytes, &dkeri_bytes, payload);
    /// ```
    pub fn from_blobs(
        did_key_blob: &[u8],
        did_keri_blob: &[u8],
        payload: RadCanonicalPayload,
    ) -> Result<Self, RadAttestationError> {
        if did_key_blob.is_empty() {
            return Err(RadAttestationError::EmptyBlob("did-key".into()));
        }
        if did_keri_blob.is_empty() {
            return Err(RadAttestationError::EmptyBlob("did-keri".into()));
        }
        Ok(Self {
            device_signature: did_key_blob.to_vec(),
            identity_signature: did_keri_blob.to_vec(),
            canonical_payload: payload,
        })
    }

    /// Serializes back to two blobs: `(did-key bytes, did-keri bytes)`.
    ///
    /// Usage:
    /// ```ignore
    /// let (dk, dkeri) = att.to_blobs();
    /// ```
    pub fn to_blobs(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.device_signature.clone(),
            self.identity_signature.clone(),
        )
    }

    /// Verifies both signatures against the canonical payload.
    ///
    /// The device key signs `(RID, identity_DID)` and the identity key signs
    /// `(RID, device_DID)`. Both must verify for the attestation to be valid.
    ///
    /// Args:
    /// * `device_pubkey`: The device's Ed25519 public key (32 bytes).
    /// * `identity_pubkey`: The identity's Ed25519 public key (32 bytes).
    ///
    /// Usage:
    /// ```ignore
    /// att.verify(&device_pk, &identity_pk)?;
    /// ```
    pub fn verify(
        &self,
        device_pubkey: &[u8; 32],
        identity_pubkey: &[u8; 32],
    ) -> Result<(), RadAttestationError> {
        let canonical = self.canonical_payload.canonicalize();

        let device_vk =
            UnparsedPublicKey::new(&ring::signature::ED25519, device_pubkey.as_slice());
        device_vk
            .verify(&canonical, &self.device_signature)
            .map_err(|_| RadAttestationError::DeviceSignatureFailed)?;

        let identity_vk =
            UnparsedPublicKey::new(&ring::signature::ED25519, identity_pubkey.as_slice());
        identity_vk
            .verify(&canonical, &self.identity_signature)
            .map_err(|_| RadAttestationError::IdentitySignatureFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn sign(keypair: &Ed25519KeyPair, data: &[u8]) -> Vec<u8> {
        keypair.sign(data).as_ref().to_vec()
    }

    fn make_test_attestation() -> (RadAttestation, Ed25519KeyPair, Ed25519KeyPair) {
        let device_kp = make_keypair();
        let identity_kp = make_keypair();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let canonical = payload.canonicalize();

        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        let att = RadAttestation::from_blobs(&device_sig, &identity_sig, payload).unwrap();
        (att, device_kp, identity_kp)
    }

    #[test]
    fn canonical_payload_jcs_ordering() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let bytes = payload.canonicalize();
        let s = std::str::from_utf8(&bytes).unwrap();
        // JCS orders keys alphabetically: "did" < "rid"
        let did_pos = s.find("\"did\"").unwrap();
        let rid_pos = s.find("\"rid\"").unwrap();
        assert!(did_pos < rid_pos, "JCS: 'did' must precede 'rid'");
    }

    #[test]
    fn round_trip_blobs() {
        let (att, _, _) = make_test_attestation();
        let (dk, dkeri) = att.to_blobs();
        let att2 =
            RadAttestation::from_blobs(&dk, &dkeri, att.canonical_payload.clone()).unwrap();
        assert_eq!(att.device_signature, att2.device_signature);
        assert_eq!(att.identity_signature, att2.identity_signature);
    }

    #[test]
    fn verify_valid_signatures() {
        let (att, device_kp, identity_kp) = make_test_attestation();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();
        att.verify(&device_pk, &identity_pk).unwrap();
    }

    #[test]
    fn reject_swapped_blobs() {
        let (att, device_kp, identity_kp) = make_test_attestation();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();

        // Swap the signatures
        let swapped = RadAttestation {
            device_signature: att.identity_signature.clone(),
            identity_signature: att.device_signature.clone(),
            canonical_payload: att.canonical_payload.clone(),
        };
        assert!(swapped.verify(&device_pk, &identity_pk).is_err());
    }

    #[test]
    fn reject_tampered_rid() {
        let device_kp = make_keypair();
        let identity_kp = make_keypair();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let canonical = payload.canonicalize();
        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        // Tamper: different RID
        let tampered_payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:TAMPERED".into(),
        };
        let att =
            RadAttestation::from_blobs(&device_sig, &identity_sig, tampered_payload).unwrap();

        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();
        assert!(att.verify(&device_pk, &identity_pk).is_err());
    }

    #[test]
    fn reject_truncated_blob() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        // Truncated signature (not 64 bytes)
        let short = vec![1, 2, 3];
        let att = RadAttestation::from_blobs(&short, &short, payload).unwrap();
        let pk = [0u8; 32];
        assert!(att.verify(&pk, &pk).is_err());
    }

    #[test]
    fn reject_empty_blobs() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        assert!(RadAttestation::from_blobs(&[], &[1], payload.clone()).is_err());
        assert!(RadAttestation::from_blobs(&[1], &[], payload).is_err());
    }
}
