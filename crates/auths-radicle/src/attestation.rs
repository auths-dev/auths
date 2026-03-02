//! RIP-X 2-blob attestation format.
//!
//! Radicle stores attestation signatures as two separate Git blobs:
//! - `did-key`: device signature (Ed25519)
//! - `did-keri`: identity signature (Ed25519)
//!
//! The canonical signing payload is `(RID, identity_DID)` serialized via
//! JSON Canonicalization Scheme (RFC 8785). Both parties sign the same payload.
//!
//! This module keeps `RadAttestation` separate from the core `Attestation`
//! to prevent the core from becoming a "God Object." The bridge converts
//! between formats at the boundary via `TryFrom` impls.

use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use auths_verifier::IdentityDID;
use ring::signature::UnparsedPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical signing payload for RIP-X 2-way attestations.
///
/// Both the device and identity sign this identical payload. The `did` field
/// is always the identity (KERI controller) DID, and `rid` is the Radicle
/// Repository ID binding this attestation to a specific project.
///
/// Fields are ordered alphabetically for JCS (RFC 8785) stability:
/// `did` before `rid` lexicographically.
///
/// Args:
/// * `did`: The identity (KERI controller) DID.
/// * `rid`: The Radicle Repository ID binding this attestation to a specific repo.
///
/// Usage:
/// ```ignore
/// let payload = RadCanonicalPayload {
///     did: "did:keri:EXq5abc".into(),
///     rid: "rad:z3gqabc".into(),
/// };
/// let bytes = payload.canonicalize()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadCanonicalPayload {
    pub did: String,
    pub rid: String,
}

impl RadCanonicalPayload {
    /// Produces the JCS-canonical byte representation for signing/verification.
    ///
    /// Returns an error if serialization fails (should not happen for valid payloads).
    pub fn canonicalize(&self) -> Result<Vec<u8>, AttestationConversionError> {
        json_canon::to_vec(self).map_err(|e| AttestationConversionError::Serialization(e.to_string()))
    }
}

/// Errors from RIP-X attestation operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RadAttestationError {
    #[error("device signature verification failed")]
    DeviceSignatureFailed,

    #[error("identity signature verification failed")]
    IdentitySignatureFailed,

    #[error("empty blob: {0}")]
    EmptyBlob(String),
}

/// Errors from attestation format conversion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestationConversionError {
    #[error("device public key must be 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("JCS serialization failed: {0}")]
    Serialization(String),
}

/// RIP-X 2-blob attestation.
///
/// Represents a mutual attestation between a device key (`did:key`) and a
/// KERI identity (`did:keri`), stored as two separate Git blobs under
/// `refs/keys/<nid>/signatures/`.
///
/// The `device_did` and `device_public_key` fields provide the device context
/// needed for conversion to/from the core `Attestation` type. They are populated
/// from the Git ref path when loading from storage.
///
/// Usage:
/// ```ignore
/// let att = RadAttestation::from_blobs(
///     &did_key_bytes, &did_keri_bytes, payload,
///     "did:key:z6MkDevice".into(), device_pk,
/// )?;
/// let core_att: Attestation = att.try_into()?;
/// ```
#[derive(Debug, Clone)]
pub struct RadAttestation {
    pub device_signature: Vec<u8>,
    pub identity_signature: Vec<u8>,
    pub canonical_payload: RadCanonicalPayload,
    pub device_did: String,
    pub device_public_key: [u8; 32],
}

impl RadAttestation {
    /// Constructs from raw blob contents, signing payload, and device context.
    ///
    /// Args:
    /// * `did_key_blob`: Raw bytes from the `did-key` Git blob (device signature).
    /// * `did_keri_blob`: Raw bytes from the `did-keri` Git blob (identity signature).
    /// * `payload`: The canonical payload that was signed.
    /// * `device_did`: The device's DID (`did:key:z6Mk...`), from the ref path.
    /// * `device_public_key`: The device's Ed25519 public key (32 bytes).
    ///
    /// Usage:
    /// ```ignore
    /// let att = RadAttestation::from_blobs(
    ///     &dk_bytes, &dkeri_bytes, payload,
    ///     device_did, device_pk,
    /// )?;
    /// ```
    pub fn from_blobs(
        did_key_blob: &[u8],
        did_keri_blob: &[u8],
        payload: RadCanonicalPayload,
        device_did: String,
        device_public_key: [u8; 32],
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
            device_did,
            device_public_key,
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
    /// Both the device and identity sign the same JCS-canonical `(did, rid)` payload.
    /// Both must verify for the attestation to be valid.
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
        let canonical = self
            .canonical_payload
            .canonicalize()
            .map_err(|_| RadAttestationError::DeviceSignatureFailed)?;

        let device_vk = UnparsedPublicKey::new(&ring::signature::ED25519, device_pubkey.as_slice());
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

/// 2-blob `RadAttestation` -> core `Attestation` (verification-ready JSON).
///
/// Fields not present in the 2-blob format (`revoked_at`, `expires_at`, etc.)
/// default to `None`/empty. In the RIP-X model, revocation is handled by
/// removing the attestation ref from the KEL, not by an embedded field.
impl TryFrom<RadAttestation> for Attestation {
    type Error = AttestationConversionError;

    fn try_from(rad: RadAttestation) -> Result<Self, Self::Error> {
        Ok(Attestation {
            version: 1,
            rid: rad.canonical_payload.rid,
            issuer: IdentityDID::new(&rad.canonical_payload.did),
            subject: DeviceDID::new(&rad.device_did),
            device_public_key: rad.device_public_key.to_vec(),
            identity_signature: rad.identity_signature,
            device_signature: rad.device_signature,
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        })
    }
}

/// Core `Attestation` -> 2-blob `RadAttestation` (for Git storage).
///
/// The `issuer` DID becomes the `canonical_payload.did`, and the `subject` DID
/// becomes `device_did`. The canonical payload is validated via JCS serialization.
impl TryFrom<&Attestation> for RadAttestation {
    type Error = AttestationConversionError;

    fn try_from(att: &Attestation) -> Result<Self, Self::Error> {
        let device_public_key: [u8; 32] = att
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                AttestationConversionError::InvalidPublicKeyLength(att.device_public_key.len())
            })?;

        let canonical_payload = RadCanonicalPayload {
            did: att.issuer.as_str().to_string(),
            rid: att.rid.clone(),
        };

        // Validate JCS serialization succeeds
        canonical_payload.canonicalize()?;

        Ok(RadAttestation {
            device_signature: att.device_signature.clone(),
            identity_signature: att.identity_signature.clone(),
            canonical_payload,
            device_did: att.subject.as_str().to_string(),
            device_public_key,
        })
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

    fn make_test_rad_attestation() -> (RadAttestation, Ed25519KeyPair, Ed25519KeyPair) {
        let device_kp = make_keypair();
        let identity_kp = make_keypair();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let canonical = payload.canonicalize().unwrap();

        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        let att = RadAttestation::from_blobs(
            &device_sig,
            &identity_sig,
            payload,
            "did:key:z6MkTestDevice".into(),
            device_pk,
        )
        .unwrap();
        (att, device_kp, identity_kp)
    }

    #[test]
    fn canonical_payload_jcs_ordering() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let bytes = payload.canonicalize().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let did_pos = s.find("\"did\"").unwrap();
        let rid_pos = s.find("\"rid\"").unwrap();
        assert!(did_pos < rid_pos, "JCS: 'did' must precede 'rid'");
    }

    #[test]
    fn canonical_payload_deterministic() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let bytes1 = payload.canonicalize().unwrap();
        let bytes2 = payload.canonicalize().unwrap();
        assert_eq!(bytes1, bytes2, "JCS output must be byte-for-byte deterministic");
    }

    #[test]
    fn round_trip_blobs() {
        let (att, _, _) = make_test_rad_attestation();
        let (dk, dkeri) = att.to_blobs();
        let att2 = RadAttestation::from_blobs(
            &dk,
            &dkeri,
            att.canonical_payload.clone(),
            att.device_did.clone(),
            att.device_public_key,
        )
        .unwrap();
        assert_eq!(att.device_signature, att2.device_signature);
        assert_eq!(att.identity_signature, att2.identity_signature);
    }

    #[test]
    fn verify_valid_signatures() {
        let (att, device_kp, identity_kp) = make_test_rad_attestation();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();
        att.verify(&device_pk, &identity_pk).unwrap();
    }

    #[test]
    fn reject_swapped_blobs() {
        let (att, device_kp, identity_kp) = make_test_rad_attestation();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();

        let swapped = RadAttestation {
            device_signature: att.identity_signature.clone(),
            identity_signature: att.device_signature.clone(),
            canonical_payload: att.canonical_payload.clone(),
            device_did: att.device_did.clone(),
            device_public_key: att.device_public_key,
        };
        assert!(swapped.verify(&device_pk, &identity_pk).is_err());
    }

    #[test]
    fn reject_tampered_rid() {
        let device_kp = make_keypair();
        let identity_kp = make_keypair();
        let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let canonical = payload.canonicalize().unwrap();
        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        let tampered_payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:TAMPERED".into(),
        };
        let att = RadAttestation::from_blobs(
            &device_sig,
            &identity_sig,
            tampered_payload,
            "did:key:z6MkTestDevice".into(),
            device_pk,
        )
        .unwrap();

        let identity_pk: [u8; 32] = identity_kp.public_key().as_ref().try_into().unwrap();
        assert!(att.verify(&device_pk, &identity_pk).is_err());
    }

    #[test]
    fn reject_truncated_blob() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let short = vec![1, 2, 3];
        let att = RadAttestation::from_blobs(
            &short,
            &short,
            payload,
            "did:key:z6MkTest".into(),
            [0u8; 32],
        )
        .unwrap();
        let pk = [0u8; 32];
        assert!(att.verify(&pk, &pk).is_err());
    }

    #[test]
    fn reject_empty_blobs() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        assert!(RadAttestation::from_blobs(
            &[],
            &[1],
            payload.clone(),
            "did:key:z6MkTest".into(),
            [0u8; 32],
        )
        .is_err());
        assert!(RadAttestation::from_blobs(
            &[1],
            &[],
            payload,
            "did:key:z6MkTest".into(),
            [0u8; 32],
        )
        .is_err());
    }

    // --- TryFrom conversion tests ---

    #[test]
    fn rad_attestation_to_core_attestation() {
        let (rad, _, _) = make_test_rad_attestation();
        let device_sig = rad.device_signature.clone();
        let identity_sig = rad.identity_signature.clone();
        let rid = rad.canonical_payload.rid.clone();
        let identity_did = rad.canonical_payload.did.clone();
        let device_did = rad.device_did.clone();
        let device_pk = rad.device_public_key;

        let core: Attestation = rad.try_into().unwrap();

        assert_eq!(core.version, 1);
        assert_eq!(core.rid, rid);
        assert_eq!(core.issuer.as_str(), identity_did);
        assert_eq!(core.subject.as_str(), device_did);
        assert_eq!(core.device_public_key, device_pk.to_vec());
        assert_eq!(core.identity_signature, identity_sig);
        assert_eq!(core.device_signature, device_sig);
        assert!(core.revoked_at.is_none());
        assert!(core.expires_at.is_none());
        assert!(core.capabilities.is_empty());
    }

    #[test]
    fn core_attestation_to_rad_attestation() {
        let core = Attestation {
            version: 1,
            rid: "rad:z3gqabc".to_string(),
            issuer: IdentityDID::new("did:keri:EXq5abc"),
            subject: DeviceDID::new("did:key:z6MkTestDevice"),
            device_public_key: vec![0xAB; 32],
            identity_signature: vec![0xCD; 64],
            device_signature: vec![0xEF; 64],
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };

        let rad: RadAttestation = (&core).try_into().unwrap();

        assert_eq!(rad.canonical_payload.did, "did:keri:EXq5abc");
        assert_eq!(rad.canonical_payload.rid, "rad:z3gqabc");
        assert_eq!(rad.device_did, "did:key:z6MkTestDevice");
        assert_eq!(rad.device_public_key, [0xAB; 32]);
        assert_eq!(rad.device_signature, vec![0xEF; 64]);
        assert_eq!(rad.identity_signature, vec![0xCD; 64]);
    }

    #[test]
    fn round_trip_attestation_conversion() {
        let (original_rad, _, _) = make_test_rad_attestation();
        let device_did = original_rad.device_did.clone();
        let device_pk = original_rad.device_public_key;
        let payload_did = original_rad.canonical_payload.did.clone();
        let payload_rid = original_rad.canonical_payload.rid.clone();
        let orig_device_sig = original_rad.device_signature.clone();
        let orig_identity_sig = original_rad.identity_signature.clone();

        let core: Attestation = original_rad.try_into().unwrap();
        let round_tripped: RadAttestation = (&core).try_into().unwrap();

        assert_eq!(round_tripped.device_signature, orig_device_sig);
        assert_eq!(round_tripped.identity_signature, orig_identity_sig);
        assert_eq!(round_tripped.canonical_payload.did, payload_did);
        assert_eq!(round_tripped.canonical_payload.rid, payload_rid);
        assert_eq!(round_tripped.device_did, device_did);
        assert_eq!(round_tripped.device_public_key, device_pk);
    }

    #[test]
    fn conversion_rejects_wrong_pubkey_length() {
        let core = Attestation {
            version: 1,
            rid: "rad:z3gqabc".to_string(),
            issuer: IdentityDID::new("did:keri:EXq5abc"),
            subject: DeviceDID::new("did:key:z6MkTestDevice"),
            device_public_key: vec![0xAB; 16], // wrong length
            identity_signature: vec![0xCD; 64],
            device_signature: vec![0xEF; 64],
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };

        let err = RadAttestation::try_from(&core).unwrap_err();
        assert!(matches!(err, AttestationConversionError::InvalidPublicKeyLength(16)));
    }

    #[test]
    fn jcs_canonical_form_byte_stable() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".into(),
            rid: "rad:z3gqabc".into(),
        };
        let bytes = payload.canonicalize().unwrap();
        let expected = br#"{"did":"did:keri:EXq5abc","rid":"rad:z3gqabc"}"#;
        assert_eq!(bytes, expected.to_vec(), "JCS output must be byte-for-byte stable");
    }
}
