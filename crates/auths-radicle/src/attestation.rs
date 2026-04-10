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

use auths_verifier::core::{Attestation, Ed25519Signature, ResourceId};
use auths_verifier::types::CanonicalDid;
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;
#[cfg(feature = "std")]
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
///     did: "did:keri:EXq5abc".parse()?,
///     rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse()?,
/// };
/// let bytes = payload.canonicalize()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadCanonicalPayload {
    pub did: Did,
    pub rid: RepoId,
}

impl RadCanonicalPayload {
    /// Produces the JCS-canonical byte representation for signing/verification.
    ///
    /// Returns an error if serialization fails (should not happen for valid payloads).
    pub fn canonicalize(&self) -> Result<Vec<u8>, AttestationConversionError> {
        json_canon::to_vec(self)
            .map_err(|e| AttestationConversionError::Serialization(e.to_string()))
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

    #[error("invalid DID: {0}")]
    InvalidDid(#[from] radicle_core::identity::DidError),

    #[error("invalid RID: {0}")]
    InvalidRid(#[from] radicle_core::repo::IdError),
}

/// Errors from attestation format conversion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestationConversionError {
    #[error("device public key must be 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("JCS serialization failed: {0}")]
    Serialization(String),

    #[error("invalid DID: {0}")]
    InvalidDid(#[from] radicle_core::identity::DidError),

    #[error("invalid RID: {0}")]
    InvalidRid(#[from] radicle_core::repo::IdError),
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
///     device_did, device_pk,
/// )?;
/// let core_att: Attestation = att.try_into()?;
/// ```
#[derive(Debug, Clone)]
pub struct RadAttestation {
    pub device_signature: Vec<u8>,
    pub identity_signature: Vec<u8>,
    pub canonical_payload: RadCanonicalPayload,
    pub device_did: Did,
    pub device_public_key: PublicKey,
}

impl RadAttestation {
    /// Constructs from raw blob contents, signing payload, and device context.
    ///
    /// Args:
    /// * `did_key_blob`: Raw bytes from the `did-key` Git blob (device signature).
    /// * `did_keri_blob`: Raw bytes from the `did-keri` Git blob (identity signature).
    /// * `payload`: The canonical payload that was signed.
    /// * `device_did`: The device's DID (`did:key:z6Mk...`), from the ref path.
    /// * `device_public_key`: The device's Ed25519 public key.
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
        device_did: Did,
        device_public_key: PublicKey,
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
    /// Requires the `std` feature (uses `ring` for Ed25519 verification).
    ///
    /// Args:
    /// * `device_pubkey`: The device's Ed25519 public key.
    /// * `identity_pubkey`: The identity's Ed25519 public key.
    ///
    /// Usage:
    /// ```ignore
    /// att.verify(&device_pk, &identity_pk)?;
    /// ```
    #[cfg(feature = "std")]
    pub fn verify(
        &self,
        device_pubkey: &PublicKey,
        identity_pubkey: &PublicKey,
    ) -> Result<(), RadAttestationError> {
        let canonical = self
            .canonical_payload
            .canonicalize()
            .map_err(|_| RadAttestationError::DeviceSignatureFailed)?;

        let device_vk = UnparsedPublicKey::new(&ring::signature::ED25519, device_pubkey.as_ref());
        device_vk
            .verify(&canonical, &self.device_signature)
            .map_err(|_| RadAttestationError::DeviceSignatureFailed)?;

        let identity_vk =
            UnparsedPublicKey::new(&ring::signature::ED25519, identity_pubkey.as_ref());
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
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: rad.canonical_payload.did is a validated radicle Did
        let issuer = CanonicalDid::new_unchecked(rad.canonical_payload.did.to_string());
        #[allow(clippy::disallowed_methods)] // INVARIANT: rad.device_did is a validated radicle Did
        let subject = CanonicalDid::new_unchecked(rad.device_did.to_string());
        Ok(Attestation {
            version: 1,
            rid: ResourceId::new(rad.canonical_payload.rid.to_string()),
            issuer,
            subject,
            device_public_key: auths_verifier::DevicePublicKey::from_bytes(
                rad.device_public_key.as_ref(),
            ),
            identity_signature: Ed25519Signature::try_from_slice(&rad.identity_signature).map_err(
                |_| {
                    AttestationConversionError::InvalidPublicKeyLength(rad.identity_signature.len())
                },
            )?,
            device_signature: Ed25519Signature::try_from_slice(&rad.device_signature).map_err(
                |_| AttestationConversionError::InvalidPublicKeyLength(rad.device_signature.len()),
            )?,
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
            environment_claim: None,
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
        let device_public_key: PublicKey = PublicKey::try_from(att.device_public_key.as_bytes())
            .map_err(|_| AttestationConversionError::InvalidPublicKeyLength(32))?;

        let canonical_payload = RadCanonicalPayload {
            did: att.issuer.as_str().parse()?,
            rid: att.rid.parse()?,
        };

        // Validate JCS serialization succeeds
        canonical_payload.canonicalize()?;

        Ok(RadAttestation {
            device_signature: att.device_signature.as_bytes().to_vec(),
            identity_signature: att.identity_signature.as_bytes().to_vec(),
            canonical_payload,
            device_did: att.subject.as_str().parse()?,
            device_public_key,
        })
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use auths_verifier::core::Ed25519PublicKey;
    use ring::signature::KeyPair;

    fn make_keypair() -> ring::signature::Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn sign(kp: &ring::signature::Ed25519KeyPair, msg: &[u8]) -> Vec<u8> {
        kp.sign(msg).as_ref().to_vec()
    }

    fn make_test_rad_attestation() -> (
        RadAttestation,
        ring::signature::Ed25519KeyPair,
        ring::signature::Ed25519KeyPair,
    ) {
        let device_kp = make_keypair();
        let identity_kp = make_keypair();
        let device_pk = PublicKey::try_from(device_kp.public_key().as_ref()).unwrap();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap(),
        };
        let canonical = payload.canonicalize().unwrap();

        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        let att = RadAttestation::from_blobs(
            &device_sig,
            &identity_sig,
            payload,
            "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"
                .parse()
                .unwrap(),
            device_pk,
        )
        .unwrap();
        (att, device_kp, identity_kp)
    }

    #[test]
    fn canonical_payload_jcs_ordering() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap(),
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
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap(),
        };
        let bytes1 = payload.canonicalize().unwrap();
        let bytes2 = payload.canonicalize().unwrap();
        assert_eq!(
            bytes1, bytes2,
            "JCS output must be byte-for-byte deterministic"
        );
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
        let device_pk = PublicKey::try_from(device_kp.public_key().as_ref()).unwrap();
        let identity_pk = PublicKey::try_from(identity_kp.public_key().as_ref()).unwrap();
        att.verify(&device_pk, &identity_pk).unwrap();
    }

    #[test]
    fn reject_swapped_blobs() {
        let (att, device_kp, identity_kp) = make_test_rad_attestation();
        let device_pk = PublicKey::try_from(device_kp.public_key().as_ref()).unwrap();
        let identity_pk = PublicKey::try_from(identity_kp.public_key().as_ref()).unwrap();

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
        let device_pk = PublicKey::try_from(device_kp.public_key().as_ref()).unwrap();

        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap(),
        };
        let canonical = payload.canonicalize().unwrap();
        let device_sig = sign(&device_kp, &canonical);
        let identity_sig = sign(&identity_kp, &canonical);

        let tampered_payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv6".parse().unwrap(),
        };
        let att = RadAttestation::from_blobs(
            &device_sig,
            &identity_sig,
            tampered_payload,
            "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"
                .parse()
                .unwrap(),
            device_pk,
        )
        .unwrap();

        let identity_pk = PublicKey::try_from(identity_kp.public_key().as_ref()).unwrap();
        assert!(att.verify(&device_pk, &identity_pk).is_err());
    }

    #[test]
    fn reject_empty_blobs() {
        let payload = RadCanonicalPayload {
            did: "did:keri:EXq5abc".parse().unwrap(),
            rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap(),
        };
        let device_pk = PublicKey::from([0u8; 32]);
        assert!(
            RadAttestation::from_blobs(
                &[],
                &[1],
                payload.clone(),
                "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"
                    .parse()
                    .unwrap(),
                device_pk,
            )
            .is_err()
        );
    }

    #[test]
    fn rad_attestation_to_core_attestation() {
        let (rad, _, _) = make_test_rad_attestation();
        let device_sig = rad.device_signature.clone();
        let identity_sig = rad.identity_signature.clone();
        let rid = rad.canonical_payload.rid;
        let identity_did = rad.canonical_payload.did.clone();
        let device_did = rad.device_did.clone();
        let device_pk = rad.device_public_key;

        let core: Attestation = rad.try_into().unwrap();

        assert_eq!(core.version, 1);
        assert_eq!(core.rid.as_str(), rid.to_string());
        assert_eq!(core.issuer.as_str(), identity_did.to_string());
        assert_eq!(core.subject.as_str(), device_did.to_string());
        assert_eq!(core.device_public_key.as_bytes(), device_pk.as_ref());
        assert_eq!(
            core.device_signature.as_bytes().as_slice(),
            device_sig.as_slice()
        );
        assert_eq!(
            core.identity_signature.as_bytes().as_slice(),
            identity_sig.as_slice()
        );
    }

    #[test]
    fn core_attestation_to_rad_attestation() {
        let device_pk_bytes = [0xABu8; 32];
        let device_pk = PublicKey::from(device_pk_bytes);
        let device_did = Did::from(device_pk);

        let core = Attestation {
            version: 1,
            rid: ResourceId::new("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            issuer: CanonicalDid::new_unchecked("did:keri:EXq5abc"),
            subject: CanonicalDid::new_unchecked(device_did.to_string()),
            device_public_key: Ed25519PublicKey::from_bytes(device_pk_bytes).into(),
            identity_signature: Ed25519Signature::from_bytes([0xCD; 64]),
            device_signature: Ed25519Signature::from_bytes([0xEF; 64]),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            commit_sha: None,
            commit_message: None,
            author: None,
            oidc_binding: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
            environment_claim: None,
        };

        let rad: RadAttestation = (&core).try_into().unwrap();

        assert_eq!(rad.canonical_payload.did.to_string(), "did:keri:EXq5abc");
        assert_eq!(
            rad.canonical_payload.rid.to_string(),
            "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
        );
        assert_eq!(rad.device_did, device_did);
        assert_eq!(rad.device_public_key, device_pk);
        assert_eq!(rad.device_signature, vec![0xEF; 64]);
        assert_eq!(rad.identity_signature, vec![0xCD; 64]);
    }
}
