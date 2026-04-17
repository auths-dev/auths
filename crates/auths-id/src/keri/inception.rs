//! KERI identity inception with proper pre-rotation.
//!
//! Creates a new KERI identity by:
//! 1. Generating two keypairs (current + next) for the chosen curve
//! 2. Computing next-key commitment
//! 3. Building and finalizing inception event with SAID
//! 4. Storing event in Git-backed KEL

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use auths_crypto::CurveType;

use crate::storage::registry::backend::{RegistryBackend, RegistryError};
use auths_crypto::Pkcs8Der;

/// Sign a message using a PKCS8-encoded key, dispatching on curve.
/// Public alias for use by `identity/initialize.rs`.
pub fn sign_with_pkcs8_for_init(
    curve: CurveType,
    pkcs8: &Pkcs8Der,
    message: &[u8],
) -> Result<Vec<u8>, InceptionError> {
    sign_with_pkcs8(curve, pkcs8, message)
}

fn sign_with_pkcs8(
    curve: CurveType,
    pkcs8: &Pkcs8Der,
    message: &[u8],
) -> Result<Vec<u8>, InceptionError> {
    match curve {
        CurveType::Ed25519 => {
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|e| InceptionError::KeyGeneration(format!("Ed25519 sign: {e}")))?;
            Ok(keypair.sign(message).as_ref().to_vec())
        }
        CurveType::P256 => {
            use p256::ecdsa::{SigningKey, signature::Signer};
            use p256::pkcs8::DecodePrivateKey;

            let signing_key = SigningKey::from_pkcs8_der(pkcs8.as_ref())
                .map_err(|e| InceptionError::KeyGeneration(format!("P-256 sign: {e}")))?;
            let sig: p256::ecdsa::Signature = signing_key.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Output of curve-agnostic key generation.
pub struct GeneratedKeypair {
    /// PKCS8 DER encoded keypair (zeroed on drop).
    pub pkcs8: Pkcs8Der,
    /// Raw public key bytes (32 for Ed25519, 33 for P-256 compressed).
    pub public_key: Vec<u8>,
    /// CESR-encoded public key string (e.g., "D..." or "1AAJ...").
    pub cesr_encoded: String,
}

/// Public alias for single-curve keypair generation.
///
/// Thin wrapper over [`generate_keypairs_for_init`]; preserved so existing
/// single-key callers (CLI, SDK workflows, tests) don't have to change when
/// multi-key inception lands.
pub fn generate_keypair_for_init(curve: CurveType) -> Result<GeneratedKeypair, InceptionError> {
    let mut out = generate_keypairs_for_init(&[curve])?;
    // INVARIANT: generate_keypairs_for_init rejects empty slices, so a slice
    // of length 1 yields a Vec of length 1.
    Ok(out.remove(0))
}

/// Generate N keypairs, one per entry in `curves`.
///
/// Accepts mixed curve lists (e.g. `[P256, P256, Ed25519]`). Returns the
/// keypairs in the same order as the input slice.
///
/// Args:
/// * `curves` — non-empty slice of curve choices, one per device slot.
///
/// Returns `InceptionError::KeyGeneration` if `curves` is empty.
///
/// Usage:
/// ```ignore
/// use auths_crypto::CurveType;
/// use auths_id::keri::inception::generate_keypairs_for_init;
/// let kps = generate_keypairs_for_init(&[CurveType::P256, CurveType::P256])?;
/// assert_eq!(kps.len(), 2);
/// ```
pub fn generate_keypairs_for_init(
    curves: &[CurveType],
) -> Result<Vec<GeneratedKeypair>, InceptionError> {
    if curves.is_empty() {
        return Err(InceptionError::KeyGeneration(
            "generate_keypairs_for_init requires at least one curve".to_string(),
        ));
    }
    curves.iter().map(|c| generate_keypair(*c)).collect()
}

/// Generate a keypair for the specified curve.
fn generate_keypair(curve: CurveType) -> Result<GeneratedKeypair, InceptionError> {
    match curve {
        CurveType::Ed25519 => {
            let rng = SystemRandom::new();
            let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
                .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
            let public_key = keypair.public_key().as_ref().to_vec();
            let cesr_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(&public_key));
            Ok(GeneratedKeypair {
                pkcs8: Pkcs8Der::new(pkcs8_doc.as_ref().to_vec()),
                public_key,
                cesr_encoded,
            })
        }
        CurveType::P256 => {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::rand_core::OsRng;
            use p256::pkcs8::EncodePrivateKey;

            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);

            // Compressed SEC1 public key (33 bytes)
            let compressed = verifying_key.to_encoded_point(true);
            let public_key = compressed.as_bytes().to_vec();

            // CESR encode with 1AAJ prefix (P-256 transferable)
            let cesr_encoded = format!("1AAI{}", URL_SAFE_NO_PAD.encode(&public_key));

            // PKCS8 DER encoding
            let pkcs8_doc = signing_key
                .to_pkcs8_der()
                .map_err(|e| InceptionError::KeyGeneration(format!("P-256 PKCS8: {e}")))?;
            let pkcs8 = Pkcs8Der::new(pkcs8_doc.as_bytes().to_vec());

            Ok(GeneratedKeypair {
                pkcs8,
                public_key,
                cesr_encoded,
            })
        }
    }
}

use auths_core::crypto::said::compute_next_commitment;

use super::event::{CesrKey, KeriSequence, Threshold, VersionString};
use super::types::{Prefix, Said};
use super::{Event, GitKel, IcpEvent, KelError, ValidationError, finalize_icp_event};
use crate::witness_config::WitnessConfig;

/// Error type for inception operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InceptionError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Storage error: {0}")]
    Storage(RegistryError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid threshold {threshold} for key_count={key_count}: {reason}")]
    InvalidThreshold {
        threshold: String,
        key_count: usize,
        reason: String,
    },
}

/// Validate that a threshold makes sense for a given key count.
///
/// - `Simple(n)` requires `n <= key_count` (can't need more sigs than keys).
/// - `Weighted(clauses)` requires every clause's length equal to `key_count`
///   (one weight per key) and the clause's max sum to be >= 1 (otherwise the
///   threshold is unsatisfiable).
///
/// Mirrors keripy's footgun check — reject at inception/rotation time, not at
/// signature-verification time.
pub(crate) fn validate_threshold_for_key_count(
    threshold: &Threshold,
    key_count: usize,
) -> Result<(), InceptionError> {
    let label = || match threshold {
        Threshold::Simple(n) => format!("Simple({n})"),
        Threshold::Weighted(clauses) => format!("Weighted({clauses:?})"),
    };
    match threshold {
        Threshold::Simple(n) => {
            if (*n as usize) > key_count {
                return Err(InceptionError::InvalidThreshold {
                    threshold: label(),
                    key_count,
                    reason: format!("threshold {n} exceeds key count {key_count}"),
                });
            }
            if *n == 0 && key_count > 0 {
                return Err(InceptionError::InvalidThreshold {
                    threshold: label(),
                    key_count,
                    reason: "threshold 0 with non-empty key list is unsatisfiable".to_string(),
                });
            }
        }
        Threshold::Weighted(clauses) => {
            if clauses.is_empty() {
                return Err(InceptionError::InvalidThreshold {
                    threshold: label(),
                    key_count,
                    reason: "weighted threshold with no clauses is unsatisfiable".to_string(),
                });
            }
            for (i, clause) in clauses.iter().enumerate() {
                if clause.len() != key_count {
                    return Err(InceptionError::InvalidThreshold {
                        threshold: label(),
                        key_count,
                        reason: format!(
                            "clause {i} has {} weights for {key_count} keys",
                            clause.len()
                        ),
                    });
                }
                // "Meetable" check: summing every weight must cross >= 1.
                let refs: Vec<&auths_keri::Fraction> = clause.iter().collect();
                if !auths_keri::Fraction::sum_meets_one(&refs) {
                    return Err(InceptionError::InvalidThreshold {
                        threshold: label(),
                        key_count,
                        reason: format!(
                            "clause {i} sum < 1 even with all keys signing (unsatisfiable)"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

impl auths_core::error::AuthsErrorInfo for InceptionError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::KeyGeneration(_) => "AUTHS-E4901",
            Self::Kel(_) => "AUTHS-E4902",
            Self::Storage(_) => "AUTHS-E4903",
            Self::Validation(_) => "AUTHS-E4904",
            Self::Serialization(_) => "AUTHS-E4905",
            Self::InvalidThreshold { .. } => "AUTHS-E4906",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::KeyGeneration(_) => None,
            Self::Kel(_) => Some("Check the KEL state; a KEL may already exist for this prefix"),
            Self::Storage(_) => Some("Check storage backend connectivity"),
            Self::Validation(_) => None,
            Self::Serialization(_) => None,
            Self::InvalidThreshold { .. } => Some(
                "Ensure the threshold count does not exceed the number of keys, and that weighted clauses have one weight per key summing to at least 1",
            ),
        }
    }
}

/// Result of a KERI identity inception.
pub struct InceptionResult {
    /// The KERI prefix (use with `did:keri:<prefix>`)
    pub prefix: Prefix,

    /// The current signing keypair (PKCS8 DER encoded, zeroed on drop)
    pub current_keypair_pkcs8: Pkcs8Der,

    /// The next rotation keypair (PKCS8 DER encoded, zeroed on drop)
    pub next_keypair_pkcs8: Pkcs8Der,

    /// The current public key (raw 32 bytes)
    pub current_public_key: Vec<u8>,

    /// The next public key (raw 32 bytes)
    pub next_public_key: Vec<u8>,
}

impl std::fmt::Debug for InceptionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InceptionResult")
            .field("prefix", &self.prefix)
            .field("current_keypair_pkcs8", &self.current_keypair_pkcs8)
            .field("next_keypair_pkcs8", &self.next_keypair_pkcs8)
            .field("current_public_key", &self.current_public_key)
            .field("next_public_key", &self.next_public_key)
            .finish()
    }
}

impl InceptionResult {
    /// Get the full DID for this identity.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix.as_str())
    }
}

/// Result of a multi-key KERI identity inception.
///
/// Each position in the `current_*` / `next_*` vectors corresponds to the
/// same device slot index: `current_keypairs_pkcs8[i]` signs at `k[i]`,
/// and its next-rotation counterpart is at `next_keypairs_pkcs8[i]`
/// committed at `n[i]`.
pub struct MultiKeyInceptionResult {
    pub prefix: Prefix,
    pub current_keypairs_pkcs8: Vec<Pkcs8Der>,
    pub next_keypairs_pkcs8: Vec<Pkcs8Der>,
    pub current_public_keys: Vec<Vec<u8>>,
    pub next_public_keys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for MultiKeyInceptionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiKeyInceptionResult")
            .field("prefix", &self.prefix)
            .field("device_count", &self.current_public_keys.len())
            .finish()
    }
}

impl MultiKeyInceptionResult {
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix.as_str())
    }
}

/// Create a multi-key KERI identity.
///
/// Generates `curves.len()` current keypairs and `curves.len()` next-rotation
/// keypairs. The inception event carries all current pubkeys in `k` and
/// commitment hashes of all next keypairs in `n`, with the supplied
/// `kt`/`nt` thresholds.
///
/// Signs with index 0's current key only — satisfying any `Simple(1)` or
/// single-slot threshold. Multi-device signature aggregation is wired
/// through the signing-workflow module, which adds additional
/// `IndexedSignature`s when `kt` is multi-slot.
///
/// Args:
/// * `repo` — Git repository for KEL storage.
/// * `witness_config` — Optional witness configuration.
/// * `now` — Current time (injected).
/// * `curves` — Non-empty slice of curve choices, one per device slot.
/// * `kt` — Signing threshold. Validated against `curves.len()`.
/// * `nt` — Rotation threshold. Validated against `curves.len()`.
pub fn create_keri_identity_multi(
    repo: &Repository,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
    curves: &[CurveType],
    kt: Threshold,
    nt: Threshold,
) -> Result<MultiKeyInceptionResult, InceptionError> {
    if curves.is_empty() {
        return Err(InceptionError::KeyGeneration(
            "create_keri_identity_multi requires at least one curve".to_string(),
        ));
    }
    validate_threshold_for_key_count(&kt, curves.len())?;
    validate_threshold_for_key_count(&nt, curves.len())?;

    let current_kps = generate_keypairs_for_init(curves)?;
    let next_kps = generate_keypairs_for_init(curves)?;

    let k: Vec<CesrKey> = current_kps
        .iter()
        .map(|kp| CesrKey::new_unchecked(kp.cesr_encoded.clone()))
        .collect();
    let n: Vec<Said> = next_kps
        .iter()
        .map(|kp| compute_next_commitment(&kp.public_key))
        .collect();

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.witness_urls
                .iter()
                .map(|u| Prefix::new_unchecked(u.to_string()))
                .collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt,
        k,
        nt,
        n,
        bt,
        b,
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    // Sign with index 0's key — produces a valid single-slot signature. The
    // multi-sig aggregation module can add additional sigs after the fact
    // if `kt` requires a quorum.
    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let _sig_bytes = sign_with_pkcs8(curves[0], &current_kps[0].pkcs8, &canonical)?;

    let kel = GitKel::new(repo, prefix.as_str());
    kel.create(&finalized, now)?;

    Ok(MultiKeyInceptionResult {
        prefix,
        current_keypairs_pkcs8: current_kps.iter().map(|kp| kp.pkcs8.clone()).collect(),
        next_keypairs_pkcs8: next_kps.iter().map(|kp| kp.pkcs8.clone()).collect(),
        current_public_keys: current_kps.into_iter().map(|kp| kp.public_key).collect(),
        next_public_keys: next_kps.into_iter().map(|kp| kp.public_key).collect(),
    })
}

/// Create a new KERI identity with proper pre-rotation.
///
/// This generates two Ed25519 keypairs:
/// - Current key: used for immediate signing
/// - Next key: committed to in the inception event for future rotation
///
/// The inception event is stored in the Git repository at:
/// `refs/did/keri/<prefix>/kel`
///
/// # Arguments
/// * `repo` - Git repository for KEL storage
/// * `witness_config` - Optional witness configuration. When provided and
///   enabled, the inception event's `bt`/`b` fields are set accordingly.
///
/// # Returns
/// * `InceptionResult` containing the prefix and both keypairs
pub fn create_keri_identity(
    repo: &Repository,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<InceptionResult, InceptionError> {
    create_keri_identity_with_curve(repo, witness_config, now, CurveType::P256)
}

/// Create a KERI identity with a specific curve type.
///
/// Args:
/// * `repo` — Git repository for KEL storage.
/// * `witness_config` — Optional witness configuration.
/// * `now` — Current time (injected, never use `Utc::now()` directly).
/// * `curve` — The elliptic curve to use (`P256` default, `Ed25519` available).
pub fn create_keri_identity_with_curve(
    repo: &Repository,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
    curve: CurveType,
) -> Result<InceptionResult, InceptionError> {
    // Generate current and next keypairs for the chosen curve
    let current = generate_keypair(curve)?;
    let next = generate_keypair(curve)?;

    let current_pub_encoded = current.cesr_encoded.clone();

    // Compute next-key commitment (Blake3 hash of the CESR-qualified next public key bytes)
    // The commitment is curve-agnostic: Blake3(raw_public_key_bytes)
    let next_commitment = compute_next_commitment(&next.public_key);

    // Determine witness fields from config
    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.witness_urls
                .iter()
                .map(|u| Prefix::new_unchecked(u.to_string()))
                .collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    // Build inception event (without SAID)
    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(current_pub_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt,
        b,
        c: vec![],
        a: vec![],
    };

    // Finalize event (computes and sets SAID)
    let finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    // Sign the event with the current key
    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let _sig_bytes = sign_with_pkcs8(curve, &current.pkcs8, &canonical)?;

    // Store in Git KEL
    let kel = GitKel::new(repo, prefix.as_str());
    kel.create(&finalized, now)?;

    // Collect witness receipts if configured
    #[cfg(feature = "witness-client")]
    if let Some(config) = witness_config
        && config.is_enabled()
    {
        let canonical_for_witness = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
        super::witness_integration::collect_and_store_receipts(
            repo.path().parent().unwrap_or(repo.path()),
            &prefix,
            &finalized.d,
            &canonical_for_witness,
            config,
            now,
        )
        .map_err(|e| InceptionError::Serialization(e.to_string()))?;
    }

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: current.pkcs8,
        next_keypair_pkcs8: next.pkcs8,
        current_public_key: current.public_key,
        next_public_key: next.public_key,
    })
}

/// Create a new KERI identity using any [`RegistryBackend`].
///
/// Identical logic to [`create_keri_identity`] but stores the inception event
/// via the provided backend instead of a git repository.
///
/// # Arguments
/// * `backend` - The registry backend to store the inception event
/// * `witness_config` - Unused in the backend path; kept for API symmetry
///
/// # Returns
/// * `InceptionResult` containing the prefix and both keypairs
pub fn create_keri_identity_with_backend(
    backend: &impl RegistryBackend,
    _witness_config: Option<&WitnessConfig>,
) -> Result<InceptionResult, InceptionError> {
    let rng = SystemRandom::new();

    let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(current_pub_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let sig = current_keypair.sign(&canonical);
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        sig: sig.as_ref().to_vec(),
    }])
    .map_err(|e| InceptionError::Serialization(e.to_string()))?;

    backend
        .append_signed_event(&prefix, &Event::Icp(finalized), &attachment)
        .map_err(InceptionError::Storage)?;

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Pkcs8Der::new(current_pkcs8.as_ref()),
        next_keypair_pkcs8: Pkcs8Der::new(next_pkcs8.as_ref()),
        current_public_key: current_keypair.public_key().as_ref().to_vec(),
        next_public_key: next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Create a KERI identity from an existing Ed25519 key (PKCS8 DER).
///
/// Used for migrating existing `did:key` identities to `did:keri`.
/// The provided key becomes the current signing key; a new next key
/// is generated for pre-rotation.
///
/// # Arguments
/// * `repo` - Git repository for KEL storage
/// * `current_pkcs8_bytes` - Existing Ed25519 key in PKCS8 v2 DER format
/// * `witness_config` - Optional witness configuration
/// * `now` - Timestamp for the inception event
pub fn create_keri_identity_from_key(
    repo: &Repository,
    current_pkcs8_bytes: &[u8],
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<InceptionResult, InceptionError> {
    let rng = SystemRandom::new();

    // Use the provided key as the current keypair
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8_bytes)
        .map_err(|e| InceptionError::KeyGeneration(format!("invalid PKCS8 key: {e}")))?;

    // Generate next keypair (for pre-rotation)
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.witness_urls
                .iter()
                .map(|u| Prefix::new_unchecked(u.to_string()))
                .collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(current_pub_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt,
        b,
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let _sig = current_keypair.sign(&canonical);

    let kel = GitKel::new(repo, prefix.as_str());
    kel.create(&finalized, now)?;

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Pkcs8Der::new(current_pkcs8_bytes),
        next_keypair_pkcs8: Pkcs8Der::new(next_pkcs8.as_ref()),
        current_public_key: current_keypair.public_key().as_ref().to_vec(),
        next_public_key: next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Format a KERI prefix as a full DID.
pub fn prefix_to_did(prefix: &str) -> String {
    format!("did:keri:{}", prefix)
}

/// Extract the prefix from a did:keri DID.
///
/// Prefer [`auths_verifier::IdentityDID`] at API boundaries for type safety.
pub fn did_to_prefix(did: &str) -> Option<&str> {
    did.strip_prefix("did:keri:")
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{Event, validate_kel};
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        // Set git config for CI environments
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    #[test]
    fn create_identity_returns_valid_result() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Prefix should start with 'E' (Blake3 SAID prefix)
        assert!(result.prefix.as_str().starts_with('E'));

        // Keys should be present
        assert!(!result.current_keypair_pkcs8.is_empty());
        assert!(!result.next_keypair_pkcs8.is_empty());
        assert_eq!(result.current_public_key.len(), 32);
        assert_eq!(result.next_public_key.len(), 32);

        // DID should be formatted correctly
        assert!(result.did().starts_with("did:keri:E"));
    }

    #[test]
    fn create_identity_stores_kel() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Verify KEL exists and has one event
        let kel = GitKel::new(&repo, result.prefix.as_str());
        assert!(kel.exists());

        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_inception());
    }

    #[test]
    fn inception_event_is_valid() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        // Validate the KEL
        let state = validate_kel(&events).unwrap();
        assert_eq!(state.prefix, result.prefix);
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
    }

    #[test]
    fn inception_event_has_correct_structure() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        if let Event::Icp(icp) = &events[0] {
            // Version
            assert_eq!(icp.v.kind, "JSON");

            // SAID equals prefix
            assert_eq!(icp.d.as_str(), icp.i.as_str());
            assert_eq!(icp.d.as_str(), result.prefix.as_str());

            // Sequence is 0
            assert_eq!(icp.s, KeriSequence::new(0));

            // Single key
            assert_eq!(icp.k.len(), 1);
            assert!(icp.k[0].as_str().starts_with('D')); // Ed25519 prefix

            // Single next commitment
            assert_eq!(icp.n.len(), 1);
            assert!(icp.n[0].as_str().starts_with('E')); // Blake3 hash prefix

            // No witnesses
            assert_eq!(icp.bt, Threshold::Simple(0));
            assert!(icp.b.is_empty());
        } else {
            panic!("Expected inception event");
        }
    }

    #[test]
    fn next_key_commitment_is_correct() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        if let Event::Icp(icp) = &events[0] {
            // Verify the next commitment matches the next public key
            let expected_commitment = compute_next_commitment(&result.next_public_key);
            assert_eq!(icp.n[0], expected_commitment);
        } else {
            panic!("Expected inception event");
        }
    }

    #[test]
    fn prefix_to_did_works() {
        assert_eq!(prefix_to_did("ETest123"), "did:keri:ETest123");
    }

    #[test]
    fn did_to_prefix_works() {
        assert_eq!(did_to_prefix("did:keri:ETest123"), Some("ETest123"));
        assert_eq!(did_to_prefix("did:key:z6Mk..."), None);
    }

    #[test]
    fn multiple_identities_have_different_prefixes() {
        let (_dir, repo) = setup_repo();

        let result1 = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Create second repo for second identity
        let (_dir2, repo2) = setup_repo();
        let result2 = create_keri_identity_with_curve(
            &repo2,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Prefixes should be different
        assert_ne!(result1.prefix, result2.prefix);
    }

    #[test]
    fn generate_keypairs_for_init_rejects_empty_slice() {
        let res = generate_keypairs_for_init(&[]);
        match res {
            Ok(_) => panic!("expected error on empty slice"),
            Err(InceptionError::KeyGeneration(msg)) => assert!(msg.contains("at least one")),
            Err(other) => panic!("expected KeyGeneration error, got {other:?}"),
        }
    }

    #[test]
    fn generate_keypairs_for_init_single_curve_matches_legacy() {
        // A one-element slice must produce exactly one keypair with the same
        // shape as the legacy single-curve entry point.
        let kps = generate_keypairs_for_init(&[auths_crypto::CurveType::P256]).unwrap();
        assert_eq!(kps.len(), 1);
        assert!(kps[0].cesr_encoded.starts_with("1AAI"));
        assert_eq!(kps[0].public_key.len(), 33);

        let legacy = generate_keypair_for_init(auths_crypto::CurveType::P256).unwrap();
        assert_eq!(legacy.public_key.len(), 33);
        assert!(legacy.cesr_encoded.starts_with("1AAI"));
    }

    #[test]
    fn generate_keypairs_for_init_mixed_curves_distinct_keys() {
        use auths_crypto::CurveType::{Ed25519, P256};
        let kps = generate_keypairs_for_init(&[P256, P256, Ed25519]).unwrap();
        assert_eq!(kps.len(), 3);

        // Per-entry curve dispatch: P-256 entries are 33 bytes with "1AAI"
        // CESR prefix; Ed25519 is 32 bytes with "D".
        assert_eq!(kps[0].public_key.len(), 33);
        assert!(kps[0].cesr_encoded.starts_with("1AAI"));
        assert_eq!(kps[1].public_key.len(), 33);
        assert!(kps[1].cesr_encoded.starts_with("1AAI"));
        assert_eq!(kps[2].public_key.len(), 32);
        assert!(kps[2].cesr_encoded.starts_with('D'));

        // Distinct keypairs (randomness check — pubkeys must differ).
        assert_ne!(kps[0].public_key, kps[1].public_key);
        assert_ne!(kps[0].public_key, kps[2].public_key);
        assert_ne!(kps[1].public_key, kps[2].public_key);
    }
}
