// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]
#![warn(missing_docs)]
//! Append-only transparency log for Auths.
//!
//! Implements C2SP tlog-tiles Merkle tree types, proof verification,
//! signed note format, and tile storage abstractions.
//!
//! ## Feature Flags
//!
//! - `native` (default) — enables `TileStore` trait and async tile I/O
//! - Without features — WASM-safe core: types, Merkle math, proofs, notes

/// Offline verification bundles.
pub mod bundle;
/// Log checkpoint types.
pub mod checkpoint;
/// Transparency log entry types.
pub mod entry;
/// Error types for transparency operations.
pub mod error;
/// RFC 6962 Merkle tree operations.
pub mod merkle;
/// C2SP signed note format.
pub mod note;
/// Inclusion and consistency proof types.
pub mod proof;
/// Tile storage trait (behind `native` feature).
pub mod store;
/// C2SP tlog-tiles path encoding.
pub mod tile;
/// Core newtypes: `MerkleHash`, `LogOrigin`.
pub mod types;
/// Offline bundle verification (requires `native` feature for Ed25519).
#[cfg(feature = "native")]
pub mod verify;
/// Witness protocol for split-view protection (requires `native` feature).
#[cfg(feature = "native")]
pub mod witness;

// Re-export core types
pub use bundle::{
    BundleVerificationReport, CheckpointStatus, DelegationChainLink, DelegationStatus,
    InclusionStatus, NamespaceStatus, OfflineBundle, SignatureStatus, WitnessStatus,
};
pub use checkpoint::{Checkpoint, SignedCheckpoint, WitnessCosignature};
pub use entry::{AccessTier, Entry, EntryBody, EntryContent, EntryType};
pub use error::TransparencyError;
pub use merkle::{compute_root, hash_children, hash_leaf, verify_consistency, verify_inclusion};
pub use note::{
    NoteSignature, build_signature_line, compute_key_id, parse_signed_note, serialize_signed_note,
};
pub use proof::{ConsistencyProof, InclusionProof};
pub use tile::{TILE_HEIGHT, TILE_WIDTH, leaf_tile, tile_count, tile_path};
pub use types::{LogOrigin, MerkleHash};

#[cfg(feature = "native")]
mod fs_store;
#[cfg(feature = "native")]
pub use fs_store::FsTileStore;

#[cfg(feature = "s3")]
/// S3-compatible tile store (Tigris, AWS S3, MinIO).
pub mod s3_store;
#[cfg(feature = "s3")]
pub use s3_store::S3TileStore;

#[cfg(feature = "native")]
pub use store::TileStore;
#[cfg(feature = "native")]
pub use verify::verify_bundle;

#[cfg(feature = "native")]
pub use witness::{
    ALG_COSIGNATURE_V1, CosignRequest, CosignResponse, DEFAULT_WITNESS_TIMEOUT, WitnessClient,
    WitnessResult, build_cosignature_line, collect_witness_cosignatures, compute_witness_key_id,
    cosignature_signed_message, extract_cosignatures, parse_cosignature, serialize_cosignature,
};

use auths_verifier::DeviceDID;

/// Trust root for verifying transparency log checkpoints.
///
/// Contains the log's signing public key and an optional witness list.
/// For Epic 1 (fn-72), this is hardcoded in the verifier binary.
/// TUF-based distribution comes in fn-76.
///
/// Args:
/// * `log_public_key` — The Ed25519 public key of the log operator.
/// * `log_origin` — The log origin string for checkpoint verification.
/// * `witnesses` — List of trusted witness public keys and names.
///
/// Usage:
/// ```ignore
/// let trust_root = TrustRoot {
///     log_public_key: Ed25519PublicKey::from_bytes(key_bytes),
///     log_origin: LogOrigin::new("auths.dev/log")?,
///     witnesses: vec![],
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRoot {
    /// The log operator's Ed25519 public key. Used only when
    /// `signature_algorithm == Ed25519`. Under the `EcdsaP256` path,
    /// this field MUST NOT be the trust anchor — see
    /// [`Self::ecdsa_log_public_key_der`] for that.
    pub log_public_key: auths_verifier::Ed25519PublicKey,
    /// The log origin string (e.g., "auths.dev/log").
    pub log_origin: LogOrigin,
    /// Trusted witness keys. Empty for Epic 1.
    pub witnesses: Vec<TrustRootWitness>,
    /// Signature algorithm for checkpoint verification. Defaults to Ed25519.
    /// Rekor production shard uses EcdsaP256.
    #[serde(default)]
    pub signature_algorithm: auths_verifier::SignatureAlgorithm,
    /// DER-encoded SubjectPublicKeyInfo for the log's ECDSA-P256
    /// public key. REQUIRED when `signature_algorithm == EcdsaP256`;
    /// the verifier compares the bundle-carried ECDSA pubkey against
    /// this pinned value byte-for-byte before using it to verify the
    /// checkpoint signature. Without this field, an attacker can
    /// submit a bundle with a self-chosen ECDSA key that verifies
    /// its own forged signature — a classic "trust the key I sent
    /// you" anti-pattern.
    #[serde(default)]
    pub ecdsa_log_public_key_der: Option<Vec<u8>>,
}

/// A trusted witness in the [`TrustRoot`].
///
/// Args:
/// * `witness_did` — The witness's device DID.
/// * `name` — Human-readable witness name.
/// * `public_key` — Witness Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let witness = TrustRootWitness {
///     witness_did: DeviceDID::parse("did:key:z6Mk...")?,
///     name: "witness-1".into(),
///     public_key: Ed25519PublicKey::from_bytes(key_bytes),
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRootWitness {
    /// The witness's device DID.
    pub witness_did: DeviceDID,
    /// Human-readable witness name.
    pub name: String,
    /// Witness Ed25519 public key.
    pub public_key: auths_verifier::Ed25519PublicKey,
}

/// Multi-log trust configuration.
///
/// Indexes trust material by log ID. Each log entry is a [`TrustRoot`].
/// The `default_log` selects which log is used when none is specified.
///
/// Usage:
/// ```ignore
/// let config = TrustConfig::default_config();
/// let root = config.get_log("sigstore-rekor").unwrap();
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustConfig {
    /// ID of the default log. Must reference a key in `logs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_log: Option<String>,
    /// Map of log ID to trust material.
    pub logs: std::collections::HashMap<String, TrustRoot>,
}

impl TrustConfig {
    /// Look up trust material for a specific log by ID.
    pub fn get_log(&self, log_id: &str) -> Option<&TrustRoot> {
        self.logs.get(log_id)
    }

    /// Get the default log's trust material.
    pub fn default_log(&self) -> Option<(&str, &TrustRoot)> {
        let id = self.default_log.as_deref()?;
        self.logs.get(id).map(|root| (id, root))
    }

    /// Validate the config at load time.
    ///
    /// Checks:
    /// - If `default_log` is set, it must reference a key in `logs`.
    /// - Every `TrustRoot` whose `signature_algorithm` is
    ///   `EcdsaP256` MUST carry a non-empty
    ///   [`TrustRoot::ecdsa_log_public_key_der`]. Without it the
    ///   verifier would trust whatever ECDSA key the bundle carried
    ///   (→ trivially forgeable checkpoint). Without this check
    ///   operators can ship configs that look healthy and silently
    ///   accept any ECDSA signature.
    pub fn validate(&self) -> std::result::Result<(), TransparencyError> {
        if let Some(ref id) = self.default_log
            && !self.logs.contains_key(id)
        {
            return Err(TransparencyError::InvalidNote(format!(
                "default_log '{}' not found in logs. Available: {:?}",
                id,
                self.logs.keys().collect::<Vec<_>>()
            )));
        }

        for (log_id, root) in &self.logs {
            if matches!(
                root.signature_algorithm,
                auths_verifier::SignatureAlgorithm::EcdsaP256
            ) {
                let has_key = root
                    .ecdsa_log_public_key_der
                    .as_ref()
                    .is_some_and(|b| !b.is_empty());
                if !has_key {
                    return Err(TransparencyError::InvalidNote(format!(
                        "log '{}' declares signature_algorithm=EcdsaP256 but \
                         ecdsa_log_public_key_der is missing or empty — refuse to \
                         trust a bundle-carried ECDSA key",
                        log_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Compiled-in default: Rekor production shard.
    ///
    /// Origin pinned from `GET https://rekor.sigstore.dev/api/v1/log`
    /// on 2026-04-09. Public key from sigstore trusted_root.json.
    pub fn default_config() -> Self {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use std::collections::HashMap;

        // Rekor production shard ECDSA P-256 public key (DER SPKI).
        // Source: https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json
        // Decoded from the base64 below at build / init time so the
        // trust root carries the actual pinned bytes, not a zero
        // placeholder.
        const REKOR_PROD_PUBKEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";
        // The decode target is a fixed compile-time base64 literal.
        // A failure here would be a source-code typo, not a runtime
        // condition — using `unwrap_or_default` keeps clippy's
        // `expect_used` gate satisfied. `TrustConfig::validate()`'s
        // "ECDSA config must carry a non-empty pinned key" check
        // is the tripwire: an accidentally-empty decode fails at
        // config load time, not silently.
        let rekor_ecdsa_pk_der = STANDARD.decode(REKOR_PROD_PUBKEY_B64).unwrap_or_default();

        // Ed25519 field kept as zero-bytes because the production
        // shard does not use Ed25519. The dispatch is on
        // `signature_algorithm`, so this placeholder is never
        // consulted.
        let rekor_root = TrustRoot {
            log_public_key: auths_verifier::Ed25519PublicKey::from_bytes([0u8; 32]),
            // Origin pinned from: GET https://rekor.sigstore.dev/api/v1/log → signedTreeHead, first line
            log_origin: LogOrigin::new_unchecked("rekor.sigstore.dev - 1193050959916656506"),
            witnesses: vec![],
            signature_algorithm: auths_verifier::SignatureAlgorithm::EcdsaP256,
            ecdsa_log_public_key_der: Some(rekor_ecdsa_pk_der),
        };

        let mut logs = HashMap::new();
        logs.insert("sigstore-rekor".to_string(), rekor_root);

        Self {
            default_log: Some("sigstore-rekor".to_string()),
            logs,
        }
    }
}
