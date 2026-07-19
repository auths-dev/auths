//! The write half of the transparency log: append leaves, sign checkpoints,
//! and mint inclusion proofs a verifier can replay offline.
//!
//! [`LogWriter`] is storage-agnostic: it speaks the same [`TileStore`] port
//! the read path uses (filesystem via [`crate::FsTileStore`], S3 behind the
//! `s3` feature), persisting leaf hashes as C2SP level-0 tiles and the
//! current [`SignedCheckpoint`] (JSON) in the store's checkpoint slot. The
//! Merkle math is the shared RFC 6962 implementation in
//! `auths_verifier::tlog`, so every proof minted here is checked by the
//! exact code all verifier surfaces (native, FFI, browser WASM) run.
//!
//! Scale posture: the writer re-derives the full leaf list from tiles on
//! every call and re-verifies the stored root against it — fail-closed on a
//! corrupted store. That is O(n) per operation by design: this is the
//! local-first/operator log (release histories, org evidence), not the
//! hosted sequencer, which keeps the tree in memory.

use auths_crypto::{CurveType, TypedSeed, TypedSignerKey};
use auths_verifier::evidence_pack::TransparencyInclusion;
use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
use chrono::{DateTime, Utc};

use crate::checkpoint::{Checkpoint, SignedCheckpoint};
use crate::error::TransparencyError;
use crate::merkle::{compute_root, prove_inclusion};
use crate::proof::InclusionProof;
use crate::store::TileStore;
use crate::tile::{TILE_WIDTH, leaf_tile, tile_count, tile_path};
use crate::types::{LogOrigin, MerkleHash};

/// The log operator's Ed25519 checkpoint-signing key, parsed and
/// curve-checked at construction so signing can never fail on curve drift.
/// The C2SP signed-note `log_signature` field is Ed25519-pinned by spec;
/// non-Ed25519 keys are rejected here, once, at the boundary.
pub struct LogSigningKey {
    signer: TypedSignerKey,
    public_key: Ed25519PublicKey,
}

impl LogSigningKey {
    /// Generate a fresh Ed25519 signing key from OS randomness.
    ///
    /// Usage:
    /// ```ignore
    /// let key = LogSigningKey::generate()?;
    /// std::fs::write(key_path, key.to_pkcs8_der()?)?;
    /// ```
    pub fn generate() -> Result<Self, TransparencyError> {
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| TransparencyError::SigningKey("OS randomness unavailable".into()))?;
        let signer = TypedSignerKey::from_seed(TypedSeed::Ed25519(seed))
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        Self::from_signer(signer)
    }

    /// Parse a signing key from PKCS#8 DER bytes.
    ///
    /// Args:
    /// * `der` — PKCS#8 DER as previously produced by [`Self::to_pkcs8_der`].
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, TransparencyError> {
        let signer = TypedSignerKey::from_pkcs8(der)
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        Self::from_signer(signer)
    }

    /// Build a signing key from a raw 32-byte Ed25519 seed.
    ///
    /// A witness node uses ONE Ed25519 identity for both its cosignatures and
    /// its log checkpoints — verifiers pin a single member key — so the node
    /// derives both signers from the same stable seed.
    ///
    /// Args:
    /// * `seed` — The 32-byte Ed25519 seed.
    ///
    /// Usage:
    /// ```ignore
    /// let key = LogSigningKey::from_seed(node_seed)?;
    /// ```
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, TransparencyError> {
        let signer = TypedSignerKey::from_seed(TypedSeed::Ed25519(seed))
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        Self::from_signer(signer)
    }

    fn from_signer(signer: TypedSignerKey) -> Result<Self, TransparencyError> {
        if signer.curve() != CurveType::Ed25519 {
            return Err(TransparencyError::SigningKey(
                "checkpoint signing key must be Ed25519 (C2SP signed-note pins the curve)".into(),
            ));
        }
        let public_key = Ed25519PublicKey::try_from_slice(signer.public_key())
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        Ok(Self { signer, public_key })
    }

    /// PKCS#8 DER bytes for persisting the key alongside the log.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, TransparencyError> {
        Ok(self
            .signer
            .to_pkcs8()
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?
            .as_ref()
            .to_vec())
    }

    /// The log's public key — what verifiers pin as the log identity.
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }
}

/// The outcome of appending one leaf: its assigned index and the new signed
/// checkpoint covering it.
#[derive(Debug, Clone)]
pub struct AppendedLeaf {
    /// Zero-based index the leaf was sequenced at.
    pub index: u64,
    /// The checkpoint signed over the tree that now includes the leaf.
    pub signed_checkpoint: SignedCheckpoint,
}

/// Appends leaves to a tile-backed transparency log and mints offline
/// inclusion proofs against its signed checkpoint.
///
/// Args:
/// * `store` — Any [`TileStore`] (e.g. [`crate::FsTileStore`]).
/// * `key` — The log operator's [`LogSigningKey`].
/// * `origin` — The log's origin line; a store whose checkpoint carries a
///   different origin is rejected on every operation.
///
/// Usage:
/// ```ignore
/// let writer = LogWriter::new(FsTileStore::new(dir), key, origin);
/// let leaf = hash_leaf(b"sha256:...");
/// let appended = writer.append(leaf, now).await?;
/// let inclusion = writer.prove(&leaf).await?;
/// ```
pub struct LogWriter<S: TileStore> {
    store: S,
    key: LogSigningKey,
    origin: LogOrigin,
}

impl<S: TileStore> LogWriter<S> {
    /// Create a writer over a tile store with the given signing key + origin.
    pub fn new(store: S, key: LogSigningKey, origin: LogOrigin) -> Self {
        Self { store, key, origin }
    }

    /// Append one leaf hash: persist it to the level-0 tiles, recompute the
    /// root, and sign a fresh checkpoint over the grown tree.
    ///
    /// Args:
    /// * `leaf_hash` — The RFC 6962 leaf hash (see `hash_leaf`).
    /// * `now` — Injected checkpoint timestamp (never read from a wall clock
    ///   here).
    pub async fn append(
        &self,
        leaf_hash: MerkleHash,
        now: DateTime<Utc>,
    ) -> Result<AppendedLeaf, TransparencyError> {
        let mut leaves = match self.read_state().await? {
            Some((_, leaves)) => leaves,
            None => Vec::new(),
        };
        let index = leaves.len() as u64;
        leaves.push(leaf_hash);

        // Persist exactly the tile the new leaf lands in. A tile reaching
        // TILE_WIDTH is written at its full path (write-once); a growing
        // tile at its partial path (overwritable).
        let (tile_index, offset) = leaf_tile(index);
        let width = offset + 1;
        let start = usize::try_from(tile_index * TILE_WIDTH)
            .map_err(|_| TransparencyError::StoreError("tile index out of range".into()))?;
        let mut data = Vec::with_capacity((width as usize) * 32);
        for leaf in &leaves[start..start + width as usize] {
            data.extend_from_slice(leaf.as_bytes());
        }
        let path = tile_path(0, tile_index, width % TILE_WIDTH)?;
        self.store.write_tile(&path, &data).await?;

        let checkpoint = Checkpoint {
            origin: self.origin.clone(),
            size: leaves.len() as u64,
            root: compute_root(&leaves),
            timestamp: now,
        };
        let signed_checkpoint = self.sign(checkpoint)?;
        let bytes = serde_json::to_vec(&signed_checkpoint)
            .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
        self.store.write_checkpoint(&bytes).await?;

        Ok(AppendedLeaf {
            index,
            signed_checkpoint,
        })
    }

    /// Mint the offline inclusion evidence for a leaf already in the log:
    /// an inclusion proof directly against the current signed checkpoint.
    pub async fn prove(
        &self,
        leaf_hash: &MerkleHash,
    ) -> Result<TransparencyInclusion, TransparencyError> {
        let Some((signed_checkpoint, leaves)) = self.read_state().await? else {
            return Err(TransparencyError::InvalidProof(
                "the log is empty — nothing has been appended".into(),
            ));
        };
        let index = leaves
            .iter()
            .position(|leaf| leaf == leaf_hash)
            .ok_or_else(|| {
                TransparencyError::InvalidProof("leaf is not in the log — append it first".into())
            })? as u64;

        let inclusion_proof = InclusionProof {
            index,
            size: signed_checkpoint.checkpoint.size,
            root: signed_checkpoint.checkpoint.root,
            hashes: prove_inclusion(&leaves, index)?,
        };
        // Never emit evidence we have not replayed through the verifier path.
        inclusion_proof.verify(leaf_hash)?;

        Ok(TransparencyInclusion {
            leaf_hash: *leaf_hash,
            inclusion_proof,
            signed_checkpoint,
            consistency_proof: None,
        })
    }

    /// Load and re-verify the persisted log state: `None` when no checkpoint
    /// exists yet, otherwise the checkpoint plus every leaf, with the stored
    /// root recomputed from the leaves — a store that disagrees with its own
    /// checkpoint fails closed.
    async fn read_state(
        &self,
    ) -> Result<Option<(SignedCheckpoint, Vec<MerkleHash>)>, TransparencyError> {
        let Some(bytes) = self.store.read_checkpoint().await? else {
            return Ok(None);
        };
        let signed: SignedCheckpoint = serde_json::from_slice(&bytes)
            .map_err(|e| TransparencyError::StoreError(format!("checkpoint parse: {e}")))?;
        if signed.checkpoint.origin != self.origin {
            return Err(TransparencyError::InvalidOrigin(format!(
                "log belongs to origin '{}', not '{}'",
                signed.checkpoint.origin, self.origin
            )));
        }
        let leaves = self.read_leaves(signed.checkpoint.size).await?;
        let recomputed = compute_root(&leaves);
        if recomputed != signed.checkpoint.root {
            return Err(TransparencyError::RootMismatch {
                expected: signed.checkpoint.root.to_string(),
                actual: recomputed.to_string(),
            });
        }
        Ok(Some((signed, leaves)))
    }

    /// Read every leaf hash for a tree of `size` from the level-0 tiles.
    async fn read_leaves(&self, size: u64) -> Result<Vec<MerkleHash>, TransparencyError> {
        let (full_tiles, partial_width) = tile_count(size);
        let mut leaves = Vec::with_capacity(size as usize);
        for tile_index in 0..full_tiles {
            let path = tile_path(0, tile_index, 0)?;
            let data = self.store.read_tile(&path).await?;
            parse_leaf_tile(&data, TILE_WIDTH, &path, &mut leaves)?;
        }
        if partial_width > 0 {
            let path = tile_path(0, full_tiles, partial_width)?;
            let data = self.store.read_tile(&path).await?;
            parse_leaf_tile(&data, partial_width, &path, &mut leaves)?;
        }
        Ok(leaves)
    }

    fn sign(&self, checkpoint: Checkpoint) -> Result<SignedCheckpoint, TransparencyError> {
        let body = checkpoint.to_note_body();
        let signature = self
            .key
            .signer
            .sign(body.as_bytes())
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        let log_signature = Ed25519Signature::try_from_slice(&signature)
            .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
        Ok(SignedCheckpoint {
            checkpoint,
            log_signature,
            log_public_key: self.key.public_key,
            witnesses: Vec::new(),
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        })
    }
}

/// Parse one level-0 tile's bytes into leaf hashes, enforcing the exact
/// expected width so a truncated or padded tile is rejected at the boundary.
fn parse_leaf_tile(
    data: &[u8],
    width: u64,
    path: &str,
    out: &mut Vec<MerkleHash>,
) -> Result<(), TransparencyError> {
    let expected = (width as usize) * 32;
    if data.len() != expected {
        return Err(TransparencyError::StoreError(format!(
            "tile {path}: expected {expected} bytes ({width} hashes), got {}",
            data.len()
        )));
    }
    for chunk in data.chunks_exact(32) {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(chunk);
        out.push(MerkleHash::from_bytes(bytes));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fs_store::FsTileStore;
    use crate::merkle::hash_leaf;
    use auths_verifier::evidence_pack::verify_transparency_inclusion;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn writer_in(dir: &std::path::Path) -> LogWriter<FsTileStore> {
        LogWriter::new(
            FsTileStore::new(dir.to_path_buf()),
            LogSigningKey::generate().unwrap(),
            LogOrigin::new("test.example/log").unwrap(),
        )
    }

    #[tokio::test]
    async fn append_then_prove_roundtrips_through_the_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());

        let digests = ["sha256:aa", "sha256:bb", "sha256:cc"];
        for (i, d) in digests.iter().enumerate() {
            let appended = writer
                .append(hash_leaf(d.as_bytes()), fixed_now())
                .await
                .unwrap();
            assert_eq!(appended.index, i as u64);
            assert_eq!(appended.signed_checkpoint.checkpoint.size, i as u64 + 1);
        }

        for d in digests {
            let leaf = hash_leaf(d.as_bytes());
            let inclusion = writer.prove(&leaf).await.unwrap();
            assert_eq!(inclusion.signed_checkpoint.checkpoint.size, 3);
            verify_transparency_inclusion(&inclusion)
                .expect("the verifier the browser/CLI runs must accept the writer's evidence");
        }
    }

    #[tokio::test]
    async fn checkpoint_signature_verifies_against_the_log_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());

        let appended = writer
            .append(hash_leaf(b"sha256:aa"), fixed_now())
            .await
            .unwrap();
        let signed = &appended.signed_checkpoint;

        let body = signed.checkpoint.to_note_body();
        let key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            signed.log_public_key.as_bytes(),
        );
        key.verify(body.as_bytes(), signed.log_signature.as_bytes())
            .expect("checkpoint must be signed over the C2SP note body");
    }

    #[tokio::test]
    async fn prove_unknown_leaf_fails() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());
        writer
            .append(hash_leaf(b"sha256:aa"), fixed_now())
            .await
            .unwrap();

        let stranger = hash_leaf(b"sha256:never-appended");
        assert!(writer.prove(&stranger).await.is_err());
    }

    #[tokio::test]
    async fn origin_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());
        writer
            .append(hash_leaf(b"sha256:aa"), fixed_now())
            .await
            .unwrap();

        let imposter = LogWriter::new(
            FsTileStore::new(dir.path().to_path_buf()),
            LogSigningKey::generate().unwrap(),
            LogOrigin::new("other.example/log").unwrap(),
        );
        assert!(matches!(
            imposter.append(hash_leaf(b"sha256:bb"), fixed_now()).await,
            Err(TransparencyError::InvalidOrigin(_))
        ));
    }

    #[tokio::test]
    async fn tampered_tile_fails_closed_on_next_operation() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());
        let leaf = hash_leaf(b"sha256:aa");
        writer.append(leaf, fixed_now()).await.unwrap();
        writer
            .append(hash_leaf(b"sha256:bb"), fixed_now())
            .await
            .unwrap();

        // Flip a byte in the partial level-0 tile behind the writer's back.
        let tile = dir.path().join("tile/0/000.p/2");
        let mut bytes = std::fs::read(&tile).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&tile, bytes).unwrap();

        assert!(matches!(
            writer.prove(&leaf).await,
            Err(TransparencyError::RootMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn key_roundtrips_through_pkcs8() {
        let key = LogSigningKey::generate().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let reloaded = LogSigningKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(key.public_key(), reloaded.public_key());
    }

    #[tokio::test]
    async fn appends_roll_over_a_full_tile() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer_in(dir.path());

        let count = TILE_WIDTH + 3;
        for i in 0..count {
            writer
                .append(
                    hash_leaf(format!("sha256:{i:064x}").as_bytes()),
                    fixed_now(),
                )
                .await
                .unwrap();
        }

        // Tile 0 is now a full, write-once tile; tile 1 a 3-wide partial.
        assert!(dir.path().join("tile/0/000").exists());
        assert!(dir.path().join("tile/0/001.p/3").exists());

        let first = hash_leaf(format!("sha256:{:064x}", 0).as_bytes());
        let inclusion = writer.prove(&first).await.unwrap();
        assert_eq!(inclusion.signed_checkpoint.checkpoint.size, count);
        verify_transparency_inclusion(&inclusion).expect("proof across tiles verifies");
    }
}
