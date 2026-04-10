use cesride::{Diger, Indexer, Matter, Siger, Verfer, indexer, matter};

use crate::error::KeriTranslationError;

/// The cryptographic key algorithm for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 public verification key (transferable).
    /// CESR code: `D` (1 char) + 43 chars base64url = 44 chars total.
    Ed25519,
    /// ECDSA P-256 (secp256r1) public verification key (transferable).
    /// CESR code: `1AAJ` (4 chars) + 44 chars base64url = 48 chars total.
    /// Raw: 33 bytes SEC1 compressed (0x02/0x03 prefix + 32-byte x-coordinate).
    P256,
}

/// The signature algorithm for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigType {
    /// Ed25519 signature (indexed, for controller signatures).
    /// CESR code: 2 chars + 86 chars base64url = 88 chars total.
    Ed25519,
    /// ECDSA P-256 signature (indexed, for controller signatures).
    /// CESR code: 2 chars + 86 chars base64url = 88 chars total.
    /// Raw: 64 bytes (r || s, each 32 bytes big-endian).
    P256,
}

/// The digest algorithm for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    /// Blake3-256 digest.
    /// CESR code: `E` (1 char) + 43 chars base64url = 44 chars.
    Blake3_256,
}

/// A decoded CESR primitive with its raw bytes and identified type.
#[derive(Debug, Clone)]
pub struct DecodedPrimitive {
    /// The raw cryptographic material (key bytes, signature bytes, or digest bytes).
    pub raw: Vec<u8>,
    /// The CESR derivation code string (e.g., "D", "E", "AA").
    pub code: String,
}

/// Encodes and decodes cryptographic primitives using CESR qualified codes.
///
/// Implementations handle the CESR code table alignment rules. The default
/// implementation ([`CesrV1Codec`]) delegates to `cesride`.
pub trait CesrCodec: Send + Sync {
    /// Encode a public key as a CESR qualified base64url string.
    ///
    /// Args:
    /// * `key_bytes`: Raw public key bytes (32 bytes for Ed25519).
    /// * `key_type`: The key algorithm.
    fn encode_pubkey(
        &self,
        key_bytes: &[u8],
        key_type: KeyType,
    ) -> Result<String, KeriTranslationError>;

    /// Encode a signature as a CESR indexed signature string.
    ///
    /// Args:
    /// * `sig_bytes`: Raw signature bytes (64 bytes for Ed25519).
    /// * `sig_type`: The signature algorithm.
    /// * `key_index`: Index into the signer's current public key list.
    fn encode_indexed_signature(
        &self,
        sig_bytes: &[u8],
        sig_type: SigType,
        key_index: u32,
    ) -> Result<String, KeriTranslationError>;

    /// Encode a digest as a CESR qualified string.
    ///
    /// Args:
    /// * `digest_bytes`: Raw digest bytes (32 bytes for Blake3-256).
    /// * `digest_type`: The digest algorithm.
    fn encode_digest(
        &self,
        digest_bytes: &[u8],
        digest_type: DigestType,
    ) -> Result<String, KeriTranslationError>;

    /// Decode a CESR qualified string back to raw bytes and code.
    ///
    /// Args:
    /// * `qualified`: The full CESR qualified string (e.g., `"Dxy2sgz..."`).
    fn decode_qualified(&self, qualified: &str) -> Result<DecodedPrimitive, KeriTranslationError>;
}

/// CESR v1 codec backed by `cesride`.
///
/// Zero-sized -- carries no state. All encoding/decoding is delegated to
/// the `cesride` primitive types which implement the full CESR code table.
#[derive(Debug, Clone, Copy)]
pub struct CesrV1Codec;

impl CesrV1Codec {
    /// Creates a new CESR v1 codec instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CesrV1Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl CesrCodec for CesrV1Codec {
    fn encode_pubkey(
        &self,
        key_bytes: &[u8],
        key_type: KeyType,
    ) -> Result<String, KeriTranslationError> {
        let code = match key_type {
            KeyType::Ed25519 => matter::Codex::Ed25519,
            // P-256 transferable key: code "1AAJ", 33 raw bytes → 48 chars
            KeyType::P256 => matter::Codex::ECDSA_256r1,
        };
        let verfer = Verfer::new(Some(code), Some(key_bytes), None, None, None).map_err(|e| {
            KeriTranslationError::EncodingFailed {
                primitive_kind: "public_key",
                detail: e.to_string(),
            }
        })?;
        verfer
            .qb64()
            .map_err(|e| KeriTranslationError::EncodingFailed {
                primitive_kind: "public_key",
                detail: e.to_string(),
            })
    }

    fn encode_indexed_signature(
        &self,
        sig_bytes: &[u8],
        sig_type: SigType,
        key_index: u32,
    ) -> Result<String, KeriTranslationError> {
        let code = match sig_type {
            SigType::Ed25519 => indexer::Codex::Ed25519,
            // P-256 indexed signature: 64 raw bytes (r||s) → 88 chars
            SigType::P256 => indexer::Codex::ECDSA_256r1,
        };
        let siger = Siger::new(
            None,
            Some(key_index),
            None,
            Some(code),
            Some(sig_bytes),
            None,
            None,
            None,
        )
        .map_err(|e| KeriTranslationError::EncodingFailed {
            primitive_kind: "indexed_signature",
            detail: e.to_string(),
        })?;
        siger
            .qb64()
            .map_err(|e| KeriTranslationError::EncodingFailed {
                primitive_kind: "indexed_signature",
                detail: e.to_string(),
            })
    }

    fn encode_digest(
        &self,
        digest_bytes: &[u8],
        digest_type: DigestType,
    ) -> Result<String, KeriTranslationError> {
        let code = match digest_type {
            DigestType::Blake3_256 => matter::Codex::Blake3_256,
        };
        let diger =
            Diger::new(None, Some(code), Some(digest_bytes), None, None, None).map_err(|e| {
                KeriTranslationError::EncodingFailed {
                    primitive_kind: "digest",
                    detail: e.to_string(),
                }
            })?;
        diger
            .qb64()
            .map_err(|e| KeriTranslationError::EncodingFailed {
                primitive_kind: "digest",
                detail: e.to_string(),
            })
    }

    fn decode_qualified(&self, qualified: &str) -> Result<DecodedPrimitive, KeriTranslationError> {
        if let Ok(verfer) = Verfer::new(None, None, None, Some(qualified), None) {
            return Ok(DecodedPrimitive {
                raw: verfer.raw(),
                code: verfer.code(),
            });
        }
        if let Ok(diger) = Diger::new(None, None, None, None, Some(qualified), None) {
            return Ok(DecodedPrimitive {
                raw: diger.raw(),
                code: diger.code(),
            });
        }
        Err(KeriTranslationError::DecodingFailed(format!(
            "unrecognized CESR primitive: {}...",
            &qualified[..qualified.len().min(8)]
        )))
    }
}
