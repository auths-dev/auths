use crate::error::KeriTranslationError;

/// The cryptographic key algorithm for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 public verification key (transferable).
    /// CESR code: `D` (1 char) + 43 chars base64url = 44 chars.
    Ed25519,
}

/// The signature algorithm for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigType {
    /// Ed25519 signature (indexed, for controller signatures).
    /// CESR code: 2 chars + 86 chars base64url = 88 chars.
    Ed25519,
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

// CesrCodec implementation for CesrV1Codec is in fn-14.2.
// Stub impl to allow compilation:
impl CesrCodec for CesrV1Codec {
    fn encode_pubkey(
        &self,
        _key_bytes: &[u8],
        _key_type: KeyType,
    ) -> Result<String, KeriTranslationError> {
        todo!("implemented in fn-14.2")
    }

    fn encode_indexed_signature(
        &self,
        _sig_bytes: &[u8],
        _sig_type: SigType,
        _key_index: u32,
    ) -> Result<String, KeriTranslationError> {
        todo!("implemented in fn-14.2")
    }

    fn encode_digest(
        &self,
        _digest_bytes: &[u8],
        _digest_type: DigestType,
    ) -> Result<String, KeriTranslationError> {
        todo!("implemented in fn-14.2")
    }

    fn decode_qualified(&self, _qualified: &str) -> Result<DecodedPrimitive, KeriTranslationError> {
        todo!("implemented in fn-14.2")
    }
}
