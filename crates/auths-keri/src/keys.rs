//! KERI CESR public key parsing for Ed25519 and P-256.
//!
//! Decodes KERI-encoded public keys from their CESR-qualified string form.
//! Ed25519: 'D' prefix (transferable) / 'B' (non-transferable) + base64url(32 bytes).
//! P-256:   '1AAJ' prefix (transferable) / '1AAI' (non-transferable) + base64url(33 bytes).
//!
//! Per the CESR master code table (cesride / keripy `MatterCodex`):
//! `1AAJ` = `ECDSA_256r1` = transferable secp256r1 verification key;
//! `1AAI` = `ECDSA_256r1N` = the non-transferable variant. This mirrors the
//! Ed25519 `D`/`B` pair. Auths identities rotate, so they encode verkeys with
//! the transferable `1AAJ` code.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Errors from decoding a KERI-encoded public key.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeriDecodeError {
    /// The KERI derivation code prefix was not recognized.
    #[error("Unsupported KERI key type: prefix '{0}'")]
    UnsupportedKeyType(String),
    /// Input string was empty; no derivation code could be read.
    #[error("Missing KERI prefix: empty string")]
    EmptyInput,
    /// Base64url decoding of the key payload failed.
    #[error("Base64url decode failed: {0}")]
    DecodeError(String),
    /// Decoded bytes were not the expected length for the key type.
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
}

impl auths_crypto::AuthsErrorInfo for KeriDecodeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedKeyType(_) => "AUTHS-E1201",
            Self::EmptyInput => "AUTHS-E1202",
            Self::DecodeError(_) => "AUTHS-E1203",
            Self::InvalidLength { .. } => "AUTHS-E1204",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedKeyType(_) => Some(
                "Supported verkey prefixes: 'D'/'B' (Ed25519), '1AAJ'/'1AAI' (P-256 transferable/non-transferable).",
            ),
            Self::EmptyInput => Some("Provide a non-empty KERI-encoded key string"),
            _ => None,
        }
    }
}

/// A validated KERI public key supporting Ed25519 and P-256.
///
/// Parsed from a CESR-qualified string. The derivation code prefix
/// determines the curve, key size, and transferability.
///
/// Usage:
/// ```
/// use auths_keri::KeriPublicKey;
///
/// // Ed25519 (D prefix, 32 bytes)
/// let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
/// assert_eq!(key.as_bytes().len(), 32);
///
/// // P-256 transferable uses the "1AAJ" prefix (33 bytes compressed SEC1).
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeriPublicKey {
    /// Ed25519 public key (32 bytes).
    Ed25519([u8; 32]),
    /// P-256 compressed public key (33 bytes, SEC1: 0x02/0x03 + x-coordinate).
    ///
    /// `transferable` records which CESR code qualified it: `1AAJ` (true) is
    /// the rotating verkey code; `1AAI` (false) is the non-transferable one.
    P256 {
        /// Compressed SEC1 point (33 bytes).
        key: [u8; 33],
        /// Whether the key was qualified with the transferable code (`1AAJ`).
        transferable: bool,
    },
}

impl KeriPublicKey {
    /// Parse a CESR-qualified key string, dispatching on the derivation code prefix.
    ///
    /// - `D` prefix → Ed25519 (32 bytes)
    /// - `1AAJ` prefix → P-256 transferable (33 bytes compressed)
    /// - `1AAI` prefix → P-256 non-transferable (33 bytes compressed)
    ///
    /// Per the CESR master code table, `1AAJ`/`1AAI` are the transferable /
    /// non-transferable secp256r1 verkey codes (the P-256 analogue of Ed25519
    /// `D`/`B`). Both decode to the same 33-byte compressed point.
    ///
    /// Unknown prefixes return `Err(UnsupportedKeyType)`.
    pub fn parse(encoded: &str) -> Result<Self, KeriDecodeError> {
        if encoded.is_empty() {
            return Err(KeriDecodeError::EmptyInput);
        }

        // P-256 verkey: `1AAJ` (transferable) or `1AAI` (non-transferable).
        // Check `1AAJ` first; both share the `1AA` stem.
        for (code, transferable) in [("1AAJ", true), ("1AAI", false)] {
            if let Some(payload) = encoded.strip_prefix(code) {
                let bytes = decode_base64url(payload)?;
                if bytes.len() != 33 {
                    return Err(KeriDecodeError::InvalidLength {
                        expected: 33,
                        actual: bytes.len(),
                    });
                }
                let mut arr = [0u8; 33];
                arr.copy_from_slice(&bytes);
                return Ok(KeriPublicKey::P256 {
                    key: arr,
                    transferable,
                });
            }
        }

        // Try Ed25519 1-char prefix
        if let Some(payload) = encoded.strip_prefix('D') {
            let bytes = decode_base64url(payload)?;
            if bytes.len() != 32 {
                return Err(KeriDecodeError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(KeriPublicKey::Ed25519(arr));
        }

        // Unknown prefix
        let prefix = if encoded.len() >= 4 {
            &encoded[..4]
        } else {
            encoded
        };
        Err(KeriDecodeError::UnsupportedKeyType(prefix.to_string()))
    }

    /// Returns the raw public key bytes (32 for Ed25519, 33 for P-256).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeriPublicKey::Ed25519(b) => b,
            KeriPublicKey::P256 { key, .. } => key,
        }
    }

    /// Consume self and return the raw bytes as a Vec.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            KeriPublicKey::Ed25519(b) => b.to_vec(),
            KeriPublicKey::P256 { key, .. } => key.to_vec(),
        }
    }

    /// Returns the curve type.
    pub fn curve(&self) -> auths_crypto::CurveType {
        match self {
            KeriPublicKey::Ed25519(_) => auths_crypto::CurveType::Ed25519,
            KeriPublicKey::P256 { .. } => auths_crypto::CurveType::P256,
        }
    }

    /// Whether this key is transferable (rotating).
    ///
    /// Ed25519 keys parsed via the `D` code are transferable. P-256 keys carry
    /// the transferability recorded from their `1AAJ`/`1AAI` code.
    pub fn is_transferable(&self) -> bool {
        match self {
            KeriPublicKey::Ed25519(_) => true,
            KeriPublicKey::P256 { transferable, .. } => *transferable,
        }
    }

    /// Returns the CESR derivation code prefix for this key type.
    ///
    /// `D` for Ed25519; `1AAJ` for a transferable P-256 verkey and `1AAI` for a
    /// non-transferable one (per the CESR master code table).
    pub fn cesr_prefix(&self) -> &'static str {
        match self {
            KeriPublicKey::Ed25519(_) => "D",
            KeriPublicKey::P256 {
                transferable: true, ..
            } => "1AAJ",
            KeriPublicKey::P256 {
                transferable: false,
                ..
            } => "1AAI",
        }
    }

    /// Encode this key as a CESR-qualified qb64 string, byte-identical to keripy.
    ///
    /// Ed25519 → `D…`; transferable P-256 → `1AAJ…`; non-transferable P-256 → `1AAI…`.
    /// This is the CESR-correct encoding (proper lead-byte alignment), not the legacy
    /// naive `D` + base64url(raw) form.
    ///
    /// Usage:
    /// ```ignore
    /// let qb64 = key.to_qb64()?;
    /// ```
    pub fn to_qb64(&self) -> Result<String, KeriDecodeError> {
        let code = crate::cesr_encode::verkey_code(self.curve(), self.is_transferable());
        crate::cesr_encode::encode_verkey(self.as_bytes(), code)
    }

    /// Construct a transferable Ed25519 verkey from a 32-byte slice.
    ///
    /// Ergonomic bridge for raw-byte sources (e.g. a `ring` public key) into the
    /// typed key. Returns `Err(InvalidLength)` if the slice is not 32 bytes.
    ///
    /// Usage:
    /// ```
    /// use auths_keri::KeriPublicKey;
    /// let key = KeriPublicKey::ed25519(&[0u8; 32]).unwrap();
    /// assert!(matches!(key, KeriPublicKey::Ed25519(_)));
    /// ```
    pub fn ed25519(bytes: &[u8]) -> Result<Self, KeriDecodeError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeriDecodeError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            })?;
        Ok(KeriPublicKey::Ed25519(arr))
    }

    /// Construct a transferable verkey from raw bytes plus an explicit curve.
    ///
    /// The complement of [`Self::as_bytes`] + [`Self::curve`]: rebuilds the typed key
    /// when you hold curve-tagged bytes (a `CurveType` carried alongside a `Vec<u8>`),
    /// instead of re-guessing the curve from byte length. Encodes as transferable
    /// (`D` / `1AAJ`). Returns `Err(InvalidLength)` if the length doesn't match the curve.
    ///
    /// Usage:
    /// ```
    /// use auths_keri::KeriPublicKey;
    /// use auths_crypto::CurveType;
    /// let key = KeriPublicKey::from_verkey_bytes(&[0u8; 32], CurveType::Ed25519).unwrap();
    /// assert_eq!(key.curve(), CurveType::Ed25519);
    /// ```
    pub fn from_verkey_bytes(
        bytes: &[u8],
        curve: auths_crypto::CurveType,
    ) -> Result<Self, KeriDecodeError> {
        match curve {
            auths_crypto::CurveType::Ed25519 => Self::ed25519(bytes),
            auths_crypto::CurveType::P256 => {
                let arr: [u8; 33] =
                    bytes
                        .try_into()
                        .map_err(|_| KeriDecodeError::InvalidLength {
                            expected: 33,
                            actual: bytes.len(),
                        })?;
                Ok(KeriPublicKey::P256 {
                    key: arr,
                    transferable: true,
                })
            }
        }
    }

    /// Verify a signature against this public key.
    ///
    /// Dispatches to the correct algorithm based on the key's curve:
    /// - Ed25519 → `ring::signature::ED25519`
    /// - P-256 → `p256::ecdsa` (handles compressed SEC1 keys natively)
    ///
    /// This method keeps the curve dispatch in one place so validation code
    /// doesn't need to know about specific algorithms.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        match self {
            KeriPublicKey::Ed25519(pk) => {
                use ring::signature::UnparsedPublicKey;
                let verifier = UnparsedPublicKey::new(&ring::signature::ED25519, pk);
                verifier
                    .verify(message, signature)
                    .map_err(|_| "Ed25519 signature verification failed".to_string())
            }
            KeriPublicKey::P256 { key: pk, .. } => {
                use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                // p256 crate handles compressed SEC1 (33 bytes) natively
                let vk = VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|e| format!("P-256 key parse failed: {e}"))?;
                let sig = Signature::from_slice(signature)
                    .map_err(|e| format!("P-256 signature parse failed: {e}"))?;
                vk.verify(message, &sig)
                    .map_err(|e| format!("P-256 signature verification failed: {e}"))
            }
        }
    }
}

fn decode_base64url(payload: &str) -> Result<Vec<u8>, KeriDecodeError> {
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ed25519_all_zeros() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.as_bytes(), &[0u8; 32]);
        assert!(matches!(key, KeriPublicKey::Ed25519(_)));
        assert_eq!(key.curve(), auths_crypto::CurveType::Ed25519);
        assert_eq!(key.cesr_prefix(), "D");
    }

    #[test]
    fn parse_p256_key() {
        // `1AAJ` is the transferable P-256 verkey code (the rotating default).
        let zeros_33 = [0u8; 33];
        let encoded = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(zeros_33));
        let key = KeriPublicKey::parse(&encoded).unwrap();
        assert_eq!(key.as_bytes().len(), 33);
        assert!(matches!(key, KeriPublicKey::P256 { .. }));
        assert_eq!(key.curve(), auths_crypto::CurveType::P256);
        assert!(key.is_transferable());
        assert_eq!(key.cesr_prefix(), "1AAJ");
    }

    #[test]
    fn parses_both_1aai_and_1aaj() {
        // Both P-256 codes decode to the same 33-byte point; transferability
        // and the round-tripped prefix differ.
        let zeros_33 = [0u8; 33];
        let transferable =
            KeriPublicKey::parse(&format!("1AAJ{}", URL_SAFE_NO_PAD.encode(zeros_33))).unwrap();
        let non_transferable =
            KeriPublicKey::parse(&format!("1AAI{}", URL_SAFE_NO_PAD.encode(zeros_33))).unwrap();
        assert_eq!(transferable.as_bytes(), non_transferable.as_bytes());
        assert!(transferable.is_transferable());
        assert!(!non_transferable.is_transferable());
        assert_eq!(transferable.cesr_prefix(), "1AAJ");
        assert_eq!(non_transferable.cesr_prefix(), "1AAI");
    }

    #[test]
    fn parse_p256_non_transferable() {
        let zeros_33 = [0u8; 33];
        let encoded = format!("1AAI{}", URL_SAFE_NO_PAD.encode(zeros_33));
        let key = KeriPublicKey::parse(&encoded).unwrap();
        assert!(matches!(
            key,
            KeriPublicKey::P256 {
                transferable: false,
                ..
            }
        ));
    }

    #[test]
    fn rejects_empty_input() {
        let err = KeriPublicKey::parse("").unwrap_err();
        assert_eq!(err, KeriDecodeError::EmptyInput);
    }

    #[test]
    fn rejects_unknown_prefix() {
        let err = KeriPublicKey::parse("Xsomething").unwrap_err();
        assert!(matches!(err, KeriDecodeError::UnsupportedKeyType(_)));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = KeriPublicKey::parse("D!!!invalid!!!").unwrap_err();
        assert!(matches!(err, KeriDecodeError::DecodeError(_)));
    }

    #[test]
    fn rejects_wrong_length_ed25519() {
        // 31 bytes instead of 32
        let short = [0u8; 31];
        let encoded = format!("D{}", URL_SAFE_NO_PAD.encode(short));
        let err = KeriPublicKey::parse(&encoded).unwrap_err();
        assert!(matches!(
            err,
            KeriDecodeError::InvalidLength {
                expected: 32,
                actual: 31
            }
        ));
    }

    #[test]
    fn rejects_wrong_length_p256() {
        // 32 bytes instead of 33
        let short = [0u8; 32];
        let encoded = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(short));
        let err = KeriPublicKey::parse(&encoded).unwrap_err();
        assert!(matches!(
            err,
            KeriDecodeError::InvalidLength {
                expected: 33,
                actual: 32
            }
        ));
    }

    // Backward compatibility: the old API had `as_bytes()` returning `&[u8; 32]`.
    // The new API returns `&[u8]`. Test that Ed25519 keys still work with the
    // 32-byte slice pattern.
    #[test]
    fn ed25519_as_bytes_is_32() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let bytes = key.as_bytes();
        assert_eq!(bytes.len(), 32);
        // Can still convert to [u8; 32] for backward compat
        let arr: [u8; 32] = bytes.try_into().unwrap();
        assert_eq!(arr, [0u8; 32]);
    }
}
