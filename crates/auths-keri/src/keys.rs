//! KERI CESR public key parsing for Ed25519 and P-256.
//!
//! Decodes KERI-encoded public keys from their CESR-qualified string form.
//! Ed25519: 'D' prefix + base64url(32 bytes) = 44 chars.
//! P-256:   '1AAI' prefix + base64url(33 bytes) = 48 chars. (`1AAJ` is the
//! CESR spec's P-256 *signature* code, NOT a verkey code; parser rejects it.)

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
                "Supported key prefixes: 'D' (Ed25519), '1AAI' (P-256). '1AAJ' is the P-256 SIGNATURE code per CESR spec; do not use as a verkey prefix.",
            ),
            Self::EmptyInput => Some("Provide a non-empty KERI-encoded key string"),
            _ => None,
        }
    }
}

/// A validated KERI public key supporting Ed25519 and P-256.
///
/// Parsed from a CESR-qualified string. The derivation code prefix
/// determines the curve and key size.
///
/// Usage:
/// ```
/// use auths_keri::KeriPublicKey;
///
/// // Ed25519 (D prefix, 32 bytes)
/// let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
/// assert_eq!(key.as_bytes().len(), 32);
///
/// // P-256 uses "1AAI" prefix (33 bytes compressed SEC1) per CESR spec
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeriPublicKey {
    /// Ed25519 public key (32 bytes).
    Ed25519([u8; 32]),
    /// P-256 compressed public key (33 bytes, SEC1: 0x02/0x03 + x-coordinate).
    P256([u8; 33]),
}

impl KeriPublicKey {
    /// Parse a CESR-qualified key string, dispatching on the derivation code prefix.
    ///
    /// - `D` prefix → Ed25519 (32 bytes)
    /// - `1AAI` prefix → P-256 (33 bytes compressed)
    ///
    /// fn-116.5: strict per CESR spec. `1AAJ` (which is the spec's P-256 SIGNATURE
    /// code, not a verkey code) is rejected with `UnsupportedKeyType`. Prior to
    /// fn-114.37 some repo sites emitted `1AAJ` for verkeys; those are spec-invalid
    /// and must be regenerated.
    ///
    /// Unknown prefixes return `Err(UnsupportedKeyType)`.
    pub fn parse(encoded: &str) -> Result<Self, KeriDecodeError> {
        if encoded.is_empty() {
            return Err(KeriDecodeError::EmptyInput);
        }

        // P-256 verkey: `1AAI` only per CESR spec. `1AAJ` is the spec's P-256
        // *signature* code — reject loudly if someone supplies it as a verkey.
        if let Some(payload) = encoded.strip_prefix("1AAI") {
            let bytes = decode_base64url(payload)?;
            if bytes.len() != 33 {
                return Err(KeriDecodeError::InvalidLength {
                    expected: 33,
                    actual: bytes.len(),
                });
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            return Ok(KeriPublicKey::P256(arr));
        }
        if encoded.starts_with("1AAJ") {
            return Err(KeriDecodeError::UnsupportedKeyType(
                "1AAJ is the P-256 signature code; use 1AAI for P-256 verkeys (CESR spec).".into(),
            ));
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
            KeriPublicKey::P256(b) => b,
        }
    }

    /// Consume self and return the raw bytes as a Vec.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            KeriPublicKey::Ed25519(b) => b.to_vec(),
            KeriPublicKey::P256(b) => b.to_vec(),
        }
    }

    /// Returns the curve type.
    pub fn curve(&self) -> auths_crypto::CurveType {
        match self {
            KeriPublicKey::Ed25519(_) => auths_crypto::CurveType::Ed25519,
            KeriPublicKey::P256(_) => auths_crypto::CurveType::P256,
        }
    }

    /// Returns the CESR derivation code prefix for this key type.
    ///
    /// Per CESR spec: `D` for Ed25519, `1AAI` for P-256 verkeys. The parser is
    /// strict about this post-fn-116.5 — legacy `1AAJ` emissions are rejected.
    pub fn cesr_prefix(&self) -> &'static str {
        match self {
            KeriPublicKey::Ed25519(_) => "D",
            KeriPublicKey::P256(_) => "1AAI",
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
            KeriPublicKey::P256(pk) => {
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
        // fn-116.5: strict — `1AAI` is the spec-correct P-256 verkey prefix.
        let zeros_33 = [0u8; 33];
        let encoded = format!("1AAI{}", URL_SAFE_NO_PAD.encode(zeros_33));
        let key = KeriPublicKey::parse(&encoded).unwrap();
        assert_eq!(key.as_bytes().len(), 33);
        assert!(matches!(key, KeriPublicKey::P256(_)));
        assert_eq!(key.curve(), auths_crypto::CurveType::P256);
        assert_eq!(key.cesr_prefix(), "1AAI");
    }

    #[test]
    fn rejects_legacy_1aaj_verkey() {
        // fn-116.5: `1AAJ` is the CESR spec's P-256 *signature* code. Reject loudly
        // when supplied as a verkey — the parser previously tolerated this for
        // pre-fn-114.37 on-disk identities. Pre-launch posture removes the grace.
        let zeros_33 = [0u8; 33];
        let encoded = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(zeros_33));
        let err = KeriPublicKey::parse(&encoded).unwrap_err();
        assert!(matches!(err, KeriDecodeError::UnsupportedKeyType(_)));
    }

    #[test]
    fn parse_p256_non_transferable() {
        let zeros_33 = [0u8; 33];
        let encoded = format!("1AAI{}", URL_SAFE_NO_PAD.encode(zeros_33));
        let key = KeriPublicKey::parse(&encoded).unwrap();
        assert!(matches!(key, KeriPublicKey::P256(_)));
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
