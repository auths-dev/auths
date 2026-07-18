//! KERI CESR public key parsing for Ed25519 and P-256.
//!
//! Decodes KERI-encoded public keys from their CESR-qualified string form.
//! Ed25519: 'D' prefix (transferable) / 'B' (non-transferable) + base64url(32 bytes).
//! P-256:   '1AAJ' prefix (transferable) / '1AAI' (non-transferable) + base64url(33 bytes).
//!
//! Both curves carry the transferability recorded from their CESR code: rotating
//! identity keys are transferable (`D` / `1AAJ`), while keys pinned to one
//! incepting event — most notably KERI witnesses — are non-transferable
//! (`B` / `1AAI`). The raw bytes and signature algorithm are identical across the
//! pair; only the code (and thus the rotation semantics) differ.
//!
//! Per the CESR master code table (cesride / keripy `MatterCodex`):
//! `1AAJ` = `ECDSA_256r1` = transferable secp256r1 verification key;
//! `1AAI` = `ECDSA_256r1N` = the non-transferable variant. This mirrors the
//! Ed25519 `D`/`B` pair. Auths identities rotate, so they encode verkeys with
//! the transferable `1AAJ` code.

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
                "Supported verkey prefixes: 'D'/'B' (Ed25519 transferable/non-transferable), '1AAJ'/'1AAI' (P-256 transferable/non-transferable).",
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
    ///
    /// `transferable` records which CESR code qualified it: `D` (true) is the
    /// rotating verkey code; `B` (false) is the non-transferable one used by
    /// KERI witnesses. Both decode to the same 32-byte key and verify with the
    /// same Ed25519 algorithm.
    Ed25519 {
        /// Raw Ed25519 public key (32 bytes).
        key: [u8; 32],
        /// Whether the key was qualified with the transferable code (`D`).
        transferable: bool,
    },
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
    /// - `D` prefix → Ed25519 transferable (32 bytes)
    /// - `B` prefix → Ed25519 non-transferable (32 bytes) — the KERI witness code
    /// - `1AAJ` prefix → P-256 transferable (33 bytes compressed)
    /// - `1AAI` prefix → P-256 non-transferable (33 bytes compressed)
    ///
    /// Per the CESR master code table, `D`/`B` and `1AAJ`/`1AAI` are the
    /// transferable / non-transferable verkey codes for each curve. Both members
    /// of a pair decode to the same raw key; only the recorded transferability
    /// (and thus the rotation semantics) differ. Any other matter code returns
    /// `Err(UnsupportedKeyType)`; malformed CESR returns `Err(DecodeError)`.
    pub fn parse(encoded: &str) -> Result<Self, KeriDecodeError> {
        if encoded.is_empty() {
            return Err(KeriDecodeError::EmptyInput);
        }

        // cesride's qb64 decoder derives a primitive's length from its derivation
        // code and slices the input by that length, so a non-ASCII, truncated, or
        // unknown code makes it slice off a char boundary or past the end and panic.
        // Validate the input is exactly one well-formed CESR primitive (with no
        // trailing bytes) before the decoder runs; the curve is then selected by the
        // in-band code below, never by raw byte length.
        let primitive = crate::cesr_encode::take_matter_qb64(encoded)?;
        if primitive.len() != encoded.len() {
            return Err(KeriDecodeError::DecodeError(
                "trailing bytes after verkey primitive".into(),
            ));
        }

        let (bytes, code) = crate::cesr_encode::decode_verkey(encoded)?;

        use cesride::matter::Codex;
        if code.as_str() == Codex::Ed25519 || code.as_str() == Codex::Ed25519N {
            let arr: [u8; 32] =
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeriDecodeError::InvalidLength {
                        expected: 32,
                        actual: bytes.len(),
                    })?;
            Ok(KeriPublicKey::Ed25519 {
                key: arr,
                transferable: code.as_str() == Codex::Ed25519,
            })
        } else if code.as_str() == Codex::ECDSA_256r1 || code.as_str() == Codex::ECDSA_256r1N {
            let arr: [u8; 33] =
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeriDecodeError::InvalidLength {
                        expected: 33,
                        actual: bytes.len(),
                    })?;
            Ok(KeriPublicKey::P256 {
                key: arr,
                transferable: code.as_str() == Codex::ECDSA_256r1,
            })
        } else {
            Err(KeriDecodeError::UnsupportedKeyType(code))
        }
    }

    /// Returns the raw public key bytes (32 for Ed25519, 33 for P-256).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeriPublicKey::Ed25519 { key, .. } => key,
            KeriPublicKey::P256 { key, .. } => key,
        }
    }

    /// Consume self and return the raw bytes as a Vec.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            KeriPublicKey::Ed25519 { key, .. } => key.to_vec(),
            KeriPublicKey::P256 { key, .. } => key.to_vec(),
        }
    }

    /// Returns the curve type.
    pub fn curve(&self) -> auths_crypto::CurveType {
        match self {
            KeriPublicKey::Ed25519 { .. } => auths_crypto::CurveType::Ed25519,
            KeriPublicKey::P256 { .. } => auths_crypto::CurveType::P256,
        }
    }

    /// Whether this key is transferable (rotating).
    ///
    /// Each variant carries the transferability recorded from its CESR code:
    /// Ed25519 from `D`/`B`, P-256 from `1AAJ`/`1AAI`.
    pub fn is_transferable(&self) -> bool {
        match self {
            KeriPublicKey::Ed25519 { transferable, .. }
            | KeriPublicKey::P256 { transferable, .. } => *transferable,
        }
    }

    /// Returns the CESR derivation code prefix for this key type.
    ///
    /// `D`/`B` for transferable / non-transferable Ed25519; `1AAJ`/`1AAI` for
    /// transferable / non-transferable P-256 (per the CESR master code table).
    pub fn cesr_prefix(&self) -> &'static str {
        match self {
            KeriPublicKey::Ed25519 {
                transferable: true, ..
            } => "D",
            KeriPublicKey::Ed25519 {
                transferable: false,
                ..
            } => "B",
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
    /// assert!(matches!(key, KeriPublicKey::Ed25519 { .. }));
    /// ```
    pub fn ed25519(bytes: &[u8]) -> Result<Self, KeriDecodeError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeriDecodeError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            })?;
        Ok(KeriPublicKey::Ed25519 {
            key: arr,
            transferable: true,
        })
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
            KeriPublicKey::Ed25519 { key: pk, .. } => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn parse_ed25519_all_zeros() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.as_bytes(), &[0u8; 32]);
        assert!(matches!(key, KeriPublicKey::Ed25519 { .. }));
        assert!(key.is_transferable());
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
    fn parse_rejects_malformed_qb64_without_panicking() {
        // A derivation code whose declared primitive size exceeds the actual
        // input length must fail closed with a typed error, never an
        // out-of-bounds slice panic inside the CESR decoder.
        for malformed in ["6AAA1IAA", "1AAJ", "D", "1AAI"] {
            assert!(
                KeriPublicKey::parse(malformed).is_err(),
                "malformed CESR verkey {malformed:?} must be rejected, not panic"
            );
        }
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
        // Not valid CESR for any verkey code: rejected either as undecodable or
        // (if it parses to some other matter code) as an unsupported key type.
        let err = KeriPublicKey::parse("Xsomething").unwrap_err();
        assert!(
            matches!(
                err,
                KeriDecodeError::DecodeError(_) | KeriDecodeError::UnsupportedKeyType(_)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parses_non_transferable_ed25519_code() {
        // `B` (Ed25519N) is the standard KERI witness key code. It decodes to the
        // same 32-byte key as `D`; only transferability and the prefix differ.
        let b_code =
            crate::cesr_encode::encode_verkey(&[0u8; 32], cesride::matter::Codex::Ed25519N)
                .unwrap();
        let key = KeriPublicKey::parse(&b_code).unwrap();
        assert!(matches!(
            key,
            KeriPublicKey::Ed25519 {
                transferable: false,
                ..
            }
        ));
        assert_eq!(key.as_bytes(), &[0u8; 32]);
        assert_eq!(key.curve(), auths_crypto::CurveType::Ed25519);
        assert!(!key.is_transferable());
        assert_eq!(key.cesr_prefix(), "B");
    }

    #[test]
    fn parses_both_d_and_b_ed25519() {
        // Both Ed25519 codes decode to the same 32-byte key; transferability and
        // the round-tripped prefix differ — mirroring the P-256 1AAJ/1AAI pair.
        let d =
            crate::cesr_encode::encode_verkey(&[7u8; 32], cesride::matter::Codex::Ed25519).unwrap();
        let b = crate::cesr_encode::encode_verkey(&[7u8; 32], cesride::matter::Codex::Ed25519N)
            .unwrap();
        let transferable = KeriPublicKey::parse(&d).unwrap();
        let non_transferable = KeriPublicKey::parse(&b).unwrap();
        assert_eq!(transferable.as_bytes(), non_transferable.as_bytes());
        assert!(transferable.is_transferable());
        assert!(!non_transferable.is_transferable());
        assert_eq!(transferable.cesr_prefix(), "D");
        assert_eq!(non_transferable.cesr_prefix(), "B");
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = KeriPublicKey::parse("D!!!invalid!!!").unwrap_err();
        assert!(matches!(err, KeriDecodeError::DecodeError(_)));
    }

    #[test]
    fn rejects_wrong_length_ed25519() {
        // A naive `D` + base64(31 bytes) has the wrong qb64 length for the
        // Ed25519 code, so cesride rejects it as malformed CESR.
        let short = [0u8; 31];
        let encoded = format!("D{}", URL_SAFE_NO_PAD.encode(short));
        let err = KeriPublicKey::parse(&encoded).unwrap_err();
        assert!(matches!(err, KeriDecodeError::DecodeError(_)));
    }

    #[test]
    fn rejects_wrong_length_p256() {
        // A naive `1AAJ` + base64(32 bytes) has the wrong qb64 length for the
        // ECDSA_256r1 code, so cesride rejects it as malformed CESR.
        let short = [0u8; 32];
        let encoded = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(short));
        let err = KeriPublicKey::parse(&encoded).unwrap_err();
        assert!(matches!(err, KeriDecodeError::DecodeError(_)));
    }

    // `as_bytes()` returns `&[u8]`; Ed25519 keys must still convert cleanly to a
    // 32-byte array for callers that need the fixed-width form.
    #[test]
    fn ed25519_as_bytes_is_32() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let bytes = key.as_bytes();
        assert_eq!(bytes.len(), 32);
        // Can still convert to [u8; 32] for backward compat
        let arr: [u8; 32] = bytes.try_into().unwrap();
        assert_eq!(arr, [0u8; 32]);
    }

    /// keripy 1.3.4 reference: `Verfer(bytes(0..32), Ed25519).qb64`. `parse` must
    /// decode it to the exact 32 raw bytes via CESR alignment (lead-byte aware),
    /// NOT naive base64-after-`D` (which would recover shifted, wrong bytes).
    #[test]
    fn parse_matches_keripy_ed25519_vector() {
        let raw: Vec<u8> = (0u8..32).collect();
        let key = KeriPublicKey::parse("DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f").unwrap();
        assert_eq!(key.as_bytes(), raw.as_slice());
        assert_eq!(key.curve(), auths_crypto::CurveType::Ed25519);
    }

    /// `parse` must invert `to_qb64` (cesride) for a non-zero Ed25519 key.
    #[test]
    fn parse_inverts_to_qb64_ed25519() {
        let raw: Vec<u8> = (0u8..32).collect();
        let key = KeriPublicKey::ed25519(&raw).unwrap();
        let qb64 = key.to_qb64().unwrap();
        let parsed = KeriPublicKey::parse(&qb64).unwrap();
        assert_eq!(parsed, key, "parse must invert to_qb64 (CESR round-trip)");
    }

    /// `parse` must invert `to_qb64` for a non-zero transferable P-256 key.
    #[test]
    fn parse_inverts_to_qb64_p256() {
        let mut point = [0u8; 33];
        point[0] = 0x02;
        for (i, b) in point.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        let key = KeriPublicKey::from_verkey_bytes(&point, auths_crypto::CurveType::P256).unwrap();
        let qb64 = key.to_qb64().unwrap();
        let parsed = KeriPublicKey::parse(&qb64).unwrap();
        assert_eq!(parsed, key, "P-256 parse must invert to_qb64");
        assert!(parsed.is_transferable());
    }
}
