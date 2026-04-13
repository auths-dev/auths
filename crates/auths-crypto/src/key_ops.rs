//! Curve-agnostic key operations.
//!
//! Single source of truth for parsing, signing, and public key derivation
//! across Ed25519 and P-256. The [`TypedSeed`] enum carries the curve with
//! the key material — callers never need to guess which curve a key uses.

// INVARIANT: sanctioned crypto boundary — the only legitimate caller of ring
// Ed25519 APIs inside the workspace. Every other crate must route through
// auths_crypto::sign / public_key / TypedSignerKey. Permanent allow; do NOT
// remove in fn-114.40.
#![allow(clippy::disallowed_methods)]

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::provider::{CryptoError, CurveType, SecureSeed};

/// A private key seed that knows its curve.
///
/// Adding a new curve means adding a variant here. The compiler then errors
/// on every `match` that doesn't handle it — no grep needed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum TypedSeed {
    /// Ed25519 private key seed (32 bytes).
    Ed25519(#[zeroize] [u8; 32]),
    /// P-256 private scalar (32 bytes).
    P256(#[zeroize] [u8; 32]),
}

impl TypedSeed {
    /// Returns the curve this seed belongs to.
    pub fn curve(&self) -> CurveType {
        match self {
            Self::Ed25519(_) => CurveType::Ed25519,
            Self::P256(_) => CurveType::P256,
        }
    }

    /// Returns the raw seed bytes (32 bytes for both Ed25519 and P-256).
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Self::Ed25519(b) | Self::P256(b) => b,
        }
    }

    /// Convert to a legacy `SecureSeed` (loses curve info — use sparingly).
    pub fn to_secure_seed(&self) -> SecureSeed {
        SecureSeed::new(*self.as_bytes())
    }
}

impl std::fmt::Debug for TypedSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(_) => f.write_str("TypedSeed::Ed25519([REDACTED])"),
            Self::P256(_) => f.write_str("TypedSeed::P256([REDACTED])"),
        }
    }
}

/// Parsed key material with curve baked in.
#[derive(Debug)]
pub struct ParsedKey {
    /// The private key seed, typed to its curve.
    pub seed: TypedSeed,
    /// The public key bytes (32 for Ed25519, 33 for P-256 compressed).
    pub public_key: Vec<u8>,
}

/// Parse any supported PKCS8 DER (or raw seed) to extract seed + public key + curve.
///
/// This is the single source of truth for "what curve is this key?"
/// The curve is detected here and carried in `TypedSeed` — never re-guessed.
///
/// Usage:
/// ```ignore
/// let parsed = parse_key_material(&pkcs8_bytes)?;
/// let sig = sign(&parsed.seed, message)?;
/// ```
pub fn parse_key_material(bytes: &[u8]) -> Result<ParsedKey, CryptoError> {
    // Try Ed25519 first (most common, multiple PKCS8 formats)
    if let Ok((seed, maybe_pk)) = crate::key_material::parse_ed25519_key_material(bytes) {
        let public_key = match maybe_pk {
            Some(pk) => pk.to_vec(),
            None => {
                // Derive from seed via ring
                #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
                {
                    use ring::signature::{Ed25519KeyPair, KeyPair};
                    let kp = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes()).map_err(|e| {
                        CryptoError::OperationFailed(format!("Ed25519 pubkey: {e}"))
                    })?;
                    kp.public_key().as_ref().to_vec()
                }
                #[cfg(not(all(feature = "native", not(target_arch = "wasm32"))))]
                {
                    return Err(CryptoError::UnsupportedTarget);
                }
            }
        };
        return Ok(ParsedKey {
            seed: TypedSeed::Ed25519(*seed.as_bytes()),
            public_key,
        });
    }

    // Try P-256 PKCS8
    #[cfg(feature = "native")]
    {
        use p256::pkcs8::DecodePrivateKey;
        if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_der(bytes) {
            let vk = p256::ecdsa::VerifyingKey::from(&sk);
            let compressed = vk.to_encoded_point(true);
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&sk.to_bytes());
            return Ok(ParsedKey {
                seed: TypedSeed::P256(scalar),
                public_key: compressed.as_bytes().to_vec(),
            });
        }
    }

    Err(CryptoError::InvalidPrivateKey(format!(
        "Unrecognized key format ({} bytes)",
        bytes.len()
    )))
}

/// Sign a message using the seed's curve. No curve parameter needed.
///
/// Usage:
/// ```ignore
/// let parsed = parse_key_material(&pkcs8)?;
/// let sig = sign(&parsed.seed, b"hello")?;
/// ```
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub fn sign(seed: &TypedSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match seed {
        TypedSeed::Ed25519(s) => {
            use ring::signature::Ed25519KeyPair;
            let kp = Ed25519KeyPair::from_seed_unchecked(s)
                .map_err(|e| CryptoError::InvalidPrivateKey(format!("Ed25519: {e}")))?;
            Ok(kp.sign(message).as_ref().to_vec())
        }
        TypedSeed::P256(s) => {
            use p256::ecdsa::{SigningKey, signature::Signer};
            let sk = SigningKey::from_slice(s)
                .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256: {e}")))?;
            let sig: p256::ecdsa::Signature = sk.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Derive the public key from the seed's curve.
///
/// Returns 32 bytes for Ed25519, 33 bytes compressed SEC1 for P-256.
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub fn public_key(seed: &TypedSeed) -> Result<Vec<u8>, CryptoError> {
    match seed {
        TypedSeed::Ed25519(s) => {
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let kp = Ed25519KeyPair::from_seed_unchecked(s)
                .map_err(|e| CryptoError::OperationFailed(format!("Ed25519 pubkey: {e}")))?;
            Ok(kp.public_key().as_ref().to_vec())
        }
        TypedSeed::P256(s) => {
            use p256::ecdsa::SigningKey;
            let sk = SigningKey::from_slice(s)
                .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256: {e}")))?;
            let vk = p256::ecdsa::VerifyingKey::from(&sk);
            let compressed = vk.to_encoded_point(true);
            Ok(compressed.as_bytes().to_vec())
        }
    }
}

/// Parsed signing key with curve carried explicitly — the authoritative owner
/// of a private-key + curve pair across sign / verify / PKCS8 export / CESR
/// encoding flows.
///
/// `TypedSignerKey` replaces every `(SecureSeed, CurveType)` pair, every
/// `[u8; 32]` seed passed alongside an implicit "assume Ed25519", and every
/// ad-hoc `RotationSigner` (kept as a type alias during the fn-114 refactor).
///
/// Constructed from PKCS8 DER bytes via [`TypedSignerKey::from_pkcs8`], which
/// delegates to [`parse_key_material`] for curve detection.
///
/// Args on construction:
/// * `bytes`: PKCS8 DER (Ed25519 v1/v2 or P-256).
///
/// Usage:
/// ```ignore
/// let s = TypedSignerKey::from_pkcs8(&pkcs8)?;
/// let sig = s.sign(b"payload bytes")?;
/// let cesr = s.cesr_encoded_pubkey(); // "D..." for Ed25519, "1AAI..." for P-256 (spec-correct)
/// let pkcs8 = s.to_pkcs8()?;          // curve-aware encode (replaces build_ed25519_pkcs8_v2)
/// ```
#[derive(Debug)]
pub struct TypedSignerKey {
    /// The private seed, tagged with its curve. Private — access via [`TypedSignerKey::curve`]
    /// or the typed sign/to_pkcs8 methods. Prevents callers from grabbing raw bytes and
    /// re-introducing curve-less dispatch.
    seed: TypedSeed,
    /// The public key bytes (32 Ed25519, 33 P-256 compressed). Private — access via
    /// [`TypedSignerKey::public_key`].
    public_key: Vec<u8>,
}

/// Transitional alias. Callers that haven't migrated yet keep working. Remove
/// in fn-114.40 once every caller has switched to `TypedSignerKey`.
pub type RotationSigner = TypedSignerKey;

impl TypedSignerKey {
    /// Parse a PKCS8 DER blob into a curve-tagged signer.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        let parsed = parse_key_material(bytes)?;
        Ok(Self {
            seed: parsed.seed,
            public_key: parsed.public_key,
        })
    }

    /// Construct directly from a typed seed and its derived public key.
    /// Caller must ensure the public key matches the seed's curve; if the
    /// lengths disagree with the curve, returns `InvalidPrivateKey`.
    pub fn from_parts(seed: TypedSeed, public_key: Vec<u8>) -> Result<Self, CryptoError> {
        let expected = seed.curve().public_key_len();
        if public_key.len() != expected {
            return Err(CryptoError::InvalidPrivateKey(format!(
                "public key length {} does not match {} expected {} bytes",
                public_key.len(),
                seed.curve(),
                expected
            )));
        }
        Ok(Self { seed, public_key })
    }

    /// Derive from a typed seed by recomputing the public key.
    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    pub fn from_seed(seed: TypedSeed) -> Result<Self, CryptoError> {
        let pk = public_key(&seed)?;
        Ok(Self {
            seed,
            public_key: pk,
        })
    }

    /// CESR-encoded public key string.
    ///
    /// Uses the spec-correct derivation codes:
    /// - `D` + base64url(32 bytes) for Ed25519
    /// - `1AAI` + base64url(33 bytes compressed SEC1) for P-256
    ///
    /// audit corrected a prior `1AAJ` emission (which is the CESR
    /// spec's P-256 *signature* prefix, not verkey). `KeriPublicKey::parse`
    /// remains tolerant of legacy `1AAJ` so pre-fn-114.37 identities still
    /// deserialize.
    pub fn cesr_encoded_pubkey(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        match self.seed.curve() {
            CurveType::Ed25519 => format!("D{}", URL_SAFE_NO_PAD.encode(&self.public_key)),
            CurveType::P256 => format!("1AAI{}", URL_SAFE_NO_PAD.encode(&self.public_key)),
        }
    }

    /// Legacy alias; callers should prefer [`cesr_encoded_pubkey`].
    pub fn cesr_encoded(&self) -> String {
        self.cesr_encoded_pubkey()
    }

    /// Curve-aware PKCS8 DER encode — replaces `build_ed25519_pkcs8_v2` and
    /// `encode_seed_as_pkcs8`. Dispatches on the seed's curve so a P-256 seed
    /// never silently wraps as an Ed25519 PKCS8 blob (hazard S3/S4).
    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    pub fn to_pkcs8(&self) -> Result<crate::pkcs8::Pkcs8Der, CryptoError> {
        match &self.seed {
            TypedSeed::Ed25519(seed_bytes) => {
                if self.public_key.len() != crate::provider::ED25519_PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidPrivateKey(
                        "Ed25519 public key must be 32 bytes".to_string(),
                    ));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&self.public_key);
                let bytes = crate::key_material::build_ed25519_pkcs8_v2(seed_bytes, &pk);
                Ok(crate::pkcs8::Pkcs8Der::new(bytes))
            }
            TypedSeed::P256(scalar) => {
                use p256::ecdsa::SigningKey;
                use p256::pkcs8::EncodePrivateKey;
                let sk = SigningKey::from_slice(scalar)
                    .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256 scalar: {e}")))?;
                let doc = sk
                    .to_pkcs8_der()
                    .map_err(|e| CryptoError::OperationFailed(format!("P-256 PKCS8: {e}")))?;
                Ok(crate::pkcs8::Pkcs8Der::new(doc.as_bytes().to_vec()))
            }
        }
    }

    /// Sign bytes using the signer's curve.
    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sign(&self.seed, message)
    }

    /// Returns the curve this signer uses.
    pub fn curve(&self) -> CurveType {
        self.seed.curve()
    }

    /// Returns the public key bytes (32 for Ed25519, 33 for P-256 compressed).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns a reference to the typed seed. Scoped access for signing paths that
    /// need the `TypedSeed` directly (e.g. `auths_crypto::sign(&seed, msg)`) without
    /// exposing the raw bytes.
    pub fn seed(&self) -> &TypedSeed {
        &self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_seed_curve_identification() {
        let ed = TypedSeed::Ed25519([1u8; 32]);
        assert_eq!(ed.curve(), CurveType::Ed25519);

        let p = TypedSeed::P256([2u8; 32]);
        assert_eq!(p.curve(), CurveType::P256);
    }

    #[test]
    fn typed_seed_as_bytes() {
        let seed = TypedSeed::Ed25519([42u8; 32]);
        assert_eq!(seed.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn typed_seed_debug_redacts() {
        let seed = TypedSeed::P256([0u8; 32]);
        let debug = format!("{:?}", seed);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0, 0, 0"));
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    mod native {
        use super::*;

        #[test]
        fn parse_ed25519_pkcs8_v2() {
            // Generate via ring, parse back
            use ring::rand::SystemRandom;
            use ring::signature::Ed25519KeyPair;
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let parsed = parse_key_material(pkcs8.as_ref()).unwrap();
            assert_eq!(parsed.seed.curve(), CurveType::Ed25519);
            assert_eq!(parsed.public_key.len(), 32);
        }

        #[test]
        fn parse_p256_pkcs8() {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::rand_core::OsRng;
            use p256::pkcs8::EncodePrivateKey;
            let sk = SigningKey::random(&mut OsRng);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            let parsed = parse_key_material(pkcs8.as_bytes()).unwrap();
            assert_eq!(parsed.seed.curve(), CurveType::P256);
            assert_eq!(parsed.public_key.len(), 33);
        }

        #[test]
        fn parse_raw_32_bytes_is_ed25519() {
            let raw = [7u8; 32];
            let parsed = parse_key_material(&raw).unwrap();
            assert_eq!(parsed.seed.curve(), CurveType::Ed25519);
        }

        #[test]
        fn parse_garbage_fails() {
            let garbage = [0xFFu8; 50];
            assert!(parse_key_material(&garbage).is_err());
        }

        #[test]
        fn parse_empty_fails() {
            assert!(parse_key_material(&[]).is_err());
        }

        #[test]
        fn sign_ed25519_roundtrip() {
            use ring::signature::{ED25519, UnparsedPublicKey};
            let seed = TypedSeed::Ed25519([1u8; 32]);
            let msg = b"hello world";
            let sig = sign(&seed, msg).unwrap();
            assert_eq!(sig.len(), 64);

            let pk = public_key(&seed).unwrap();
            let verifier = UnparsedPublicKey::new(&ED25519, &pk);
            assert!(verifier.verify(msg, &sig).is_ok());
        }

        #[test]
        fn sign_p256_roundtrip() {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let seed = TypedSeed::P256([3u8; 32]);
            let msg = b"hello p256";
            let sig_bytes = sign(&seed, msg).unwrap();
            assert_eq!(sig_bytes.len(), 64);

            let pk_bytes = public_key(&seed).unwrap();
            assert_eq!(pk_bytes.len(), 33);

            let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            assert!(vk.verify(msg, &sig).is_ok());
        }

        #[test]
        fn cross_curve_isolation() {
            // Same raw bytes, different curves, different outputs
            let bytes = [5u8; 32];
            let ed_seed = TypedSeed::Ed25519(bytes);
            let p256_seed = TypedSeed::P256(bytes);

            let ed_pk = public_key(&ed_seed).unwrap();
            let p256_pk = public_key(&p256_seed).unwrap();

            // Different lengths (32 vs 33) and different values
            assert_ne!(ed_pk.len(), p256_pk.len());

            let msg = b"test";
            let ed_sig = sign(&ed_seed, msg).unwrap();
            let p256_sig = sign(&p256_seed, msg).unwrap();

            // Both 64 bytes but different values
            assert_eq!(ed_sig.len(), 64);
            assert_eq!(p256_sig.len(), 64);
            assert_ne!(ed_sig, p256_sig);
        }

        #[test]
        fn parse_then_sign_ed25519() {
            use ring::rand::SystemRandom;
            use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let parsed = parse_key_material(pkcs8.as_ref()).unwrap();

            let msg = b"end to end";
            let sig = sign(&parsed.seed, msg).unwrap();
            let verifier = UnparsedPublicKey::new(&ED25519, &parsed.public_key);
            assert!(verifier.verify(msg, &sig).is_ok());
        }

        #[test]
        fn parse_then_sign_p256() {
            use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};
            use p256::elliptic_curve::rand_core::OsRng;
            use p256::pkcs8::EncodePrivateKey;

            let sk = SigningKey::random(&mut OsRng);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            let parsed = parse_key_material(pkcs8.as_bytes()).unwrap();

            let msg = b"end to end p256";
            let sig_bytes = sign(&parsed.seed, msg).unwrap();

            let vk = VerifyingKey::from_sec1_bytes(&parsed.public_key).unwrap();
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            assert!(vk.verify(msg, &sig).is_ok());
        }

        #[test]
        fn typed_signer_key_ed25519_roundtrip() {
            use ring::rand::SystemRandom;
            use ring::signature::Ed25519KeyPair;
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let s = TypedSignerKey::from_pkcs8(pkcs8.as_ref()).unwrap();
            assert_eq!(s.curve(), CurveType::Ed25519);
            assert!(s.cesr_encoded_pubkey().starts_with('D'));
            assert_eq!(s.public_key().len(), 32);
            let sig = s.sign(b"msg").unwrap();
            assert_eq!(sig.len(), 64);
        }

        #[test]
        fn typed_signer_key_p256_roundtrip() {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::rand_core::OsRng;
            use p256::pkcs8::EncodePrivateKey;
            let sk = SigningKey::random(&mut OsRng);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            let s = TypedSignerKey::from_pkcs8(pkcs8.as_bytes()).unwrap();
            assert_eq!(s.curve(), CurveType::P256);
            assert!(s.cesr_encoded_pubkey().starts_with("1AAI"));
            assert_eq!(s.public_key().len(), 33);
            let sig = s.sign(b"msg").unwrap();
            assert_eq!(sig.len(), 64);
        }

        #[test]
        fn typed_signer_key_to_pkcs8_ed25519_roundtrip() {
            use ring::rand::SystemRandom;
            use ring::signature::Ed25519KeyPair;
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let s = TypedSignerKey::from_pkcs8(pkcs8.as_ref()).unwrap();
            let encoded = s.to_pkcs8().unwrap();
            let reparsed = TypedSignerKey::from_pkcs8(encoded.as_ref()).unwrap();
            assert_eq!(reparsed.curve(), CurveType::Ed25519);
            assert_eq!(reparsed.public_key(), s.public_key());
            assert_eq!(reparsed.seed.as_bytes(), s.seed.as_bytes());
        }

        #[test]
        fn typed_signer_key_to_pkcs8_p256_roundtrip() {
            let seed = TypedSeed::P256({
                let mut scalar = [9u8; 32];
                scalar[0] |= 1;
                scalar
            });
            let s = TypedSignerKey::from_seed(seed).unwrap();
            let encoded = s.to_pkcs8().unwrap();
            let reparsed = TypedSignerKey::from_pkcs8(encoded.as_ref()).unwrap();
            assert_eq!(reparsed.curve(), CurveType::P256);
            assert_eq!(reparsed.public_key(), s.public_key());
            assert_eq!(reparsed.seed.as_bytes(), s.seed.as_bytes());
        }

        #[test]
        fn rotation_signer_alias_still_works() {
            use ring::rand::SystemRandom;
            use ring::signature::Ed25519KeyPair;
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            // Via the transitional alias
            let s: RotationSigner = RotationSigner::from_pkcs8(pkcs8.as_ref()).unwrap();
            assert_eq!(s.curve(), CurveType::Ed25519);
        }

        #[test]
        fn typed_signer_key_from_parts_rejects_mismatched_pubkey_length() {
            let seed = TypedSeed::Ed25519([1u8; 32]);
            let wrong_len_pk = vec![0u8; 33]; // 33 bytes, expected 32 for Ed25519
            let err = TypedSignerKey::from_parts(seed, wrong_len_pk).unwrap_err();
            assert!(matches!(err, CryptoError::InvalidPrivateKey(_)));
        }
    }
}
