//! Curve-agnostic key operations.
//!
//! Single source of truth for parsing, signing, and public key derivation
//! across Ed25519 and P-256. The [`TypedSeed`] enum carries the curve with
//! the key material — callers never need to guess which curve a key uses.

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

/// A parsed signing key with its curve carried explicitly — used by rotation
/// workflows and any other code that needs to sign arbitrary bytes without
/// re-inferring the curve.
///
/// Constructed from PKCS8 DER bytes via [`RotationSigner::from_pkcs8`], which
/// delegates to [`parse_key_material`] for curve detection.
///
/// Args on construction:
/// * `bytes`: PKCS8 DER (Ed25519 v1/v2 or P-256).
///
/// Usage:
/// ```ignore
/// let s = RotationSigner::from_pkcs8(&pkcs8)?;
/// let sig = s.sign(b"rotation event bytes")?;
/// let cesr = s.cesr_encoded(); // "D..." for Ed25519, "1AAJ..." for P-256
/// ```
pub struct RotationSigner {
    /// The private seed, tagged with its curve.
    pub seed: TypedSeed,
    /// The public key bytes (32 Ed25519, 33 P-256 compressed).
    pub public_key: Vec<u8>,
}

impl RotationSigner {
    /// Parse a PKCS8 DER blob into a curve-tagged signer.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        let parsed = parse_key_material(bytes)?;
        Ok(Self {
            seed: parsed.seed,
            public_key: parsed.public_key,
        })
    }

    /// CESR-encoded public key string.
    ///
    /// Uses the derivation codes defined in `auths_keri::KeriPublicKey`:
    /// - `D` + base64url(32 bytes) for Ed25519
    /// - `1AAJ` + base64url(33 bytes compressed SEC1) for P-256
    pub fn cesr_encoded(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        match self.seed.curve() {
            CurveType::Ed25519 => format!("D{}", URL_SAFE_NO_PAD.encode(&self.public_key)),
            CurveType::P256 => format!("1AAJ{}", URL_SAFE_NO_PAD.encode(&self.public_key)),
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
        fn rotation_signer_ed25519_roundtrip() {
            use ring::rand::SystemRandom;
            use ring::signature::Ed25519KeyPair;
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let s = RotationSigner::from_pkcs8(pkcs8.as_ref()).unwrap();
            assert_eq!(s.curve(), CurveType::Ed25519);
            assert!(s.cesr_encoded().starts_with('D'));
            assert_eq!(s.public_key.len(), 32);
            let sig = s.sign(b"msg").unwrap();
            assert_eq!(sig.len(), 64);
        }

        #[test]
        fn rotation_signer_p256_roundtrip() {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::rand_core::OsRng;
            use p256::pkcs8::EncodePrivateKey;
            let sk = SigningKey::random(&mut OsRng);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            let s = RotationSigner::from_pkcs8(pkcs8.as_bytes()).unwrap();
            assert_eq!(s.curve(), CurveType::P256);
            assert!(s.cesr_encoded().starts_with("1AAJ"));
            assert_eq!(s.public_key.len(), 33);
            let sig = s.sign(b"msg").unwrap();
            assert_eq!(sig.len(), 64);
        }
    }
}
