//! Ed25519 key material parsing from various serialization formats.
//!
//! Extracts [`SecureSeed`] (and optionally the public key) from PKCS#8 v1, v2,
//! raw 32-byte seeds, and OCTET-STRING-wrapped seeds — pure byte parsing with
//! no backend dependency.

use crate::provider::{CryptoError, SecureSeed};

/// PKCS#8 v2 Ed25519 total length — explicit [1] tag (85 bytes).
const PKCS8_V2_EXPLICIT_LEN: usize = 85;

/// PKCS#8 v2 Ed25519 total length — implicit [1] tag, as produced by ring (83 bytes).
const PKCS8_V2_IMPLICIT_LEN: usize = 83;

/// PKCS#8 v1 Ed25519 total length (48 bytes) — seed wrapped in inner OCTET STRING.
const PKCS8_V1_LEN: usize = 48;

/// PKCS#8 v1 Ed25519 with unwrapped seed (46 bytes) — seed directly in outer OCTET STRING.
const PKCS8_V1_UNWRAPPED_LEN: usize = 46;

/// Offset where the 32-byte seed starts in PKCS#8 formats with inner OCTET STRING wrapper.
const SEED_OFFSET: usize = 16;

/// Offset where the 32-byte seed starts in PKCS#8 v1 without inner OCTET STRING wrapper.
const SEED_OFFSET_UNWRAPPED: usize = 14;

/// Offset where the 32-byte public key starts in PKCS#8 v2 (explicit [1] tag).
const PUBKEY_OFFSET_EXPLICIT: usize = 53;

/// Offset where the 32-byte public key starts in PKCS#8 v2 (implicit [1] tag, ring format).
const PUBKEY_OFFSET_IMPLICIT: usize = 51;

/// Parse an Ed25519 seed from key bytes in various formats.
///
/// Handles:
/// 1. PKCS#8 v2 explicit tag (85 bytes) — seed at bytes [16..48]
/// 2. PKCS#8 v2 implicit tag / ring (83 bytes) — seed at bytes [16..48]
/// 3. PKCS#8 v1 wrapped (48 bytes) — seed at bytes [16..48]
/// 4. PKCS#8 v1 unwrapped (46 bytes) — seed at bytes [14..46]
/// 5. Raw 32-byte seed
/// 6. Raw 34-byte OCTET STRING wrapped seed (04 20 prefix)
///
/// Args:
/// * `bytes`: Key material in any supported format.
///
/// Usage:
/// ```ignore
/// let seed = parse_ed25519_seed(&pkcs8_bytes)?;
/// let sig = provider.sign_ed25519(&seed, b"msg").await?;
/// ```
pub fn parse_ed25519_seed(bytes: &[u8]) -> Result<SecureSeed, CryptoError> {
    match bytes.len() {
        PKCS8_V2_EXPLICIT_LEN | PKCS8_V2_IMPLICIT_LEN | PKCS8_V1_LEN => {
            extract_seed_at(bytes, SEED_OFFSET)
        }
        PKCS8_V1_UNWRAPPED_LEN => extract_seed_at(bytes, SEED_OFFSET_UNWRAPPED),
        32 => {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(bytes);
            Ok(SecureSeed::new(buf))
        }
        34 if bytes[0] == 0x04 && bytes[1] == 0x20 => {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[2..]);
            Ok(SecureSeed::new(buf))
        }
        _ => Err(CryptoError::InvalidPrivateKey(format!(
            "Unrecognized Ed25519 key format ({} bytes)",
            bytes.len()
        ))),
    }
}

/// Parse an Ed25519 seed and, when available, the public key from key bytes.
///
/// Returns `(seed, Some(pubkey))` for PKCS#8 v2 (which embeds the public key),
/// or `(seed, None)` for formats that don't include one. Callers can derive the
/// public key from the seed via [`CryptoProvider::ed25519_public_key_from_seed`].
///
/// Args:
/// * `bytes`: Key material in any supported format.
///
/// Usage:
/// ```ignore
/// let (seed, maybe_pk) = parse_ed25519_key_material(&pkcs8_bytes)?;
/// let pk = match maybe_pk {
///     Some(pk) => pk,
///     None => provider.ed25519_public_key_from_seed(&seed).await?,
/// };
/// ```
pub fn parse_ed25519_key_material(
    bytes: &[u8],
) -> Result<(SecureSeed, Option<[u8; 32]>), CryptoError> {
    let seed = parse_ed25519_seed(bytes)?;

    let pubkey = match bytes.len() {
        PKCS8_V2_EXPLICIT_LEN => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes[PUBKEY_OFFSET_EXPLICIT..PUBKEY_OFFSET_EXPLICIT + 32]);
            Some(pk)
        }
        PKCS8_V2_IMPLICIT_LEN => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes[PUBKEY_OFFSET_IMPLICIT..PUBKEY_OFFSET_IMPLICIT + 32]);
            Some(pk)
        }
        _ => None,
    };

    Ok((seed, pubkey))
}

/// Build a PKCS#8 v2 DER encoding from a raw seed and public key.
///
/// Produces an 85-byte document (explicit [1] tag) compatible with ring's
/// `Ed25519KeyPair::from_pkcs8` (which accepts both 83 and 85-byte forms).
///
/// Args:
/// * `seed`: Raw 32-byte Ed25519 private key seed.
/// * `pubkey`: Raw 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let (seed, pk) = provider.generate_ed25519_keypair().await?;
/// let pkcs8 = build_ed25519_pkcs8_v2(seed.as_bytes(), &pk);
/// assert_eq!(pkcs8.len(), 85);
/// ```
pub fn build_ed25519_pkcs8_v2(seed: &[u8; 32], pubkey: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PKCS8_V2_EXPLICIT_LEN);
    // SEQUENCE (83 bytes payload)
    buf.extend_from_slice(&[0x30, 0x53]);
    // INTEGER 1 (version = v2)
    buf.extend_from_slice(&[0x02, 0x01, 0x01]);
    // SEQUENCE { OID 1.3.101.112 }
    buf.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // OCTET STRING (34 bytes) containing OCTET STRING (32 bytes) containing seed
    buf.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    buf.extend_from_slice(seed);
    // [1] EXPLICIT BIT STRING (33 bytes: 0x00 pad + 32 bytes pubkey)
    buf.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
    buf.extend_from_slice(pubkey);
    buf
}

fn extract_seed_at(bytes: &[u8], offset: usize) -> Result<SecureSeed, CryptoError> {
    if bytes.len() < offset + 32 {
        return Err(CryptoError::InvalidPrivateKey(
            "Key bytes too short for seed extraction".to_string(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes[offset..offset + 32]);
    Ok(SecureSeed::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_32_byte_seed() {
        let seed_bytes = [42u8; 32];
        let seed = parse_ed25519_seed(&seed_bytes).unwrap();
        assert_eq!(seed.as_bytes(), &seed_bytes);
    }

    #[test]
    fn test_octet_wrapped_34_bytes() {
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&[7u8; 32]);
        let seed = parse_ed25519_seed(&wrapped).unwrap();
        assert_eq!(seed.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn test_pkcs8_v2_roundtrip() {
        let seed_bytes = [1u8; 32];
        let pubkey_bytes = [2u8; 32];
        let pkcs8 = build_ed25519_pkcs8_v2(&seed_bytes, &pubkey_bytes);
        assert_eq!(pkcs8.len(), 85);

        let (seed, maybe_pk) = parse_ed25519_key_material(&pkcs8).unwrap();
        assert_eq!(seed.as_bytes(), &seed_bytes);
        assert_eq!(maybe_pk.unwrap(), pubkey_bytes);
    }

    #[test]
    fn test_pkcs8_v2_seed_extraction() {
        let seed_bytes = [3u8; 32];
        let pubkey_bytes = [4u8; 32];
        let pkcs8 = build_ed25519_pkcs8_v2(&seed_bytes, &pubkey_bytes);

        let seed = parse_ed25519_seed(&pkcs8).unwrap();
        assert_eq!(seed.as_bytes(), &seed_bytes);
    }

    #[test]
    fn test_invalid_length_rejected() {
        let bad = vec![0u8; 50];
        assert!(parse_ed25519_seed(&bad).is_err());
    }

    #[test]
    fn test_ring_83_byte_pkcs8_v2() {
        // Ring produces 83-byte PKCS#8 v2 with implicit [1] tag for public key
        let seed_bytes = [6u8; 32];
        let pubkey_bytes = [7u8; 32];

        let mut buf = Vec::with_capacity(83);
        // SEQUENCE (81 bytes payload)
        buf.extend_from_slice(&[0x30, 0x51]);
        // INTEGER 1 (version = v2)
        buf.extend_from_slice(&[0x02, 0x01, 0x01]);
        // SEQUENCE { OID 1.3.101.112 }
        buf.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
        // OCTET STRING { OCTET STRING { seed } }
        buf.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
        buf.extend_from_slice(&seed_bytes);
        // [1] IMPLICIT (33 bytes: 0x00 pad + pubkey)
        buf.extend_from_slice(&[0x81, 0x21, 0x00]);
        buf.extend_from_slice(&pubkey_bytes);
        assert_eq!(buf.len(), 83);

        let seed = parse_ed25519_seed(&buf).unwrap();
        assert_eq!(seed.as_bytes(), &seed_bytes);

        let (seed2, maybe_pk) = parse_ed25519_key_material(&buf).unwrap();
        assert_eq!(seed2.as_bytes(), &seed_bytes);
        assert_eq!(maybe_pk.unwrap(), pubkey_bytes);
    }

    #[test]
    fn test_non_pkcs8_v2_returns_none_pubkey() {
        let seed_bytes = [5u8; 32];
        let (seed, maybe_pk) = parse_ed25519_key_material(&seed_bytes).unwrap();
        assert_eq!(seed.as_bytes(), &seed_bytes);
        assert!(maybe_pk.is_none());
    }
}
