//! Symmetric encryption utilities.

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::EncryptionAlgorithm;
use crate::error::AgentError;

/// Byte size of the algorithm tag prefix.
pub const TAG_LEN: usize = 1;
/// Byte size of the nonce used in both AES-GCM and ChaCha20Poly1305.
pub const NONCE_LEN: usize = 12; // we're using 12-byte nonces for both
/// Byte size of the salt used in HKDF key derivation.
pub const SALT_LEN: usize = 16;
/// Length in bytes of a symmetric encryption key (256-bit).
pub const SYMMETRIC_KEY_LEN: usize = 32;

/// Tag byte for Argon2id-derived encryption blobs.
pub const ARGON2_TAG: u8 = 3;
/// Length of embedded Argon2 parameters: 3 × u32 LE = 12 bytes.
const ARGON2_PARAMS_LEN: usize = 12;

/// Returns Argon2id parameters for key derivation.
///
/// Production builds use OWASP-recommended settings (m=64 MiB, t=3).
/// Test and `test-utils` builds use minimal settings (m=8 KiB, t=1) to keep
/// both unit and integration test suites fast. The parameters are embedded in
/// the encrypted blob, so decryption always uses the values from the blob
/// header rather than this getter.
///
/// Args:
/// * None
///
/// Usage:
/// ```ignore
/// let params = get_kdf_params()?;
/// let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
/// ```
pub fn get_kdf_params() -> Result<Params, AgentError> {
    #[cfg(not(any(test, feature = "test-utils")))]
    let params = Params::new(65536, 3, 1, Some(SYMMETRIC_KEY_LEN));
    #[cfg(any(test, feature = "test-utils"))]
    let params = Params::new(8, 1, 1, Some(SYMMETRIC_KEY_LEN));
    params.map_err(|e| AgentError::CryptoError(format!("Invalid Argon2 params: {}", e)))
}

/// Encrypt data, prepending a tag to identify algorithm during decryption.
pub fn encrypt_bytes(
    data: &[u8],
    passphrase: &str,
    algo: EncryptionAlgorithm,
) -> Result<Vec<u8>, AgentError> {
    let salt: [u8; SALT_LEN] = rand::random();
    let hk = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
    let mut key = [0u8; SYMMETRIC_KEY_LEN];
    hk.expand(&[], &mut key)
        .map_err(|_| AgentError::CryptoError("HKDF expand failed".into()))?;

    let nonce: [u8; NONCE_LEN] = rand::random();

    match algo {
        EncryptionAlgorithm::AesGcm256 => {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| AgentError::CryptoError("Invalid AES key".into()))?;

            let ciphertext = cipher
                .encrypt(AesNonce::from_slice(&nonce), data)
                .map_err(|_| AgentError::CryptoError("AES encryption failed".into()))?;

            let mut out = vec![algo.tag()];
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }

        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| AgentError::CryptoError("Invalid ChaCha key".into()))?;

            let ciphertext = cipher
                .encrypt(ChaChaNonce::from_slice(&nonce), data)
                .map_err(|_| AgentError::CryptoError("ChaCha encryption failed".into()))?;

            let mut out = vec![algo.tag()];
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }
    }
}

/// Validates that a passphrase meets minimum strength requirements.
///
/// Requires at least 12 characters and at least 3 of 4 character classes:
/// lowercase, uppercase, digit, symbol.
pub fn validate_passphrase(passphrase: &str) -> Result<(), AgentError> {
    if passphrase.len() < 12 {
        return Err(AgentError::WeakPassphrase(format!(
            "Passphrase must be at least 12 characters (got {})",
            passphrase.len()
        )));
    }

    let has_lower = passphrase.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = passphrase.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_symbol = passphrase.chars().any(|c| {
        c.is_ascii_punctuation() || (c.is_ascii() && !c.is_ascii_alphanumeric() && c != ' ')
    });

    let class_count = has_lower as u8 + has_upper as u8 + has_digit as u8 + has_symbol as u8;

    if class_count < 3 {
        return Err(AgentError::WeakPassphrase(format!(
            "Passphrase must contain at least 3 of 4 character classes \
             (lowercase, uppercase, digit, symbol); found {}",
            class_count
        )));
    }

    Ok(())
}

/// Encrypt data using Argon2id for key derivation, prepending tag 0x03.
///
/// Output format: `[0x03][salt:16][m_cost:4 LE][t_cost:4 LE][p_cost:4 LE][algo_tag:1][nonce:12][ciphertext]`
pub fn encrypt_bytes_argon2(
    data: &[u8],
    passphrase: &str,
    algo: EncryptionAlgorithm,
) -> Result<Vec<u8>, AgentError> {
    validate_passphrase(passphrase)?;

    let salt: [u8; SALT_LEN] = rand::random();

    // Derive key with Argon2id
    let params = get_kdf_params()?;
    let m_cost = params.m_cost();
    let t_cost = params.t_cost();
    let p_cost = params.p_cost();
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; SYMMETRIC_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| AgentError::CryptoError(format!("Argon2 key derivation failed: {}", e)))?;

    let nonce: [u8; NONCE_LEN] = rand::random();

    let ciphertext = match algo {
        EncryptionAlgorithm::AesGcm256 => {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| AgentError::CryptoError("Invalid AES key".into()))?;
            cipher
                .encrypt(AesNonce::from_slice(&nonce), data)
                .map_err(|_| AgentError::CryptoError("AES encryption failed".into()))?
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| AgentError::CryptoError("Invalid ChaCha key".into()))?;
            cipher
                .encrypt(ChaChaNonce::from_slice(&nonce), data)
                .map_err(|_| AgentError::CryptoError("ChaCha encryption failed".into()))?
        }
    };

    // Build output: [tag][salt][m_cost LE][t_cost LE][p_cost LE][algo_tag][nonce][ciphertext]
    let mut out = Vec::with_capacity(
        TAG_LEN + SALT_LEN + ARGON2_PARAMS_LEN + TAG_LEN + NONCE_LEN + ciphertext.len(),
    );
    out.push(ARGON2_TAG);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&m_cost.to_le_bytes());
    out.extend_from_slice(&t_cost.to_le_bytes());
    out.extend_from_slice(&p_cost.to_le_bytes());
    out.push(algo.tag());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts data using a tagged encryption format and a user-provided passphrase.
///
/// Supports three tag formats:
/// - Tag 1 (AES-GCM) / Tag 2 (ChaCha20): Legacy HKDF path `[tag][salt:16][nonce:12][ciphertext]`
/// - Tag 3 (Argon2id): `[0x03][salt:16][m_cost:4 LE][t_cost:4 LE][p_cost:4 LE][algo_tag:1][nonce:12][ciphertext]`
///
/// If decryption fails (e.g. due to wrong passphrase), returns
/// `AgentError::IncorrectPassphrase`.
pub fn decrypt_bytes(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, AgentError> {
    if encrypted.is_empty() {
        return Err(AgentError::CryptoError("Encrypted data too short".into()));
    }

    let tag = encrypted[0];

    if tag == ARGON2_TAG {
        return decrypt_bytes_argon2(encrypted, passphrase);
    }

    // Legacy HKDF path (tags 1, 2)
    if encrypted.len() < TAG_LEN + SALT_LEN + NONCE_LEN {
        return Err(AgentError::CryptoError("Encrypted data too short".into()));
    }

    let algo = EncryptionAlgorithm::from_tag(tag)
        .ok_or_else(|| AgentError::CryptoError(format!("Unknown encryption tag: {}", tag)))?;

    let rest = &encrypted[TAG_LEN..];
    let (salt, remaining) = rest.split_at(SALT_LEN);
    let (nonce, ciphertext) = remaining.split_at(NONCE_LEN);

    let hkdf = Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
    let mut key = [0u8; SYMMETRIC_KEY_LEN];
    hkdf.expand(&[], &mut key)
        .map_err(|_| AgentError::CryptoError("HKDF expand failed".into()))?;

    let result = match algo {
        EncryptionAlgorithm::AesGcm256 => Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AgentError::CryptoError("Invalid AES key".into()))?
            .decrypt(AesNonce::from_slice(nonce), ciphertext),

        EncryptionAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| AgentError::CryptoError("Invalid ChaCha key".into()))?
            .decrypt(ChaChaNonce::from_slice(nonce), ciphertext),
    };

    match result {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(AgentError::IncorrectPassphrase),
    }
}

/// Decrypts an Argon2id-tagged blob.
///
/// Expected format: `[0x03][salt:16][m_cost:4 LE][t_cost:4 LE][p_cost:4 LE][algo_tag:1][nonce:12][ciphertext]`
fn decrypt_bytes_argon2(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, AgentError> {
    const MIN_LEN: usize = TAG_LEN + SALT_LEN + ARGON2_PARAMS_LEN + TAG_LEN + NONCE_LEN;
    if encrypted.len() < MIN_LEN {
        return Err(AgentError::CryptoError(
            "Argon2id encrypted data too short".into(),
        ));
    }

    let mut offset = TAG_LEN; // skip the 0x03 tag

    let salt = &encrypted[offset..offset + SALT_LEN];
    offset += SALT_LEN;

    let m_cost = u32::from_le_bytes(
        encrypted[offset..offset + 4]
            .try_into()
            .map_err(|_| AgentError::CryptoError("invalid m_cost bytes".into()))?,
    );
    offset += 4;
    let t_cost = u32::from_le_bytes(
        encrypted[offset..offset + 4]
            .try_into()
            .map_err(|_| AgentError::CryptoError("invalid t_cost bytes".into()))?,
    );
    offset += 4;
    let p_cost = u32::from_le_bytes(
        encrypted[offset..offset + 4]
            .try_into()
            .map_err(|_| AgentError::CryptoError("invalid p_cost bytes".into()))?,
    );
    offset += 4;

    let algo_tag = encrypted[offset];
    offset += 1;
    let algo = EncryptionAlgorithm::from_tag(algo_tag)
        .ok_or_else(|| AgentError::CryptoError(format!("Unknown encryption tag: {}", algo_tag)))?;

    let nonce = &encrypted[offset..offset + NONCE_LEN];
    offset += NONCE_LEN;

    let ciphertext = &encrypted[offset..];

    // Derive key with Argon2id using embedded params
    let params = Params::new(m_cost, t_cost, p_cost, Some(SYMMETRIC_KEY_LEN))
        .map_err(|e| AgentError::CryptoError(format!("Invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; SYMMETRIC_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| AgentError::CryptoError(format!("Argon2 key derivation failed: {}", e)))?;

    let result = match algo {
        EncryptionAlgorithm::AesGcm256 => Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AgentError::CryptoError("Invalid AES key".into()))?
            .decrypt(AesNonce::from_slice(nonce), ciphertext),

        EncryptionAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| AgentError::CryptoError("Invalid ChaCha key".into()))?
            .decrypt(ChaChaNonce::from_slice(nonce), ciphertext),
    };

    match result {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(AgentError::IncorrectPassphrase),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptionAlgorithm;

    const STRONG_PASS: &str = "MyStr0ng!Pass";

    #[test]
    fn test_argon2_roundtrip_aes() {
        let data = b"hello argon2 aes";
        let encrypted =
            encrypt_bytes_argon2(data, STRONG_PASS, EncryptionAlgorithm::AesGcm256).unwrap();
        let decrypted = decrypt_bytes(&encrypted, STRONG_PASS).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_argon2_roundtrip_chacha() {
        let data = b"hello argon2 chacha";
        let encrypted =
            encrypt_bytes_argon2(data, STRONG_PASS, EncryptionAlgorithm::ChaCha20Poly1305).unwrap();
        let decrypted = decrypt_bytes(&encrypted, STRONG_PASS).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_legacy_hkdf_decrypt_still_works() {
        let data = b"legacy data";
        let encrypted =
            encrypt_bytes(data, "any-passphrase", EncryptionAlgorithm::AesGcm256).unwrap();
        let decrypted = decrypt_bytes(&encrypted, "any-passphrase").unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_argon2_wrong_passphrase() {
        let data = b"secret";
        let encrypted =
            encrypt_bytes_argon2(data, STRONG_PASS, EncryptionAlgorithm::AesGcm256).unwrap();
        let result = decrypt_bytes(&encrypted, "Wr0ng!Passphrase");
        assert!(matches!(result, Err(AgentError::IncorrectPassphrase)));
    }

    #[test]
    fn test_argon2_blob_starts_with_tag_3() {
        let data = b"tag check";
        let encrypted =
            encrypt_bytes_argon2(data, STRONG_PASS, EncryptionAlgorithm::AesGcm256).unwrap();
        assert_eq!(encrypted[0], ARGON2_TAG);
    }

    #[test]
    fn test_unknown_tag_returns_error() {
        let blob = vec![0xFF; 64];
        let result = decrypt_bytes(&blob, "irrelevant");
        assert!(matches!(result, Err(AgentError::CryptoError(_))));
    }

    #[test]
    fn test_validate_passphrase_too_short() {
        let result = validate_passphrase("Short1!");
        assert!(matches!(result, Err(AgentError::WeakPassphrase(_))));
    }

    #[test]
    fn test_validate_passphrase_insufficient_classes() {
        // 14 chars, only lowercase + uppercase = 2 classes
        let result = validate_passphrase("abcdefABCDEFgh");
        assert!(matches!(result, Err(AgentError::WeakPassphrase(_))));
    }

    #[test]
    fn test_validate_passphrase_strong() {
        assert!(validate_passphrase(STRONG_PASS).is_ok());
    }

    #[test]
    fn test_argon2_encrypt_rejects_weak() {
        let result = encrypt_bytes_argon2(b"data", "weak", EncryptionAlgorithm::AesGcm256);
        assert!(matches!(result, Err(AgentError::WeakPassphrase(_))));
    }
}
