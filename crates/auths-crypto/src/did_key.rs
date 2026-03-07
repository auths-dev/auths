//! DID:key encoding and decoding for Ed25519 public keys.
//!
//! Centralizes all `did:key` ↔ Ed25519 byte conversions in one place.
//! The `did:key` method encodes a public key directly in the DID string
//! using multicodec + base58btc, per the [did:key spec](https://w3c-ccg.github.io/did-method-key/).

/// Ed25519 multicodec prefix (varint-encoded `0xED`).
const ED25519_MULTICODEC: [u8; 2] = [0xED, 0x01];

/// Errors from parsing or encoding `did:key` strings.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidKeyError {
    #[error("DID must start with 'did:key:z', got: {0}")]
    InvalidPrefix(String),

    #[error("Base58 decoding failed: {0}")]
    Base58DecodeFailed(String),

    #[error("Unsupported or malformed multicodec: expected Ed25519 [0xED, 0x01]")]
    UnsupportedMulticodec,

    #[error("Invalid Ed25519 key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// Decode a `did:key:z...` string into a 32-byte Ed25519 public key.
///
/// Args:
/// * `did`: A DID string in `did:key:z<base58btc>` format.
///
/// Usage:
/// ```ignore
/// let pk: [u8; 32] = did_key_to_ed25519("did:key:z6Mkf...")?;
/// ```
pub fn did_key_to_ed25519(did: &str) -> Result<[u8; 32], DidKeyError> {
    let encoded = strip_did_key_prefix(did)?;
    let decoded = decode_base58(encoded)?;
    validate_multicodec_and_extract(&decoded)
}

/// Encode a 32-byte Ed25519 public key as a `did:key:z...` string.
///
/// Args:
/// * `public_key`: A 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let did = ed25519_pubkey_to_did_key(&key_bytes);
/// assert!(did.starts_with("did:key:z"));
/// ```
pub fn ed25519_pubkey_to_did_key(public_key: &[u8; 32]) -> String {
    let mut prefixed = vec![0xED, 0x01];
    prefixed.extend_from_slice(public_key);
    let encoded = bs58::encode(prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// Encode a raw public key as a `did:keri:` string (base58-encoded).
///
/// Args:
/// * `pk`: Raw public key bytes.
pub fn ed25519_pubkey_to_did_keri(pk: &[u8]) -> String {
    format!("did:keri:{}", bs58::encode(pk).into_string())
}

fn strip_did_key_prefix(did: &str) -> Result<&str, DidKeyError> {
    did.strip_prefix("did:key:z")
        .ok_or_else(|| DidKeyError::InvalidPrefix(did.to_string()))
}

fn decode_base58(encoded: &str) -> Result<Vec<u8>, DidKeyError> {
    bs58::decode(encoded)
        .into_vec()
        .map_err(|e| DidKeyError::Base58DecodeFailed(e.to_string()))
}

fn validate_multicodec_and_extract(decoded: &[u8]) -> Result<[u8; 32], DidKeyError> {
    if decoded.len() != 34
        || decoded[0] != ED25519_MULTICODEC[0]
        || decoded[1] != ED25519_MULTICODEC[1]
    {
        if decoded.len() != 34 {
            return Err(DidKeyError::InvalidKeyLength(
                decoded.len().saturating_sub(2),
            ));
        }
        return Err(DidKeyError::UnsupportedMulticodec);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encode_decode() {
        let original = [42u8; 32];
        let did = ed25519_pubkey_to_did_key(&original);
        assert!(did.starts_with("did:key:z"));
        let decoded = did_key_to_ed25519(&did).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_invalid_prefix() {
        let err = did_key_to_ed25519("did:web:example.com").unwrap_err();
        assert!(matches!(err, DidKeyError::InvalidPrefix(_)));
    }

    #[test]
    fn rejects_invalid_base58() {
        let err = did_key_to_ed25519("did:key:z0OOO").unwrap_err();
        assert!(matches!(err, DidKeyError::Base58DecodeFailed(_)));
    }
}
