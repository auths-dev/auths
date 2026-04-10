//! DID:key encoding and decoding for Ed25519 and P-256 public keys.
//!
//! Centralizes all `did:key` ↔ public key byte conversions in one place.
//! The `did:key` method encodes a public key directly in the DID string
//! using multicodec + base58btc, per the [did:key spec](https://w3c-ccg.github.io/did-method-key/).

/// Ed25519 multicodec prefix (varint-encoded `0xED`).
const ED25519_MULTICODEC: [u8; 2] = [0xED, 0x01];

/// P-256 (secp256r1) compressed multicodec prefix (varint-encoded `0x1200`).
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// Errors from parsing or encoding `did:key` strings.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidKeyError {
    #[error("DID must start with 'did:key:z', got: {0}")]
    InvalidPrefix(String),

    #[error("Base58 decoding failed: {0}")]
    Base58DecodeFailed(String),

    #[error("Unsupported multicodec: expected Ed25519 [0xED, 0x01] or P-256 [0x80, 0x24]")]
    UnsupportedMulticodec,

    #[error("Invalid key length: got {0} bytes")]
    InvalidKeyLength(usize),
}

impl crate::AuthsErrorInfo for DidKeyError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidPrefix(_) => "AUTHS-E1101",
            Self::Base58DecodeFailed(_) => "AUTHS-E1102",
            Self::UnsupportedMulticodec => "AUTHS-E1103",
            Self::InvalidKeyLength(_) => "AUTHS-E1104",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidPrefix(_) => Some("DID must start with 'did:key:z'"),
            Self::UnsupportedMulticodec => Some("Supported key types: Ed25519, P-256 (secp256r1)"),
            _ => None,
        }
    }
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

/// Encode a 33-byte compressed P-256 public key as a `did:key:z...` string.
///
/// Args:
/// * `public_key`: A 33-byte SEC1 compressed P-256 public key.
///
/// Usage:
/// ```ignore
/// let did = p256_pubkey_to_did_key(&compressed_key);
/// assert!(did.starts_with("did:key:z"));
/// ```
pub fn p256_pubkey_to_did_key(public_key: &[u8]) -> String {
    let mut prefixed = vec![P256_MULTICODEC[0], P256_MULTICODEC[1]];
    prefixed.extend_from_slice(public_key);
    let encoded = bs58::encode(prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// Decode a `did:key:z...` string to a 33-byte compressed P-256 public key.
///
/// Args:
/// * `did`: A DID string in `did:key:z<base58btc>` format with P-256 multicodec.
///
/// Usage:
/// ```ignore
/// let pk: Vec<u8> = did_key_to_p256("did:key:zDn...")?;
/// assert_eq!(pk.len(), 33);
/// ```
pub fn did_key_to_p256(did: &str) -> Result<Vec<u8>, DidKeyError> {
    let encoded = strip_did_key_prefix(did)?;
    let decoded = decode_base58(encoded)?;
    if decoded.len() < 2 {
        return Err(DidKeyError::InvalidKeyLength(decoded.len()));
    }
    if decoded[0] != P256_MULTICODEC[0] || decoded[1] != P256_MULTICODEC[1] {
        return Err(DidKeyError::UnsupportedMulticodec);
    }
    let key = decoded[2..].to_vec();
    if key.len() != 33 {
        return Err(DidKeyError::InvalidKeyLength(key.len()));
    }
    Ok(key)
}

/// Decoded public key from a `did:key` string, with curve identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedDidKey {
    /// Ed25519 public key (32 bytes).
    Ed25519([u8; 32]),
    /// P-256 compressed public key (33 bytes).
    P256(Vec<u8>),
}

/// Decode a `did:key:z...` string, auto-detecting the curve from the multicodec.
///
/// Usage:
/// ```ignore
/// match did_key_decode("did:key:z...")? {
///     DecodedDidKey::Ed25519(pk) => { /* 32 bytes */ }
///     DecodedDidKey::P256(pk) => { /* 33 bytes */ }
/// }
/// ```
pub fn did_key_decode(did: &str) -> Result<DecodedDidKey, DidKeyError> {
    let encoded = strip_did_key_prefix(did)?;
    let decoded = decode_base58(encoded)?;
    if decoded.len() < 2 {
        return Err(DidKeyError::InvalidKeyLength(decoded.len()));
    }
    if decoded[0] == ED25519_MULTICODEC[0] && decoded[1] == ED25519_MULTICODEC[1] {
        let key = validate_multicodec_and_extract(&decoded)?;
        Ok(DecodedDidKey::Ed25519(key))
    } else if decoded[0] == P256_MULTICODEC[0] && decoded[1] == P256_MULTICODEC[1] {
        let key = decoded[2..].to_vec();
        if key.len() != 33 {
            return Err(DidKeyError::InvalidKeyLength(key.len()));
        }
        Ok(DecodedDidKey::P256(key))
    } else {
        Err(DidKeyError::UnsupportedMulticodec)
    }
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
