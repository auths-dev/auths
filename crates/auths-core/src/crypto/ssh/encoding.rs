//! SSH wire-format encoding for public keys and signatures.
//!
//! Supports both Ed25519 and ECDSA P-256 key types. Key type is detected
//! from the public key length; signature encoding requires an explicit
//! curve parameter since both curves produce 64-byte raw signatures.

use auths_crypto::CurveType;

/// Encode a public key in SSH wire format.
///
/// Args:
/// * `pubkey`: Raw public key bytes.
/// * `curve`: Which curve this key belongs to.
///
/// Usage:
/// ```
/// use auths_core::crypto::ssh::encode_ssh_pubkey;
/// use auths_crypto::CurveType;
/// let blob = encode_ssh_pubkey(&[0x42u8; 32], CurveType::Ed25519);
/// assert_eq!(&blob[4..15], b"ssh-ed25519");
/// ```
pub fn encode_ssh_pubkey(pubkey: &[u8], curve: CurveType) -> Vec<u8> {
    match curve {
        CurveType::Ed25519 => encode_ssh_pubkey_ed25519(pubkey),
        CurveType::P256 => encode_ssh_pubkey_ecdsa_p256(pubkey),
    }
}

/// Encode a raw signature in SSH wire format.
///
/// Args:
/// * `signature`: Raw signature bytes (64 for both Ed25519 and P-256 r||s).
/// * `curve`: Which curve produced the signature.
///
/// Usage:
/// ```
/// use auths_core::crypto::ssh::encode_ssh_signature;
/// use auths_crypto::CurveType;
/// let blob = encode_ssh_signature(&[0xAB; 64], CurveType::Ed25519);
/// assert_eq!(&blob[4..15], b"ssh-ed25519");
/// ```
pub fn encode_ssh_signature(signature: &[u8], curve: CurveType) -> Vec<u8> {
    match curve {
        CurveType::Ed25519 => encode_ssh_sig_ed25519(signature),
        CurveType::P256 => encode_ssh_sig_ecdsa_p256(signature),
    }
}

fn encode_ssh_pubkey_ed25519(pubkey: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    let key_type = b"ssh-ed25519";
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);
    blob.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
    blob.extend_from_slice(pubkey);
    blob
}

fn encode_ssh_pubkey_ecdsa_p256(pubkey: &[u8]) -> Vec<u8> {
    let uncompressed = if pubkey.len() == 33 {
        decompress_p256(pubkey)
    } else {
        pubkey.to_vec()
    };

    let mut blob = Vec::new();
    let key_type = b"ecdsa-sha2-nistp256";
    let curve_name = b"nistp256";
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);
    blob.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(curve_name);
    blob.extend_from_slice(&(uncompressed.len() as u32).to_be_bytes());
    blob.extend_from_slice(&uncompressed);
    blob
}

fn decompress_p256(compressed: &[u8]) -> Vec<u8> {
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    match PublicKey::from_sec1_bytes(compressed) {
        Ok(pk) => {
            let point = pk.to_encoded_point(false);
            point.as_bytes().to_vec()
        }
        Err(_) => compressed.to_vec(),
    }
}

fn encode_ssh_sig_ed25519(signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    let sig_type = b"ssh-ed25519";
    blob.extend_from_slice(&(sig_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig_type);
    blob.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    blob.extend_from_slice(signature);
    blob
}

fn encode_ssh_sig_ecdsa_p256(signature: &[u8]) -> Vec<u8> {
    let r = &signature[..32];
    let s = &signature[32..];

    let mut inner = Vec::new();
    inner.extend_from_slice(&encode_mpint(r));
    inner.extend_from_slice(&encode_mpint(s));

    let mut blob = Vec::new();
    let sig_type = b"ecdsa-sha2-nistp256";
    blob.extend_from_slice(&(sig_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig_type);
    blob.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    blob.extend_from_slice(&inner);
    blob
}

fn encode_mpint(bytes: &[u8]) -> Vec<u8> {
    let trimmed = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &bytes[bytes.len() - 1..],
    };

    let mut buf = Vec::new();
    if trimmed[0] & 0x80 != 0 {
        buf.extend_from_slice(&((trimmed.len() + 1) as u32).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(trimmed);
    } else {
        buf.extend_from_slice(&(trimmed.len() as u32).to_be_bytes());
        buf.extend_from_slice(trimmed);
    }
    buf
}

/// Encode a big integer for the SSH agent `add_identity` wire format.
///
/// Args:
/// * `bytes`: Big-endian integer bytes (leading zeros are stripped).
///
/// Usage:
/// ```
/// use auths_core::crypto::ssh::encode_mpint_for_agent;
/// let encoded = encode_mpint_for_agent(&[0x00, 0x01, 0x02]);
/// assert_eq!(&encoded[..4], &2u32.to_be_bytes());
/// ```
pub fn encode_mpint_for_agent(bytes: &[u8]) -> Vec<u8> {
    encode_mpint(bytes)
}
