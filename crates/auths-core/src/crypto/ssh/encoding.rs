//! SSH wire-format encoding for Ed25519 public keys and signatures.

/// Encode an Ed25519 public key in SSH wire format.
///
/// Produces a byte blob with the key type string ("ssh-ed25519") followed
/// by the raw public key, both length-prefixed as SSH strings.
///
/// Args:
/// * `pubkey`: Raw 32-byte Ed25519 public key.
///
/// Usage:
/// ```
/// use auths_core::crypto::ssh::encode_ssh_pubkey;
/// let blob = encode_ssh_pubkey(&[0x42u8; 32]);
/// assert_eq!(&blob[4..15], b"ssh-ed25519");
/// ```
pub fn encode_ssh_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    let key_type = b"ssh-ed25519";
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);
    blob.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
    blob.extend_from_slice(pubkey);
    blob
}

/// Encode a raw Ed25519 signature in SSH signature wire format.
///
/// Produces a byte blob with the signature type string ("ssh-ed25519")
/// followed by the raw signature bytes, both length-prefixed as SSH strings.
///
/// Args:
/// * `signature`: Raw Ed25519 signature bytes.
///
/// Usage:
/// ```
/// use auths_core::crypto::ssh::encode_ssh_signature;
/// let blob = encode_ssh_signature(&[0xAB; 64]);
/// assert_eq!(&blob[4..15], b"ssh-ed25519");
/// ```
pub fn encode_ssh_signature(signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    let sig_type = b"ssh-ed25519";
    blob.extend_from_slice(&(sig_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig_type);
    blob.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    blob.extend_from_slice(signature);
    blob
}
