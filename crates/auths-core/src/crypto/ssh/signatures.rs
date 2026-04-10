//! SSHSIG signature creation and PEM encoding.

use sha2::{Digest, Sha512};
use ssh_key::private::{Ed25519Keypair as SshEd25519Keypair, KeypairData};
use ssh_key::{HashAlg, LineEnding, PrivateKey as SshPrivateKey, SshSig};

use super::CryptoError;
use super::SecureSeed;
use super::encoding::{encode_ssh_pubkey, encode_ssh_signature};

/// Create an SSHSIG signature and return it as a PEM-armored string.
///
/// Uses the `ssh-key` crate to produce a standard SSHSIG signature from
/// an Ed25519 seed and arbitrary data, suitable for Git commit signing.
///
/// Args:
/// * `seed`: The Ed25519 private key seed.
/// * `data`: The raw bytes to sign.
/// * `namespace`: The SSHSIG namespace (e.g., "git").
///
/// Usage:
/// ```ignore
/// let pem = create_sshsig(&seed, b"commit data", "git")?;
/// assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
/// ```
pub fn create_sshsig(
    seed: &SecureSeed,
    data: &[u8],
    namespace: &str,
) -> Result<String, CryptoError> {
    // Detect curve from the stored key context.
    // For now, try Ed25519 first (most common), then P-256.
    // TODO: pass CurveType explicitly once the full signing path is curve-aware.
    if let Ok(pem) = create_sshsig_ed25519(seed, data, namespace) {
        return Ok(pem);
    }
    create_sshsig_p256(seed, data, namespace)
}

fn create_sshsig_ed25519(
    seed: &SecureSeed,
    data: &[u8],
    namespace: &str,
) -> Result<String, CryptoError> {
    let ssh_keypair = SshEd25519Keypair::from_seed(seed.as_bytes());
    let keypair_data = KeypairData::Ed25519(ssh_keypair);
    let private_key = SshPrivateKey::new(keypair_data, "auths-sign")
        .map_err(|e| CryptoError::SshKeyConstruction(e.to_string()))?;

    let sshsig = SshSig::sign(&private_key, namespace, HashAlg::Sha512, data)
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

    sshsig
        .to_pem(LineEnding::LF)
        .map_err(|e| CryptoError::PemEncoding(e.to_string()))
}

fn create_sshsig_p256(
    seed: &SecureSeed,
    data: &[u8],
    namespace: &str,
) -> Result<String, CryptoError> {
    use ssh_key::private::EcdsaKeypair;

    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret_key = p256::SecretKey::from_slice(seed.as_bytes())
        .map_err(|e| CryptoError::SigningFailed(format!("P-256 seed: {e}")))?;
    let public_key = secret_key.public_key();

    let ecdsa_keypair = EcdsaKeypair::NistP256 {
        public: public_key.to_encoded_point(false), // uncompressed
        private: ssh_key::private::EcdsaPrivateKey::from(secret_key),
    };

    let keypair_data = KeypairData::Ecdsa(ecdsa_keypair);
    let private_key = SshPrivateKey::new(keypair_data, "auths-sign")
        .map_err(|e| CryptoError::SshKeyConstruction(e.to_string()))?;

    let sshsig = SshSig::sign(&private_key, namespace, HashAlg::Sha256, data)
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

    sshsig
        .to_pem(LineEnding::LF)
        .map_err(|e| CryptoError::PemEncoding(e.to_string()))
}

/// Construct the data blob that SSHSIG signs (the "message to sign").
///
/// Format per OpenSSH sshsig.c:
///   literal "SSHSIG"   -- 6 raw bytes, NO length prefix
///   string  namespace  -- 4-byte length + data
///   string  reserved   -- 4-byte length + data (empty)
///   string  hash_alg   -- 4-byte length + data ("sha512")
///   string  H(message) -- 4-byte length + sha512(message)
///
/// Args:
/// * `data`: The raw message bytes to hash.
/// * `namespace`: The SSHSIG namespace (e.g., "git").
///
/// Usage:
/// ```ignore
/// let blob = construct_sshsig_signed_data(b"commit data", "git")?;
/// let sig = agent_sign(&socket, &pubkey, &blob)?;
/// ```
pub fn construct_sshsig_signed_data(data: &[u8], namespace: &str) -> Result<Vec<u8>, CryptoError> {
    let mut blob = Vec::new();

    // Magic preamble: 6 raw bytes, NOT a length-prefixed SSH string.
    blob.extend_from_slice(b"SSHSIG");

    blob.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    blob.extend_from_slice(namespace.as_bytes());

    // Reserved (empty)
    blob.extend_from_slice(&0u32.to_be_bytes());

    let hash_algo = b"sha512";
    blob.extend_from_slice(&(hash_algo.len() as u32).to_be_bytes());
    blob.extend_from_slice(hash_algo);

    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash = hasher.finalize();
    blob.extend_from_slice(&(hash.len() as u32).to_be_bytes());
    blob.extend_from_slice(&hash);

    Ok(blob)
}

/// Construct the final SSHSIG PEM from a public key, curve, and raw signature.
///
/// Builds the full SSHSIG binary structure (magic, version, pubkey,
/// namespace, signature) and encodes it as base64-wrapped PEM.
///
/// Args:
/// * `pubkey`: Raw public key bytes.
/// * `signature`: Raw signature bytes.
/// * `namespace`: The SSHSIG namespace (e.g., "git").
/// * `curve`: The curve type of the key/signature.
///
/// Usage:
/// ```ignore
/// let sig_data = construct_sshsig_signed_data(data, "git")?;
/// let raw_sig = agent_sign(&socket, &pubkey, &sig_data)?;
/// let pem = construct_sshsig_pem(&pubkey, &raw_sig, "git", CurveType::Ed25519)?;
/// ```
pub fn construct_sshsig_pem(
    pubkey: &[u8],
    signature: &[u8],
    namespace: &str,
    curve: auths_crypto::CurveType,
) -> Result<String, CryptoError> {
    let mut blob = Vec::new();

    blob.extend_from_slice(b"SSHSIG");

    // Version
    blob.extend_from_slice(&1u32.to_be_bytes());

    // Public key blob (SSH wire format)
    let pubkey_blob = encode_ssh_pubkey(pubkey, curve);
    blob.extend_from_slice(&(pubkey_blob.len() as u32).to_be_bytes());
    blob.extend_from_slice(&pubkey_blob);

    // Namespace
    blob.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    blob.extend_from_slice(namespace.as_bytes());

    // Reserved (empty)
    blob.extend_from_slice(&0u32.to_be_bytes());

    // Hash algorithm
    let hash_algo = b"sha512";
    blob.extend_from_slice(&(hash_algo.len() as u32).to_be_bytes());
    blob.extend_from_slice(hash_algo);

    // Signature blob (SSH signature format)
    let sig_blob = encode_ssh_signature(signature, curve);
    blob.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes());
    blob.extend_from_slice(&sig_blob);

    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);

    let wrapped: String = b64
        .chars()
        .collect::<Vec<_>>()
        .chunks(70)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        wrapped
    ))
}
