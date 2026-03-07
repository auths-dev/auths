//! SSH key parsing, seed extraction, and public key derivation.

pub use auths_crypto::SecureSeed;
use auths_crypto::{Pkcs8Der, build_ed25519_pkcs8_v2, parse_ed25519_key_material};
use ssh_key::private::Ed25519Keypair as SshEd25519Keypair;

use super::CryptoError;

/// Extract an Ed25519 seed from PKCS#8 key bytes.
///
/// Delegates to `auths_crypto::parse_ed25519_seed` and wraps the result
/// in the SSH-specific `CryptoError`.
///
/// Args:
/// * `pkcs8`: PKCS#8 encoded key material (v1 or v2).
///
/// Usage:
/// ```ignore
/// let seed = extract_seed_from_pkcs8(&pkcs8)?;
/// let sshsig = create_sshsig(&seed, data, "git")?;
/// ```
pub fn extract_seed_from_pkcs8(pkcs8: &Pkcs8Der) -> Result<SecureSeed, CryptoError> {
    auths_crypto::parse_ed25519_seed(pkcs8.as_ref()).map_err(CryptoError::from)
}

/// Build a PKCS#8 v2 DER document from a seed, deriving the public key internally.
///
/// Args:
/// * `seed`: The 32-byte Ed25519 seed.
///
/// Usage:
/// ```ignore
/// let pkcs8 = build_ed25519_pkcs8_v2_from_seed(&seed)?;
/// ```
pub fn build_ed25519_pkcs8_v2_from_seed(seed: &SecureSeed) -> Result<Pkcs8Der, CryptoError> {
    let ssh_kp = SshEd25519Keypair::from_seed(seed.as_bytes());
    let pubkey: [u8; 32] = ssh_kp.public.0;
    let pkcs8 = build_ed25519_pkcs8_v2(seed.as_bytes(), &pubkey);
    Ok(Pkcs8Der::new(pkcs8))
}

/// Extract the 32-byte Ed25519 public key from key bytes.
///
/// Parses key material to find the embedded public key (PKCS#8 v2), or
/// derives it from the seed when only PKCS#8 v1 or raw bytes are provided.
///
/// Args:
/// * `key_bytes`: Key material in any supported PKCS#8 or raw format.
///
/// Usage:
/// ```ignore
/// let pubkey = extract_pubkey_from_key_bytes(pkcs8.as_ref())?;
/// ```
pub fn extract_pubkey_from_key_bytes(key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (seed, maybe_pubkey) = parse_ed25519_key_material(key_bytes).map_err(CryptoError::from)?;

    match maybe_pubkey {
        Some(pk) => Ok(pk.to_vec()),
        None => {
            let ssh_kp = SshEd25519Keypair::from_seed(seed.as_bytes());
            Ok(ssh_kp.public.0.to_vec())
        }
    }
}
