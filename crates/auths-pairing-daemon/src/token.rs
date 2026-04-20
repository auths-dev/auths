#[cfg(feature = "server")]
use base64::Engine;
#[cfg(feature = "server")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "server")]
use crate::DaemonError;

/// Generate a cryptographically random transport token.
///
/// Returns the raw 16-byte token and its base64url-encoded string representation.
/// Uses `ring::rand::SystemRandom` for cryptographic randomness.
///
/// Usage:
/// ```ignore
/// let (raw_bytes, b64_token) = generate_transport_token()?;
/// let state = DaemonState::new(session, raw_bytes, tx);
/// // Include b64_token in QR code URL
/// ```
#[cfg(feature = "server")]
pub fn generate_transport_token() -> Result<(Vec<u8>, String), DaemonError> {
    let mut token_bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token_bytes)
        .map_err(|_| DaemonError::TokenGenerationFailed)?;
    let b64 = URL_SAFE_NO_PAD.encode(token_bytes);
    Ok((token_bytes.to_vec(), b64))
}
