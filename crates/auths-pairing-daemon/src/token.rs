#[cfg(feature = "server")]
use axum::http::HeaderMap;
#[cfg(feature = "server")]
use base64::Engine;
#[cfg(feature = "server")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "server")]
use subtle::ConstantTimeEq;

#[cfg(feature = "server")]
use crate::DaemonError;

/// Validate a pairing token from an HTTP request header.
///
/// Extracts the `X-Pairing-Token` header, base64url-decodes it, and
/// compares it against the expected token bytes.
///
/// Args:
/// * `headers`: HTTP headers from the incoming request.
/// * `expected`: The raw token bytes to compare against.
///
/// Usage:
/// ```ignore
/// if !validate_pairing_token(&headers, state.pairing_token()) {
///     return Err(StatusCode::UNAUTHORIZED);
/// }
/// ```
#[cfg(feature = "server")]
pub fn validate_pairing_token(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers.get("X-Pairing-Token") else {
        return false;
    };
    let Ok(provided) = URL_SAFE_NO_PAD.decode(value.as_bytes()) else {
        return false;
    };
    // Constant-time comparison prevents timing attacks that could leak token bytes
    provided.ct_eq(expected).into()
}

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
