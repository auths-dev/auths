#[cfg(feature = "server")]
use axum::http::HeaderMap;
#[cfg(feature = "server")]
use base64::Engine;
#[cfg(feature = "server")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "server")]
use subtle::ConstantTimeEq;

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
