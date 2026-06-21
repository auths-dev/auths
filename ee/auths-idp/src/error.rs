//! IdP verification errors.

use thiserror::Error;

/// Errors produced during IdP verification and JWKS operations.
///
/// Args:
/// * `TokenInvalid`: The IdP token failed signature or claims validation.
/// * `JwksFetchFailed`: JWKS key fetch failed (network or parse error).
/// * `ProviderConfig`: The IdP provider is misconfigured.
/// * `UnsupportedProtocol`: The IdP protocol is not supported.
///
/// Usage:
/// ```ignore
/// match idp_verifier.verify(token, now).await {
///     Err(IdpError::TokenInvalid(msg)) => eprintln!("bad token: {msg}"),
///     Err(IdpError::JwksFetchFailed(msg)) => eprintln!("JWKS error: {msg}"),
///     _ => {}
/// }
/// ```
#[derive(Debug, Error)]
pub enum IdpError {
    #[error("token invalid: {0}")]
    TokenInvalid(String),

    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    #[error("provider misconfigured: {0}")]
    ProviderConfig(String),

    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}

pub type IdpResult<T> = Result<T, IdpError>;
