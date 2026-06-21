//! Request/response types and validation for RFC 7591 dynamic client registration.

use serde::{Deserialize, Deserializer, Serialize};

use super::client::{GrantType, ResponseType, TokenEndpointAuthMethod};

/// A decoded Ed25519 root public key.
///
/// Deserialized from a hex-encoded string — invalid hex is rejected at the
/// API boundary so downstream code never needs to re-decode.
#[derive(Debug, Clone)]
pub struct RootPublicKey(Vec<u8>);

impl RootPublicKey {
    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RootPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str)
            .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32-byte Ed25519 key, got {} bytes",
                bytes.len()
            )));
        }
        Ok(RootPublicKey(bytes))
    }
}

/// KERI capability receipt submitted as the initial access token.
#[derive(Debug, Clone, Deserialize)]
pub struct KeriCapabilityReceipt {
    /// The attestation chain proving identity and capability delegation.
    pub attestation_chain: Vec<auths_verifier::core::Attestation>,
    /// Ed25519 root public key (hex-decoded at deserialization time).
    pub root_public_key: RootPublicKey,
}

/// RFC 7591 client registration request body.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<GrantType>>,
    pub response_types: Option<Vec<ResponseType>>,
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub jwks: Option<serde_json::Value>,
    pub keri_capability_receipt: KeriCapabilityReceipt,
}

/// RFC 7591 client registration response body.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub response_types: Vec<ResponseType>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub registration_access_token: String,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: i64,
}

/// Errors from validating a registration request.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationValidationError {
    #[error("redirect_uris must not be empty")]
    EmptyRedirectUris,

    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    #[error("redirect URI must use HTTPS: {0}")]
    NonHttpsRedirectUri(String),

    #[error("jwks is required when token_endpoint_auth_method is private_key_jwt")]
    MissingJwks,

    #[error("invalid root public key: {0}")]
    InvalidRootPublicKey(String),
}

/// Validates a registration request and returns normalized grant/response types.
///
/// Args:
/// * `req`: The registration request to validate.
/// * `allow_http_redirects`: If true, allow HTTP redirect URIs (for development).
///
/// Usage:
/// ```ignore
/// let (grant_types, response_types, auth_method) = validate_registration_request(&req, false)?;
/// ```
pub fn validate_registration_request(
    req: &RegistrationRequest,
    allow_http_redirects: bool,
) -> Result<(Vec<GrantType>, Vec<ResponseType>, TokenEndpointAuthMethod), RegistrationValidationError>
{
    // redirect_uris must be non-empty
    if req.redirect_uris.is_empty() {
        return Err(RegistrationValidationError::EmptyRedirectUris);
    }

    // Validate each redirect URI
    for uri in &req.redirect_uris {
        let parsed = reqwest::Url::parse(uri)
            .map_err(|_| RegistrationValidationError::InvalidRedirectUri(uri.clone()))?;

        if !allow_http_redirects && parsed.scheme() != "https" {
            return Err(RegistrationValidationError::NonHttpsRedirectUri(
                uri.clone(),
            ));
        }
    }

    // Defaults per RFC 7591
    let grant_types = req
        .grant_types
        .clone()
        .unwrap_or_else(|| vec![GrantType::AuthorizationCode]);
    let response_types = req
        .response_types
        .clone()
        .unwrap_or_else(|| vec![ResponseType::Code]);
    let auth_method = req.token_endpoint_auth_method.clone().unwrap_or_default();

    // If private_key_jwt, jwks must be present
    if auth_method == TokenEndpointAuthMethod::PrivateKeyJwt && req.jwks.is_none() {
        return Err(RegistrationValidationError::MissingJwks);
    }

    // root_public_key is already validated at deserialization time via RootPublicKey.

    Ok((grant_types, response_types, auth_method))
}
