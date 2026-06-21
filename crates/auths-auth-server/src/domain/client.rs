//! Domain types for dynamically registered OIDC clients (RFC 7591).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A dynamically registered OIDC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: Option<String>,
    /// KERI Autonomic Identifier that registered this client.
    pub keri_aid: String,
    /// Argon2 hash of the client secret (None for `private_key_jwt`).
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub response_types: Vec<ResponseType>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Hashed registration access token for future self-management (RFC 7592).
    pub registration_access_token_hash: String,
    /// JWKS for `private_key_jwt` clients.
    pub jwks: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// OAuth 2.0 grant types supported by dynamically registered clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "refresh_token")]
    RefreshToken,
    #[serde(rename = "client_credentials")]
    ClientCredentials,
}

/// OAuth 2.0 response types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "code")]
    Code,
}

/// Token endpoint authentication methods (RFC 7591 Section 2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenEndpointAuthMethod {
    #[serde(rename = "client_secret_basic")]
    #[default]
    ClientSecretBasic,
    #[serde(rename = "client_secret_post")]
    ClientSecretPost,
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt,
    #[serde(rename = "none")]
    None,
}

// Display and FromStr are derived from the serde rename values so the
// strings stay consistent without manual duplication.
macro_rules! impl_display_fromstr_via_serde {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // serde_json serializes to `"value"` — strip the quotes.
                let json = serde_json::to_value(self).map_err(|_| fmt::Error)?;
                f.write_str(json.as_str().ok_or(fmt::Error)?)
            }
        }

        impl FromStr for $ty {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let quoted = format!("\"{s}\"");
                serde_json::from_str(&quoted)
                    .map_err(|_| format!("unknown {}: {s}", stringify!($ty)))
            }
        }
    };
}

impl_display_fromstr_via_serde!(GrantType);
impl_display_fromstr_via_serde!(ResponseType);
impl_display_fromstr_via_serde!(TokenEndpointAuthMethod);
