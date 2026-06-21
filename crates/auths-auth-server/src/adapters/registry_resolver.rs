//! Identity resolver that fetches keys from the registry server over HTTP.

use async_trait::async_trait;
use serde::Deserialize;

use crate::ports::{IdentityResolver, ResolveError};

/// Resolves identity public keys by calling the registry server HTTP API.
pub struct RegistryIdentityResolver {
    client: reqwest::Client,
    registry_url: String,
}

/// Response shape from `GET /v1/identities/:did`.
///
/// Matches the current registry API which returns an object with `status`,
/// `public_keys`, etc. — not the old `key_state.current_keys` shape.
#[derive(Debug, Deserialize)]
struct IdentityResponse {
    status: String,
    #[serde(default)]
    public_keys: Vec<PublicKeyEntry>,
}

#[derive(Debug, Deserialize)]
struct PublicKeyEntry {
    public_key_hex: String,
}

impl RegistryIdentityResolver {
    pub fn new(registry_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            registry_url: registry_url.into(),
        }
    }
}

#[async_trait]
impl IdentityResolver for RegistryIdentityResolver {
    async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
        if !did.starts_with("did:keri:") {
            return Err(ResolveError::InvalidKel(format!(
                "not a did:keri DID: {did}"
            )));
        }

        let url = format!("{}/v1/identities/{}", self.registry_url, did);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ResolveError::RegistryUnavailable(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ResolveError::NotFound(format!("identity not found: {did}")));
        }

        if !resp.status().is_success() {
            return Err(ResolveError::RegistryUnavailable(format!(
                "registry returned status {}",
                resp.status()
            )));
        }

        let identity: IdentityResponse = resp
            .json()
            .await
            .map_err(|e| ResolveError::InvalidKel(format!("failed to parse response: {e}")))?;

        if identity.status != "active" {
            return Err(ResolveError::NotFound(format!(
                "identity is not active (status: {})",
                identity.status
            )));
        }

        let first_key = identity
            .public_keys
            .first()
            .ok_or_else(|| ResolveError::InvalidKel("no public keys for identity".to_string()))?;

        let key = auths_verifier::PublicKeyHex::parse(&first_key.public_key_hex)
            .map_err(|e| ResolveError::InvalidKel(format!("KERI key decode failed: {e}")))?;
        let bytes = hex::decode(key.as_str())
            .map_err(|e| ResolveError::InvalidKel(format!("KERI key hex decode failed: {e}")))?;

        Ok(bytes)
    }
}
