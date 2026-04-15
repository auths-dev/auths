use auths_core::ports::network::{IdentityResolver, ResolutionError, ResolvedIdentity};
use auths_verifier::core::Ed25519PublicKey;
use serde::Deserialize;
use std::future::Future;

use crate::default_http_client;
use crate::request::{build_get_request, execute_request, parse_response_json};

#[derive(Debug, Deserialize)]
struct ResolvedIdentityResponse {
    did: String,
    public_key: Vec<u8>,
    method: String,
    #[serde(default)]
    sequence: u128,
    #[serde(default)]
    can_rotate: bool,
}

/// HTTP-backed implementation of `IdentityResolver`.
///
/// Calls a remote registry endpoint to resolve DIDs to their current
/// cryptographic material.
///
/// Usage:
/// ```ignore
/// use auths_infra_http::HttpIdentityResolver;
///
/// let resolver = HttpIdentityResolver::new("https://registry.example.com");
/// let identity = resolver.resolve_identity("did:keri:EAbcdef...").await?;
/// ```
pub struct HttpIdentityResolver {
    base_url: String,
    client: reqwest::Client,
}

impl HttpIdentityResolver {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: default_http_client(),
        }
    }
}

impl IdentityResolver for HttpIdentityResolver {
    fn resolve_identity(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<ResolvedIdentity, ResolutionError>> + Send {
        let url = format!("{}/resolve/{}", self.base_url, did);
        let request = build_get_request(&self.client, &url);
        let did_owned = did.to_string();

        async move {
            let response = execute_request(request, &url)
                .await
                .map_err(ResolutionError::Network)?;

            let status = response.status().as_u16();
            if status == 404 {
                return Err(ResolutionError::DidNotFound { did: did_owned });
            }

            let parsed: ResolvedIdentityResponse = parse_response_json(response, &did_owned)
                .await
                .map_err(ResolutionError::Network)?;

            let public_key = Ed25519PublicKey::try_from_slice(&parsed.public_key).map_err(|e| {
                ResolutionError::InvalidDid {
                    did: parsed.did.clone(),
                    reason: format!("invalid public key: {e}"),
                }
            })?;

            match parsed.method.as_str() {
                "key" => Ok(ResolvedIdentity::Key {
                    did: parsed.did,
                    public_key,
                }),
                "keri" => Ok(ResolvedIdentity::Keri {
                    did: parsed.did,
                    public_key,
                    sequence: parsed.sequence,
                    can_rotate: parsed.can_rotate,
                }),
                other => Err(ResolutionError::InvalidDid {
                    did: did_owned,
                    reason: format!("unsupported method: {other}"),
                }),
            }
        }
    }
}
