use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use auths_core::ports::network::NetworkError;
use auths_id::keri::Prefix;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;

use crate::error::RegistrationError;
use crate::result::RegistrationOutcome;

/// Default registry URL used when no explicit registry endpoint is configured.
pub const DEFAULT_REGISTRY_URL: &str = "https://auths-registry.fly.dev";

#[derive(Serialize)]
struct RegistryOnboardingPayload {
    inception_event: serde_json::Value,
    attestations: Vec<serde_json::Value>,
    proof_url: Option<String>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    did_prefix: String,
    platform_claims_indexed: usize,
}

/// Registers a local identity with a remote registry for public discovery.
///
/// Args:
/// * `identity_storage`: Storage adapter for loading the local identity.
/// * `registry`: Registry backend for reading KEL events.
/// * `attestation_source`: Source for loading local attestations.
/// * `registry_url`: Base URL of the target registry.
/// * `proof_url`: Optional URL to a platform proof (e.g., GitHub gist).
///
/// Usage:
/// ```ignore
/// let outcome = register_identity(
///     identity_storage, registry, attestation_source,
///     "https://auths-registry.fly.dev", None,
/// ).await?;
/// ```
pub async fn register_identity(
    identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    registry: Arc<dyn RegistryBackend + Send + Sync>,
    attestation_source: Arc<dyn AttestationSource + Send + Sync>,
    registry_url: &str,
    proof_url: Option<String>,
) -> Result<RegistrationOutcome, RegistrationError> {
    let identity = identity_storage
        .load_identity()
        .map_err(|e| RegistrationError::LocalDataError(e.to_string()))?;

    let did_prefix = identity
        .controller_did
        .as_str()
        .strip_prefix("did:keri:")
        .ok_or_else(|| {
            RegistrationError::LocalDataError(format!(
                "Invalid DID format, expected 'did:keri:': {}",
                identity.controller_did
            ))
        })?;

    let prefix = Prefix::new_unchecked(did_prefix.to_string());
    let inception = registry.get_event(&prefix, 0).map_err(|_| {
        RegistrationError::LocalDataError(
            "No KEL events found for identity. The identity may be corrupted.".to_string(),
        )
    })?;
    let inception_event = serde_json::to_value(&inception)
        .map_err(|e| RegistrationError::LocalDataError(e.to_string()))?;

    let attestations = attestation_source
        .load_all_attestations()
        .unwrap_or_default();
    let attestation_values: Vec<serde_json::Value> = attestations
        .iter()
        .filter_map(|a| serde_json::to_value(a).ok())
        .collect();

    let payload = RegistryOnboardingPayload {
        inception_event,
        attestations: attestation_values,
        proof_url,
    };

    let registry_url = registry_url.trim_end_matches('/');
    let response = transmit_registration(registry_url, &payload)
        .await
        .map_err(RegistrationError::NetworkError)?;
    let status = response.status();

    match status.as_u16() {
        201 => {
            let body: RegistrationResponse = response.json().await.map_err(|e| {
                RegistrationError::NetworkError(NetworkError::InvalidResponse {
                    detail: e.to_string(),
                })
            })?;

            Ok(RegistrationOutcome {
                did_prefix: body.did_prefix,
                registry: registry_url.to_string(),
                platform_claims_indexed: body.platform_claims_indexed,
            })
        }
        409 => Err(RegistrationError::AlreadyRegistered),
        429 => Err(RegistrationError::QuotaExceeded),
        _ => {
            let body = response.text().await.unwrap_or_default();
            Err(RegistrationError::NetworkError(
                NetworkError::InvalidResponse {
                    detail: format!("Registry error ({}): {}", status, body),
                },
            ))
        }
    }
}

async fn transmit_registration(
    registry: &str,
    payload: &RegistryOnboardingPayload,
) -> Result<reqwest::Response, NetworkError> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| NetworkError::Internal(Box::new(e)))?;

    let endpoint = format!("{}/v1/identities", registry);
    client
        .post(&endpoint)
        .json(payload)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                NetworkError::Timeout {
                    endpoint: endpoint.clone(),
                }
            } else if e.is_connect() {
                NetworkError::Unreachable {
                    endpoint: endpoint.clone(),
                }
            } else {
                NetworkError::Internal(Box::new(e))
            }
        })
}
