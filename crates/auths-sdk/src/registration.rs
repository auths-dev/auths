use std::sync::Arc;

use serde::{Deserialize, Serialize};

use auths_core::ports::network::{NetworkError, RegistryClient};
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_verifier::IdentityDID;
use auths_verifier::keri::Prefix;

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
    did: IdentityDID,
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
/// * `registry_client`: Network client for communicating with the registry.
///
/// Usage:
/// ```ignore
/// let outcome = register_identity(
///     identity_storage, registry, attestation_source,
///     "https://auths-registry.fly.dev", None, &http_client,
/// ).await?;
/// ```
pub async fn register_identity(
    identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    registry: Arc<dyn RegistryBackend + Send + Sync>,
    attestation_source: Arc<dyn AttestationSource + Send + Sync>,
    registry_url: &str,
    proof_url: Option<String>,
    registry_client: &impl RegistryClient,
) -> Result<RegistrationOutcome, RegistrationError> {
    let identity = identity_storage
        .load_identity()
        .map_err(RegistrationError::IdentityLoadError)?;

    let prefix = Prefix::from_did(&identity.controller_did).map_err(|_| {
        RegistrationError::InvalidDidFormat {
            did: identity.controller_did.to_string(),
        }
    })?;
    let inception = registry
        .get_event(&prefix, 0)
        .map_err(RegistrationError::RegistryReadError)?;
    let inception_event =
        serde_json::to_value(&inception).map_err(RegistrationError::SerializationError)?;

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

    let json_body = serde_json::to_vec(&payload).map_err(RegistrationError::SerializationError)?;

    let registry_url = registry_url.trim_end_matches('/');
    let response = registry_client
        .post_json(registry_url, "v1/identities", &json_body)
        .await
        .map_err(RegistrationError::NetworkError)?;

    match response.status {
        201 => {
            let body: RegistrationResponse =
                serde_json::from_slice(&response.body).map_err(|e| {
                    RegistrationError::NetworkError(NetworkError::InvalidResponse {
                        detail: e.to_string(),
                    })
                })?;

            Ok(RegistrationOutcome {
                did: body.did,
                registry: registry_url.to_string(),
                platform_claims_indexed: body.platform_claims_indexed,
            })
        }
        409 => Err(RegistrationError::AlreadyRegistered),
        429 => Err(RegistrationError::QuotaExceeded),
        _ => {
            let body = String::from_utf8_lossy(&response.body);
            Err(RegistrationError::NetworkError(
                NetworkError::InvalidResponse {
                    detail: format!("Registry error ({}): {}", response.status, body),
                },
            ))
        }
    }
}
