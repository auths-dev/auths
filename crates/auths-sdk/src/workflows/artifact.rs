//! Artifact digest computation and publishing workflow.

use auths_core::ports::network::{NetworkError, RegistryClient};
use auths_verifier::core::ResourceId;
use serde::Deserialize;
use thiserror::Error;

use crate::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactSource};

/// Configuration for publishing an artifact attestation to a registry.
///
/// Args:
/// * `attestation`: The signed attestation JSON.
/// * `package_name`: Optional ecosystem-prefixed package identifier (e.g. `"npm:react@18.3.0"`).
/// * `registry_url`: Base URL of the target registry.
pub struct ArtifactPublishConfig {
    /// The signed attestation JSON payload.
    pub attestation: serde_json::Value,
    /// Optional ecosystem-prefixed package identifier (e.g. `"npm:react@18.3.0"`).
    pub package_name: Option<String>,
    /// Base URL of the target registry (trailing slash stripped by the SDK).
    pub registry_url: String,
}

/// Response from a successful artifact publish.
#[derive(Debug, Deserialize)]
pub struct ArtifactPublishResult {
    /// Stable registry identifier for the stored attestation.
    pub attestation_rid: ResourceId,
    /// Package identifier echoed back by the registry, if provided.
    pub package_name: Option<String>,
    /// DID of the identity that signed the attestation.
    pub signer_did: String,
}

/// Errors that can occur when publishing an artifact attestation.
#[derive(Debug, Error)]
pub enum ArtifactPublishError {
    /// Registry rejected the attestation because an identical RID already exists.
    #[error("artifact attestation already published (duplicate RID)")]
    DuplicateAttestation,
    /// Registry could not verify the attestation signature.
    #[error("signature verification failed at registry: {0}")]
    VerificationFailed(String),
    /// Registry returned an unexpected HTTP status code.
    #[error("registry error ({status}): {body}")]
    RegistryError {
        /// HTTP status code returned by the registry.
        status: u16,
        /// Response body text from the registry.
        body: String,
    },
    /// Network-level error communicating with the registry.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    /// Failed to serialize the publish request body.
    #[error("failed to serialize publish request: {0}")]
    Serialize(String),
    /// Failed to deserialize the registry response.
    #[error("failed to deserialize registry response: {0}")]
    Deserialize(String),
}

/// Publish a signed artifact attestation to a registry.
///
/// Args:
/// * `config`: Attestation payload, optional package name, and registry URL.
/// * `registry`: Registry HTTP client implementing `RegistryClient`.
///
/// Usage:
/// ```ignore
/// let result = publish_artifact(&config, &registry_client).await?;
/// println!("RID: {}", result.attestation_rid);
/// ```
pub async fn publish_artifact<R: RegistryClient>(
    config: &ArtifactPublishConfig,
    registry: &R,
) -> Result<ArtifactPublishResult, ArtifactPublishError> {
    let mut body = serde_json::json!({ "attestation": config.attestation });
    if let Some(ref name) = config.package_name {
        body["package_name"] = serde_json::Value::String(name.clone());
    }
    let json_bytes =
        serde_json::to_vec(&body).map_err(|e| ArtifactPublishError::Serialize(e.to_string()))?;

    let response = registry
        .post_json(&config.registry_url, "v1/artifacts/publish", &json_bytes)
        .await?;

    match response.status {
        201 => {
            let result: ArtifactPublishResult = serde_json::from_slice(&response.body)
                .map_err(|e| ArtifactPublishError::Deserialize(e.to_string()))?;
            Ok(result)
        }
        409 => Err(ArtifactPublishError::DuplicateAttestation),
        422 => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::VerificationFailed(body))
        }
        status => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::RegistryError { status, body })
        }
    }
}

/// Compute the digest of an artifact source.
///
/// Args:
/// * `source`: Any implementation of `ArtifactSource`.
///
/// Usage:
/// ```ignore
/// let digest = compute_digest(&file_artifact)?;
/// println!("sha256:{}", digest.hex);
/// ```
pub fn compute_digest(source: &dyn ArtifactSource) -> Result<ArtifactDigest, ArtifactError> {
    source.digest()
}

/// Verify an artifact attestation against an expected signer DID.
///
/// Symmetric to `sign_artifact()` — given the attestation JSON and the
/// expected signer's DID, verifies the signature is valid.
///
/// Args:
/// * `attestation_json`: The attestation JSON string.
/// * `signer_did`: Expected signer DID (`did:keri:` or `did:key:`).
/// * `provider`: Crypto backend for Ed25519 verification.
///
/// Usage:
/// ```ignore
/// let result = verify_artifact(&json, "did:key:z6Mk...", &provider).await?;
/// assert!(result.valid);
/// ```
pub async fn verify_artifact<R: RegistryClient>(
    config: &ArtifactVerifyConfig,
    registry: &R,
) -> Result<ArtifactVerifyResult, ArtifactPublishError> {
    let body = serde_json::json!({
        "attestation": config.attestation_json,
        "issuer_key": config.signer_did,
    });
    let json_bytes =
        serde_json::to_vec(&body).map_err(|e| ArtifactPublishError::Serialize(e.to_string()))?;

    let response = registry
        .post_json(&config.registry_url, "v1/verify", &json_bytes)
        .await?;

    match response.status {
        200 => {
            let result: ArtifactVerifyResult = serde_json::from_slice(&response.body)
                .map_err(|e| ArtifactPublishError::Deserialize(e.to_string()))?;
            Ok(result)
        }
        status => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::RegistryError { status, body })
        }
    }
}

/// Configuration for verifying an artifact attestation.
pub struct ArtifactVerifyConfig {
    /// The attestation JSON to verify.
    pub attestation_json: String,
    /// Expected signer DID.
    pub signer_did: String,
    /// Registry URL for verification.
    pub registry_url: String,
}

/// Result of artifact verification.
#[derive(Debug, Deserialize)]
pub struct ArtifactVerifyResult {
    /// Whether the attestation verified successfully.
    pub valid: bool,
    /// The signer DID extracted from the attestation (if valid).
    pub signer_did: Option<String>,
}
