use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail};
use auths_verifier::IdentityDID;
use serde::Serialize;

use auths_infra_http::HttpRegistryClient;
use auths_sdk::domains::identity::error::RegistrationError;
pub use auths_sdk::domains::identity::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::domains::identity::types::RegistrationOutcome;
use auths_sdk::ports::AttestationSource;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::ports::RegistryBackend;
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

use crate::ux::format::{JsonResponse, Output, is_json_mode};

#[derive(Serialize)]
struct RegisterJsonResponse {
    did: IdentityDID,
    registry: String,
    platform_claims_indexed: usize,
}

/// Publishes a local identity to a registry for public discovery.
///
/// Args:
/// * `repo_path`: Path to the local identity repository.
/// * `registry`: Base URL of the target registry.
///
/// Usage:
/// ```ignore
/// handle_register(&repo_path, "https://public.auths.dev")?;
/// ```
pub fn handle_register(repo_path: &Path, registry: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(repo_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(repo_path));
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> = attestation_store;

    let registry_client = HttpRegistryClient::new();

    match rt.block_on(
        auths_sdk::domains::identity::registration::register_identity(
            identity_storage,
            backend,
            attestation_source,
            registry,
            None,
            &registry_client,
        ),
    ) {
        Ok(outcome) => display_registration_result(&outcome),
        Err(RegistrationError::AlreadyRegistered) => {
            bail!("Identity already registered at this registry.");
        }
        Err(RegistrationError::QuotaExceeded) => {
            bail!("Registration quota exceeded. Try again next month or use a paid tier.");
        }
        Err(RegistrationError::NetworkError(e)) => {
            bail!("Failed to connect to registry server: {e}");
        }
        Err(
            e @ (RegistrationError::InvalidDidFormat { .. }
            | RegistrationError::IdentityLoadError(_)
            | RegistrationError::RegistryReadError(_)
            | RegistrationError::SerializationError(_)),
        ) => {
            bail!("{e}");
        }
        Err(e) => {
            bail!("Registration failed: {e}");
        }
    }
}

fn display_registration_result(outcome: &RegistrationOutcome) -> Result<()> {
    if is_json_mode() {
        let json_resp = JsonResponse::success(
            "id register",
            RegisterJsonResponse {
                did: outcome.did.clone(),
                registry: outcome.registry.clone(),
                platform_claims_indexed: outcome.platform_claims_indexed,
            },
        );
        json_resp.print()?;
    } else {
        let out = Output::stdout();
        println!(
            "{} Identity registered at {}",
            out.success("Success!"),
            out.bold(&outcome.registry)
        );
        println!("DID: {}", out.info(&outcome.did));
        if outcome.platform_claims_indexed > 0 {
            println!(
                "Platform claims indexed: {}",
                outcome.platform_claims_indexed
            );
        }
        println!();
        println!(
            "{}",
            out.bold("Next step: Anchor a cryptographic attestation for your code")
        );
        println!(
            "Run: {}",
            out.dim(
                "auths artifact publish --signature <path-to.auths.json> --package <ecosystem:name>"
            )
        );
    }
    Ok(())
}
