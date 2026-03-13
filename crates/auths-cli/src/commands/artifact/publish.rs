use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use auths_infra_http::HttpRegistryClient;
use auths_sdk::workflows::artifact::{
    ArtifactPublishConfig, ArtifactPublishError, ArtifactPublishResult, publish_artifact,
};
use auths_transparency::OfflineBundle;
use auths_verifier::core::ResourceId;
use serde::Serialize;

use crate::ux::format::{JsonResponse, Output, is_json_mode};

#[derive(Serialize)]
struct PublishJsonResponse {
    attestation_rid: ResourceId,
    registry: String,
    package_name: Option<String>,
    signer_did: String,
}

/// Publishes a signed artifact attestation to a registry.
///
/// Args:
/// * `signature_path`: Path to the `.auths.json` signature file.
/// * `package`: Optional package identifier for registry indexing.
/// * `registry`: Base URL of the target registry.
///
/// Usage:
/// ```ignore
/// handle_publish(Path::new("artifact.auths.json"), Some("npm:react@18.3.0"), "https://public.auths.dev")?;
/// ```
pub fn handle_publish(signature_path: &Path, package: Option<&str>, registry: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    rt.block_on(handle_publish_async(signature_path, package, registry))
}

fn validate_package_identifier(package: &str) -> Result<String> {
    let trimmed = package.trim();
    if trimmed.is_empty() {
        bail!("Package identifier must not be empty.");
    }
    if !trimmed.contains(':') {
        bail!(
            "Package identifier must contain an ecosystem prefix (e.g., npm:react@18.3.0), got: {}",
            trimmed
        );
    }
    if trimmed.chars().any(|c| c.is_ascii_control() || c == ' ') {
        bail!(
            "Package identifier must not contain whitespace or control characters, got: {}",
            trimmed
        );
    }
    Ok(trimmed.to_lowercase())
}

async fn handle_publish_async(
    signature_path: &Path,
    package: Option<&str>,
    registry: &str,
) -> Result<()> {
    if !signature_path.exists() {
        bail!(
            "Signature file not found: {:?}\nRun `auths artifact sign` first to create a signature file.",
            signature_path
        );
    }

    let sig_contents = std::fs::read_to_string(signature_path)
        .with_context(|| format!("Failed to read signature file: {:?}", signature_path))?;

    let attestation: serde_json::Value =
        serde_json::from_str(&sig_contents).with_context(|| {
            format!(
                "Failed to parse signature file as JSON: {:?}",
                signature_path
            )
        })?;

    // Validate the package identifier if provided, but do NOT modify the signed
    // attestation — the payload is part of the signed canonical data.
    let package_name = if let Some(pkg) = package {
        Some(validate_package_identifier(pkg)?)
    } else {
        let has_name = attestation
            .get("payload")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .is_some_and(|s| !s.is_empty());
        if !has_name && !is_json_mode() {
            eprintln!(
                "Warning: No --package specified and no name in attestation payload. \
                 This artifact won't be discoverable by package query."
            );
        }
        None
    };

    let registry_url = registry.trim_end_matches('/').to_string();
    let registry_client =
        HttpRegistryClient::new_with_timeouts(Duration::from_secs(30), Duration::from_secs(60));
    let config = ArtifactPublishConfig {
        attestation,
        package_name,
        registry_url: registry_url.clone(),
    };

    let body = publish_artifact(&config, &registry_client)
        .await
        .map_err(|e| match e {
            ArtifactPublishError::DuplicateAttestation => {
                anyhow::anyhow!("Artifact attestation already published (duplicate RID).")
            }
            ArtifactPublishError::VerificationFailed(msg) => {
                anyhow::anyhow!("Signature verification failed at registry: {}", msg)
            }
            ArtifactPublishError::RegistryError { status, body } => {
                anyhow::anyhow!("Registry error ({}): {}", status, body)
            }
            other => anyhow::anyhow!("{}", other),
        })?;

    // Cache checkpoint from bundle if present in the signature file
    cache_checkpoint_from_sig(&sig_contents);

    if is_json_mode() {
        let json_resp = JsonResponse::success(
            "artifact publish",
            PublishJsonResponse {
                attestation_rid: body.attestation_rid.clone(),
                registry: registry_url.clone(),
                package_name: body.package_name.clone(),
                signer_did: body.signer_did.clone(),
            },
        );
        json_resp.print()?;
    } else {
        let out = Output::stdout();
        if let Some(ref pkg) = body.package_name {
            println!("Anchoring signature for {}...", out.info(pkg));
        }
        println!(
            "{} Cryptographic attestation anchored at {}",
            out.success("Success!"),
            out.bold(&registry_url)
        );
        println!("Attestation RID: {}", out.info(&body.attestation_rid));
        println!();
        if let Some(ref pkg) = body.package_name {
            println!(
                "View your trust graph online: {}/registry?q={}",
                registry_url, pkg
            );
        }
        display_rate_limit(&out, &body);
    }

    Ok(())
}

fn display_rate_limit(out: &Output, result: &ArtifactPublishResult) {
    let Some(ref rl) = result.rate_limit else {
        return;
    };
    println!();
    if let Some(tier) = &rl.tier {
        println!("  Tier:      {}", out.info(tier));
    }
    if let (Some(remaining), Some(limit)) = (rl.remaining, rl.limit) {
        println!(
            "  Quota:     {}/{} requests remaining today",
            out.bold(&remaining.to_string()),
            limit
        );
    }
    if let Some(reset) = rl.reset
        && let Some(dt) = chrono::DateTime::from_timestamp(reset, 0)
    {
        let human = dt.format("%Y-%m-%d %H:%M UTC");
        println!("  Resets at: {human}");
    }
}

/// Best-effort checkpoint caching after publish, using the bundle in the sig file.
#[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
fn cache_checkpoint_from_sig(sig_contents: &str) {
    let sig_value: serde_json::Value = match serde_json::from_str(sig_contents) {
        Ok(v) => v,
        Err(_) => return,
    };

    if sig_value.get("offline_bundle").is_none() {
        return;
    }

    let bundle: OfflineBundle = match serde_json::from_value(sig_value["offline_bundle"].clone()) {
        Ok(b) => b,
        Err(_) => return,
    };

    let cache_path = match dirs::home_dir() {
        Some(home) => home.join(".auths").join("log_checkpoint.json"),
        None => return,
    };

    if let Err(e) = auths_sdk::workflows::transparency::try_cache_checkpoint(
        &cache_path,
        &bundle.signed_checkpoint,
        None,
    ) && !is_json_mode()
    {
        eprintln!("Warning: checkpoint cache update failed: {e}");
    }
}
