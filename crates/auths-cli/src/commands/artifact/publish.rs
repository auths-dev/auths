use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::ux::format::{JsonResponse, Output, is_json_mode};

#[derive(Serialize)]
struct PublishJsonResponse {
    attestation_rid: String,
    registry: String,
    package_name: Option<String>,
    signer_did: String,
}

#[derive(Deserialize)]
struct ArtifactPublishResponse {
    attestation_rid: String,
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

    let registry_url = registry.trim_end_matches('/');
    let response = transmit_publish(registry_url, &attestation, package_name.as_deref()).await?;
    let status = response.status();

    match status.as_u16() {
        201 => {
            let body: ArtifactPublishResponse = response
                .json()
                .await
                .context("Failed to parse publish response")?;

            if is_json_mode() {
                let json_resp = JsonResponse::success(
                    "artifact publish",
                    PublishJsonResponse {
                        attestation_rid: body.attestation_rid.clone(),
                        registry: registry_url.to_string(),
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
                    out.bold(registry_url)
                );
                println!("Attestation RID: {}", out.info(&body.attestation_rid));
                println!();
                if let Some(ref pkg) = body.package_name {
                    println!(
                        "View your trust graph online: {}/registry?q={}",
                        registry_url, pkg
                    );
                }
            }
        }
        409 => {
            bail!("Artifact attestation already published (duplicate RID).");
        }
        422 => {
            let body = response.text().await.unwrap_or_default();
            bail!("Signature verification failed at registry: {}", body);
        }
        _ => {
            let body = response.text().await.unwrap_or_default();
            bail!("Registry error ({}): {}", status, body);
        }
    }

    Ok(())
}

async fn transmit_publish(
    registry: &str,
    attestation: &serde_json::Value,
    package_name: Option<&str>,
) -> Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .build()
        .context("Failed to create HTTP client")?;

    let endpoint = format!("{}/v1/artifacts/publish", registry);
    let mut body = serde_json::json!({ "attestation": attestation });
    if let Some(name) = package_name {
        body["package_name"] = serde_json::Value::String(name.to_string());
    }
    client
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .context("Failed to connect to registry server")
}
