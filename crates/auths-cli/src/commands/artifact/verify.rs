use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use auths_transparency::{
    BundleVerificationReport, CheckpointStatus, DelegationStatus, InclusionStatus, NamespaceStatus,
    OfflineBundle, SignatureStatus, TrustRoot, WitnessStatus,
};
use auths_verifier::core::Attestation;
use auths_verifier::witness::{WitnessQuorum, WitnessReceipt, WitnessVerifyConfig};
use auths_verifier::{
    CanonicalDid, Capability, IdentityBundle, VerificationReport, verify_chain,
    verify_chain_with_capability, verify_chain_with_witnesses,
};

use super::core::{ArtifactMetadata, ArtifactSource};
use super::file::FileArtifact;
use crate::commands::verify_helpers::parse_witness_keys;
use crate::config::Capabilities;
use crate::ux::format::is_json_mode;

/// JSON output for `artifact verify --json`.
#[derive(Serialize)]
struct VerifyArtifactResult {
    file: String,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_report: Option<VerificationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_quorum: Option<WitnessQuorum>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Execute the `artifact verify` command.
///
/// Exit codes: 0=valid, 1=invalid, 2=error.
pub async fn handle_verify(
    file: &Path,
    signature: Option<PathBuf>,
    identity_bundle: Option<PathBuf>,
    witness_receipts: Option<PathBuf>,
    witness_keys: &[String],
    witness_threshold: usize,
    caps: &Capabilities,
) -> Result<()> {
    let file_str = file.to_string_lossy().to_string();

    // 1. Locate and load signature file
    let sig_path = signature.unwrap_or_else(|| {
        let mut p = file.to_path_buf();
        let new_name = format!(
            "{}.auths.json",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    let sig_content = match fs::read_to_string(&sig_path) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                &file_str,
                2,
                &format!("Failed to read signature file {:?}: {}", sig_path, e),
            );
        }
    };

    let sig_value: serde_json::Value = match serde_json::from_str(&sig_content) {
        Ok(v) => v,
        Err(e) => {
            return output_error(&file_str, 2, &format!("Failed to parse .auths.json: {}", e));
        }
    };
    if sig_value.get("offline_bundle").is_some() {
        return handle_bundle_verify(file, &sig_content);
    }

    // 2. Parse attestation
    let attestation: Attestation = match serde_json::from_str(&sig_content) {
        Ok(a) => a,
        Err(e) => {
            return output_error(&file_str, 2, &format!("Failed to parse attestation: {}", e));
        }
    };

    // 3. Extract artifact metadata from payload
    let artifact_meta: ArtifactMetadata = match &attestation.payload {
        Some(payload) => match serde_json::from_value(payload.clone()) {
            Ok(m) => m,
            Err(e) => {
                return output_error(
                    &file_str,
                    2,
                    &format!("Failed to parse artifact metadata from payload: {}", e),
                );
            }
        },
        None => {
            return output_error(
                &file_str,
                2,
                "Attestation has no payload (expected artifact metadata)",
            );
        }
    };

    // 4. Compute file digest and compare
    let file_artifact = FileArtifact::new(file, caps.fs_read.clone());
    let file_digest = match file_artifact.digest() {
        Ok(d) => d,
        Err(e) => {
            return output_error(
                &file_str,
                2,
                &format!("Failed to compute file digest: {}", e),
            );
        }
    };

    if file_digest != artifact_meta.digest {
        return output_result(
            1,
            VerifyArtifactResult {
                file: file_str.clone(),
                valid: false,
                digest_match: Some(false),
                chain_valid: None,
                chain_report: None,
                capability_valid: None,
                witness_quorum: None,
                issuer: Some(attestation.issuer.to_string()),
                error: Some(format!(
                    "Digest mismatch: file={}, attestation={}",
                    file_digest.hex, artifact_meta.digest.hex
                )),
            },
        );
    }

    // 5. Resolve identity public key
    let (root_pk, identity_did) = match resolve_identity_key(&identity_bundle, &attestation) {
        Ok(v) => v,
        Err(e) => {
            return output_error(&file_str, 2, &e.to_string());
        }
    };

    // 6. Verify attestation chain with sign_release capability
    let chain = vec![attestation.clone()];
    let chain_result =
        verify_chain_with_capability(&chain, &Capability::sign_release(), &root_pk).await;

    let (chain_valid, chain_report, capability_valid) = match chain_result {
        Ok(report) => {
            let is_valid = report.is_valid();
            (Some(is_valid), Some(report), Some(true))
        }
        Err(auths_verifier::error::AttestationError::MissingCapability { .. }) => {
            // Chain signature is valid but capability is missing
            let report = verify_chain(&chain, &root_pk).await.ok();
            let chain_ok = report.as_ref().map(|r| r.is_valid());
            (chain_ok, report, Some(false))
        }
        Err(e) => {
            return output_error(&file_str, 1, &format!("Chain verification failed: {}", e));
        }
    };

    // 7. Optional witness verification
    let witness_quorum = match verify_witnesses(
        &chain,
        &root_pk,
        &witness_receipts,
        witness_keys,
        witness_threshold,
    )
    .await
    {
        Ok(q) => q,
        Err(e) => {
            return output_error(&file_str, 2, &format!("Witness verification error: {}", e));
        }
    };

    // 8. Compute overall verdict
    let mut valid = chain_valid.unwrap_or(false) && capability_valid.unwrap_or(true);

    if let Some(ref q) = witness_quorum
        && q.verified < q.required
    {
        valid = false;
    }

    let exit_code = if valid { 0 } else { 1 };

    output_result(
        exit_code,
        VerifyArtifactResult {
            file: file_str,
            valid,
            digest_match: Some(true),
            chain_valid,
            chain_report,
            capability_valid,
            witness_quorum,
            issuer: Some(identity_did.to_string()),
            error: None,
        },
    )
}

/// Resolve identity public key from bundle or from the attestation's issuer DID.
fn resolve_identity_key(
    identity_bundle: &Option<PathBuf>,
    attestation: &Attestation,
) -> Result<(Vec<u8>, CanonicalDid)> {
    if let Some(bundle_path) = identity_bundle {
        let bundle_content = fs::read_to_string(bundle_path)
            .with_context(|| format!("Failed to read identity bundle: {:?}", bundle_path))?;
        let bundle: IdentityBundle = serde_json::from_str(&bundle_content)
            .with_context(|| format!("Failed to parse identity bundle: {:?}", bundle_path))?;
        let pk = hex::decode(bundle.public_key_hex.as_str())
            .context("Invalid public key hex in bundle")?;
        Ok((pk, bundle.identity_did.into()))
    } else {
        // Resolve public key from the issuer DID
        let issuer = &attestation.issuer;
        let pk = resolve_pk_from_did(issuer)
            .with_context(|| format!("Failed to resolve public key from issuer DID '{}'. Use --identity-bundle for stateless verification.", issuer))?;
        Ok((pk, issuer.clone()))
    }
}

/// Extract raw Ed25519 public key bytes from a DID string.
///
/// Supports `did:keri:<base58>` and `did:key:z<base58multicodec>`.
fn resolve_pk_from_did(did: &str) -> Result<Vec<u8>> {
    if let Some(encoded) = did.strip_prefix("did:keri:") {
        let pk = bs58::decode(encoded)
            .into_vec()
            .context("Invalid base58 in did:keri")?;
        if pk.len() != 32 {
            return Err(anyhow!(
                "Expected 32-byte Ed25519 key from did:keri, got {}",
                pk.len()
            ));
        }
        Ok(pk)
    } else if did.starts_with("did:key:z") {
        auths_crypto::did_key_to_ed25519(did)
            .map(|k| k.to_vec())
            .map_err(|e| anyhow!("Failed to resolve did:key: {}", e))
    } else {
        Err(anyhow!(
            "Unsupported DID method: {}. Use --identity-bundle instead.",
            did
        ))
    }
}

/// Verify witness receipts if provided.
async fn verify_witnesses(
    chain: &[Attestation],
    root_pk: &[u8],
    receipts_path: &Option<PathBuf>,
    witness_keys_raw: &[String],
    threshold: usize,
) -> Result<Option<WitnessQuorum>> {
    let receipts_path = match receipts_path {
        Some(p) => p,
        None => return Ok(None),
    };

    let receipts_bytes = fs::read(receipts_path)
        .with_context(|| format!("Failed to read witness receipts: {:?}", receipts_path))?;
    let receipts: Vec<WitnessReceipt> =
        serde_json::from_slice(&receipts_bytes).context("Failed to parse witness receipts JSON")?;

    let witness_keys = parse_witness_keys(witness_keys_raw)?;

    let config = WitnessVerifyConfig {
        receipts: &receipts,
        witness_keys: &witness_keys,
        threshold,
    };

    let report = verify_chain_with_witnesses(chain, root_pk, &config)
        .await
        .context("Witness chain verification failed")?;

    Ok(report.witness_quorum)
}

/// Output error with appropriate formatting and exit code.
fn output_error(file: &str, exit_code: i32, message: &str) -> Result<()> {
    if is_json_mode() {
        let result = VerifyArtifactResult {
            file: file.to_string(),
            valid: false,
            digest_match: None,
            chain_valid: None,
            chain_report: None,
            capability_valid: None,
            witness_quorum: None,
            issuer: None,
            error: Some(message.to_string()),
        };
        println!("{}", serde_json::to_string(&result)?);
    } else {
        eprintln!("Error: {}", message);
    }
    std::process::exit(exit_code);
}

/// Output the verification result.
fn output_result(exit_code: i32, result: VerifyArtifactResult) -> Result<()> {
    if is_json_mode() {
        println!("{}", serde_json::to_string(&result)?);
    } else if result.valid {
        print!("Artifact verified");
        if let Some(ref issuer) = result.issuer {
            print!(": signed by {}", issuer);
        }
        if let Some(ref q) = result.witness_quorum {
            print!(" (witnesses: {}/{})", q.verified, q.required);
        }
        println!();
    } else {
        eprint!("Verification failed");
        if let Some(ref error) = result.error {
            eprint!(": {}", error);
        }
        if let Some(false) = result.capability_valid {
            eprint!(" (missing sign_release capability)");
        }
        eprintln!();
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn handle_bundle_verify(file: &Path, sig_content: &str) -> Result<()> {
    let file_str = file.to_string_lossy().to_string();

    let sig_value: serde_json::Value =
        serde_json::from_str(sig_content).with_context(|| "Failed to parse .auths.json")?;
    let bundle: OfflineBundle = serde_json::from_value(sig_value["offline_bundle"].clone())
        .with_context(|| "Failed to parse offline_bundle from .auths.json")?;

    let trust_root: TrustRoot = serde_json::from_str(&default_trust_root_json())
        .with_context(|| "Failed to parse default trust root")?;

    #[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
    let now = chrono::Utc::now();

    let report = auths_transparency::verify_bundle(&bundle, &trust_root, now);

    if is_json_mode() {
        println!(
            "{}",
            serde_json::to_string(&report).with_context(|| "Failed to serialize bundle report")?
        );
    } else {
        render_bundle_report(&report);
    }

    if report.is_valid() {
        cache_checkpoint_from_bundle(&bundle);
        Ok(())
    } else {
        output_error(&file_str, 1, "Bundle verification failed")
    }
}

/// Best-effort checkpoint caching after bundle verification.
#[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
fn cache_checkpoint_from_bundle(bundle: &OfflineBundle) {
    let cache_path = match dirs::home_dir() {
        Some(home) => home.join(".auths").join("log_checkpoint.json"),
        None => return,
    };

    match auths_sdk::workflows::transparency::try_cache_checkpoint(
        &cache_path,
        &bundle.signed_checkpoint,
        None,
    ) {
        Ok(report) => {
            if report.old_size == 0 && !is_json_mode() {
                eprintln!(
                    "Cached transparency checkpoint (tree size: {})",
                    report.new_size
                );
            }
        }
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Warning: checkpoint cache update failed: {e}");
            }
        }
    }
}

fn render_bundle_report(report: &BundleVerificationReport) {
    println!("Bundle Verification:");

    match &report.signature {
        SignatureStatus::Verified => println!("  Signature:    \u{2713} Verified"),
        SignatureStatus::Failed { reason } => {
            println!("  Signature:    \u{2717} Failed: {reason}")
        }
        SignatureStatus::NotProvided => println!("  Signature:    - Not provided"),
        _ => println!("  Signature:    ? Unknown status"),
    }

    match &report.inclusion {
        InclusionStatus::Verified => println!("  Inclusion:    \u{2713} Verified"),
        InclusionStatus::Failed { reason } => {
            println!("  Inclusion:    \u{2717} Failed: {reason}")
        }
        InclusionStatus::NotProvided => println!("  Inclusion:    - Not provided"),
        _ => println!("  Inclusion:    ? Unknown status"),
    }

    match &report.checkpoint {
        CheckpointStatus::Verified => println!("  Checkpoint:   \u{2713} Verified"),
        CheckpointStatus::InvalidSignature => {
            println!("  Checkpoint:   \u{2717} Invalid signature")
        }
        CheckpointStatus::NotProvided => println!("  Checkpoint:   - Not provided"),
        _ => println!("  Checkpoint:   ? Unknown status"),
    }

    match &report.witnesses {
        WitnessStatus::Quorum { verified, required } => {
            println!("  Witnesses:    \u{2713} Quorum ({verified}/{required} verified)");
        }
        WitnessStatus::Insufficient { verified, required } => {
            println!("  Witnesses:    \u{2717} Insufficient ({verified}/{required} verified)");
        }
        WitnessStatus::NotProvided => println!("  Witnesses:    - Not provided"),
        _ => println!("  Witnesses:    ? Unknown status"),
    }

    match &report.namespace {
        NamespaceStatus::Authorized => println!("  Namespace:    \u{2713} Authorized"),
        NamespaceStatus::Owned => println!("  Namespace:    \u{2713} Owned"),
        NamespaceStatus::Unowned => println!("  Namespace:    - Unowned"),
        NamespaceStatus::Unauthorized => println!("  Namespace:    \u{2717} Unauthorized"),
        _ => println!("  Namespace:    ? Unknown status"),
    }

    match &report.delegation {
        DelegationStatus::Direct => println!("  Delegation:   \u{2713} Direct"),
        DelegationStatus::ChainVerified {
            org_did,
            member_did,
            ..
        } => {
            println!("  Delegation:   \u{2713} Chain verified ({org_did} \u{2192} {member_did})");
        }
        DelegationStatus::ChainBroken { reason } => {
            println!("  Delegation:   \u{2717} Chain broken: {reason}");
        }
        DelegationStatus::NoDelegationData => println!("  Delegation:   - No delegation data"),
        _ => println!("  Delegation:   ? Unknown status"),
    }

    for warning in &report.warnings {
        println!("  Warning:      \u{26a0} {warning}");
    }
}

fn default_trust_root_json() -> String {
    // Epic 1 hardcoded trust root: no witnesses, placeholder log key.
    // Will be replaced by TUF-distributed trust root in fn-76.
    serde_json::json!({
        "log_public_key": "0000000000000000000000000000000000000000000000000000000000000000",
        "log_origin": "auths.dev/log",
        "witnesses": []
    })
    .to_string()
}
