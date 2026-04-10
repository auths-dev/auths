use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use auths_keri::witness::SignedReceipt;
use auths_verifier::core::Attestation;
use auths_verifier::witness::{WitnessQuorum, WitnessVerifyConfig};
use auths_verifier::{
    CanonicalDid, Capability, IdentityBundle, VerificationReport, verify_chain,
    verify_chain_with_capability, verify_chain_with_witnesses,
};

use super::core::{ArtifactMetadata, ArtifactSource};
use super::file::FileArtifact;
use crate::commands::verify_helpers::parse_witness_keys;
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
    commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_verified: Option<bool>,
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
    verify_commit: bool,
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
    let file_artifact = FileArtifact::new(file);
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
                commit_sha: attestation.commit_sha.clone(),
                commit_verified: None,
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

    // 8a. Ephemeral attestation: verify commit signature transitively
    let is_ephemeral = attestation.issuer.as_str().starts_with("did:key:");
    if is_ephemeral && valid {
        match &attestation.commit_sha {
            None => {
                if !is_json_mode() {
                    eprintln!(
                        "Error: ephemeral attestation (did:key issuer) requires commit_sha. \
                         This attestation is unsigned provenance without a commit anchor."
                    );
                }
                valid = false;
            }
            Some(sha) => {
                // Verify the commit is signed by a trusted key.
                // Uses in-process verification via auths-verifier (no git shell-out).
                let commit_sig_ok = verify_commit_in_process(sha);

                if !commit_sig_ok {
                    valid = false;
                }

                if !is_json_mode() {
                    if commit_sig_ok {
                        eprintln!(
                            "  Trust chain: artifact <- ephemeral key <- commit {} <- maintainer",
                            &sha[..8.min(sha.len())]
                        );
                    } else {
                        eprintln!(
                            "  Commit {} is not signed by a trusted maintainer.",
                            &sha[..8.min(sha.len())]
                        );
                    }
                }
            }
        }
    }

    // 8b. Display commit linkage info (always, when present)
    let commit_sha_val = attestation.commit_sha.clone();
    if let Some(ref sha) = commit_sha_val
        && !is_json_mode()
        && !is_ephemeral
    {
        eprintln!("  Commit: {}", sha);
    }

    // 8c. Optional commit attestation verification
    let commit_verified = if verify_commit {
        match &commit_sha_val {
            None => {
                if !is_json_mode() {
                    eprintln!(
                        "warning: artifact attestation has no commit_sha field; \
                         re-sign with: auths artifact sign --commit <SHA>"
                    );
                }
                None
            }
            Some(sha) => {
                // Look up commit attestation via git ref
                let commit_ref = format!("refs/auths/commits/{}", sha);
                let lookup = crate::subprocess::git_command(&[
                    "show",
                    &format!("{}:attestation.json", commit_ref),
                ])
                .output();
                match lookup {
                    Ok(output) if output.status.success() => {
                        if !is_json_mode() {
                            eprintln!("  Commit {}: signing attestation found", &sha[..12]);
                        }
                        Some(true)
                    }
                    _ => {
                        if !is_json_mode() {
                            eprintln!(
                                "warning: no signing attestation found for commit {}",
                                &sha[..std::cmp::min(sha.len(), 12)]
                            );
                        }
                        Some(false)
                    }
                }
            }
        }
    } else {
        None
    };

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
            commit_sha: commit_sha_val,
            commit_verified,
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
        let (pk, _curve) = resolve_pk_from_did(issuer)
            .with_context(|| format!("Failed to resolve public key from issuer DID '{}'. Use --identity-bundle for stateless verification.", issuer))?;
        Ok((pk, issuer.clone()))
    }
}

/// Extract raw Ed25519 public key bytes from a DID string.
///
/// Supports `did:keri:<base58>` and `did:key:z<base58multicodec>`.
fn resolve_pk_from_did(did: &str) -> Result<(Vec<u8>, auths_crypto::CurveType)> {
    if let Some(encoded) = did.strip_prefix("did:keri:") {
        let pk = bs58::decode(encoded)
            .into_vec()
            .context("Invalid base58 in did:keri")?;
        // KERI DIDs are currently Ed25519-only
        Ok((pk, auths_crypto::CurveType::Ed25519))
    } else if did.starts_with("did:key:z") {
        match auths_crypto::did_key_decode(did) {
            Ok(auths_crypto::DecodedDidKey::Ed25519(pk)) => {
                Ok((pk.to_vec(), auths_crypto::CurveType::Ed25519))
            }
            Ok(auths_crypto::DecodedDidKey::P256(pk)) => Ok((pk, auths_crypto::CurveType::P256)),
            Err(e) => Err(anyhow!("Failed to resolve did:key: {}", e)),
        }
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
    let receipts: Vec<SignedReceipt> =
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
            commit_sha: None,
            commit_verified: None,
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

/// Verify a commit signature in-process using `auths-verifier`.
///
/// Reads the commit content via git2, loads allowed signer keys from
/// `.auths/allowed_signers`, and verifies using the native Rust verifier.
/// No `git verify-commit --raw` shell-out.
fn verify_commit_in_process(sha: &str) -> bool {
    // Open the repository
    let repo = match git2::Repository::discover(".") {
        Ok(r) => r,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Failed to open git repository: {e}");
            }
            return false;
        }
    };

    // Parse the commit SHA
    let oid = match git2::Oid::from_str(sha) {
        Ok(o) => o,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Invalid commit SHA '{}': {e}", &sha[..8.min(sha.len())]);
            }
            return false;
        }
    };

    // Get the raw commit content (same as `git cat-file commit <sha>`)
    let commit_obj = match repo.find_object(oid, Some(git2::ObjectType::Commit)) {
        Ok(obj) => obj,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Commit {} not found: {e}", &sha[..8.min(sha.len())]);
            }
            return false;
        }
    };

    // Get raw content including the signature header
    let commit_content = match repo
        .find_commit(oid)
        .ok()
        .and_then(|c| c.raw_header().map(|h| h.to_string()))
    {
        Some(header) => {
            // Reconstruct full commit content: header + \n\n + message
            let msg = repo
                .find_commit(oid)
                .ok()
                .and_then(|c| c.message_raw().map(|m| m.to_string()))
                .unwrap_or_default();
            format!("{}\n\n{}", header, msg)
        }
        None => {
            // Fallback: use the raw object data
            match commit_obj.as_blob() {
                Some(blob) => String::from_utf8_lossy(blob.content()).to_string(),
                None => {
                    if !is_json_mode() {
                        eprintln!(
                            "Cannot read commit content for {}",
                            &sha[..8.min(sha.len())]
                        );
                    }
                    return false;
                }
            }
        }
    };

    // Load allowed signer keys from .auths/allowed_signers
    let allowed_signers_path = std::path::Path::new(".auths/allowed_signers");
    let allowed_keys = if allowed_signers_path.exists() {
        match std::fs::read_to_string(allowed_signers_path) {
            Ok(content) => parse_allowed_signer_keys(&content),
            Err(e) => {
                if !is_json_mode() {
                    eprintln!("Failed to read .auths/allowed_signers: {e}");
                }
                return false;
            }
        }
    } else {
        if !is_json_mode() {
            eprintln!("No .auths/allowed_signers file found. Create one with: auths signers sync");
        }
        return false;
    };

    if allowed_keys.is_empty() {
        if !is_json_mode() {
            eprintln!("No signing keys found in .auths/allowed_signers");
        }
        return false;
    }

    // Verify using in-process verifier
    let provider = auths_crypto::RingCryptoProvider;
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Failed to create async runtime: {e}");
            }
            return false;
        }
    };

    match rt.block_on(auths_verifier::commit::verify_commit_signature(
        commit_content.as_bytes(),
        &allowed_keys,
        &provider,
        Some(repo.path().parent().unwrap_or(std::path::Path::new("."))),
    )) {
        Ok(_verified) => true,
        Err(e) => {
            if !is_json_mode() {
                eprintln!(
                    "Commit {} signature verification failed: {e}",
                    &sha[..8.min(sha.len())]
                );
            }
            false
        }
    }
}

/// Parse public keys from an allowed_signers file.
///
/// Format: `email namespaces key-type base64-key`
/// Supports both `ssh-ed25519` and `ecdsa-sha2-nistp256` key types.
fn parse_allowed_signer_keys(content: &str) -> Vec<auths_verifier::DevicePublicKey> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find supported key type and extract the base64 key
            let key_idx = parts
                .iter()
                .position(|&p| p == "ssh-ed25519" || p == "ecdsa-sha2-nistp256")?;
            let key_type = parts[key_idx];
            let b64_key = parts.get(key_idx + 1)?;

            use base64::Engine;
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(b64_key)
                .ok()?;
            // SSH key format: 4-byte type-length + type-string + 4-byte key-length + key-data
            if key_bytes.len() < 4 {
                return None;
            }
            let type_len = u32::from_be_bytes(key_bytes[..4].try_into().ok()?) as usize;
            let after_type = 4 + type_len;

            match key_type {
                "ssh-ed25519" => {
                    let key_start = after_type + 4;
                    if key_bytes.len() < key_start + 32 {
                        return None;
                    }
                    auths_verifier::DevicePublicKey::try_new(
                        auths_crypto::CurveType::Ed25519,
                        &key_bytes[key_start..key_start + 32],
                    )
                    .ok()
                }
                "ecdsa-sha2-nistp256" => {
                    // ECDSA SSH format: type + curve-name-string + ec-point-string
                    if key_bytes.len() < after_type + 4 {
                        return None;
                    }
                    let curve_len =
                        u32::from_be_bytes(key_bytes[after_type..after_type + 4].try_into().ok()?)
                            as usize;
                    let after_curve = after_type + 4 + curve_len;
                    if key_bytes.len() < after_curve + 4 {
                        return None;
                    }
                    let point_len = u32::from_be_bytes(
                        key_bytes[after_curve..after_curve + 4].try_into().ok()?,
                    ) as usize;
                    let point_start = after_curve + 4;
                    if key_bytes.len() < point_start + point_len {
                        return None;
                    }
                    auths_verifier::DevicePublicKey::try_new(
                        auths_crypto::CurveType::P256,
                        &key_bytes[point_start..point_start + point_len],
                    )
                    .ok()
                }
                _ => None,
            }
        })
        .collect()
}
