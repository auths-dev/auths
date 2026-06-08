use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use auths_keri::witness::SignedReceipt;
use auths_verifier::core::Attestation;
use auths_verifier::witness::{WitnessQuorum, WitnessVerifyConfig};
use auths_verifier::{
    CanonicalDid, IdentityBundle, VerificationReport, verify_chain, verify_chain_with_witnesses,
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

    // 6. Verify attestation chain authenticity (signatures, linkage, expiry).
    //    Capability authority is no longer gated here: an artifact-signer capability
    //    grant must come from a holder-verified ACDC credential, not the attestation.
    let chain = vec![attestation.clone()];
    let chain_result = verify_chain(&chain, &root_pk).await;

    let (chain_valid, chain_report) = match chain_result {
        Ok(mut report) => {
            if let Ok(home) = auths_sdk::paths::auths_home() {
                let storage = auths_sdk::storage::RegistryAttestationStorage::new(&home);
                if let Ok(enriched) = storage.load_all_enriched() {
                    let anchor_set: std::collections::HashSet<auths_keri::Said> = enriched
                        .iter()
                        .filter(|e| e.anchor == auths_keri::AnchorStatus::Anchored)
                        .map(|e| e.said.clone())
                        .collect();
                    let all_anchored = chain.iter().all(|att| {
                        auths_sdk::attestation::canonical_said(att)
                            .is_some_and(|s| anchor_set.contains(&s))
                    });
                    report.anchored = Some(if all_anchored {
                        auths_keri::AnchorStatus::Anchored
                    } else {
                        auths_keri::AnchorStatus::NotAnchored
                    });
                }
            }
            let is_valid = report.is_valid();
            (Some(is_valid), Some(report))
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
    let mut valid = chain_valid.unwrap_or(false);

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
) -> Result<(auths_verifier::DevicePublicKey, CanonicalDid)> {
    if let Some(bundle_path) = identity_bundle {
        let bundle_content = fs::read_to_string(bundle_path)
            .with_context(|| format!("Failed to read identity bundle: {:?}", bundle_path))?;
        let bundle: IdentityBundle = serde_json::from_str(&bundle_content)
            .with_context(|| format!("Failed to parse identity bundle: {:?}", bundle_path))?;
        let pk_bytes = hex::decode(bundle.public_key_hex.as_str())
            .context("Invalid public key hex in bundle")?;
        let pk = auths_verifier::DevicePublicKey::try_new(bundle.curve, &pk_bytes)
            .map_err(|e| anyhow!("Invalid bundle public key: {e}"))?;
        Ok((pk, bundle.identity_did.into()))
    } else {
        // Resolve public key from the issuer DID
        let issuer = &attestation.issuer;
        let (pk_bytes, curve) = resolve_pk_from_did(issuer)
            .with_context(|| format!("Failed to resolve public key from issuer DID '{}'. Use --identity-bundle for stateless verification.", issuer))?;
        let pk = auths_verifier::DevicePublicKey::try_new(curve, &pk_bytes)
            .map_err(|e| anyhow!("Invalid issuer public key resolved from DID: {e}"))?;
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
    root_pk: &auths_verifier::DevicePublicKey,
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
        eprintln!();
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Verify the commit an ephemeral attestation is bound to, KEL-natively.
///
/// Reads the raw commit via git2, then delegates trust to the SDK commit-trust
/// resolver: the signer must be a device delegated under a root pinned in
/// `.auths/roots`. No `.auths/allowed_signers`, no `ssh-keygen` allowlist, no
/// `git verify-commit --raw` shell-out.
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

    // KEL-native trust: the commit's signer must be a device delegated under a root
    // pinned in `.auths/roots`. The verdict logic lives in the SDK commit-trust resolver.
    let provider = auths_crypto::RingCryptoProvider;
    let auths_home = match auths_sdk::paths::auths_home() {
        Ok(h) => h,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Could not locate ~/.auths: {e}");
            }
            return false;
        }
    };
    let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(&auths_home),
    );
    let pinned_roots = crate::commands::verify_helpers::load_project_pinned_roots();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Failed to create async runtime: {e}");
            }
            return false;
        }
    };

    let short = &sha[..8.min(sha.len())];
    match rt.block_on(auths_sdk::workflows::commit_trust::verify_commit_local(
        &registry,
        &pinned_roots,
        commit_content.as_bytes(),
        &provider,
    )) {
        Ok(verdict) if verdict.is_valid() => true,
        Ok(verdict) => {
            if !is_json_mode() {
                eprintln!("Commit {short} is not authorized by a pinned trusted root: {verdict:?}");
            }
            false
        }
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Commit {short} trust could not be resolved: {e}");
            }
            false
        }
    }
}

/// Verify an air-gapped org bundle entirely offline (zero network), fail-closed.
///
/// Reads the fn-154.5 bundle, loads the verifier's pinned roots (from `roots` or the
/// default `.auths/roots`, falling back to the bundle's declared roots if neither
/// exists), and classifies the optional `member` at `signed_at` purely from the
/// bundle's KEL contents. Exits non-zero on any non-authorized verdict so it can gate
/// CI.
///
/// Args:
/// * `file`: Path to the air-gapped bundle (`auths org bundle` output).
/// * `roots`: Optional pinned-roots file (default `.auths/roots`).
/// * `member`: Optional member `did:keri` to classify authority for.
/// * `signed_at`: Optional in-band signing KEL position for the member's artifact.
/// * `json`: Emit the typed report as JSON.
///
/// Usage:
/// ```ignore
/// handle_offline_verify(Path::new("acme.auths-offline"), None, None, None, false)?;
/// ```
pub fn handle_offline_verify(
    file: &Path,
    roots: Option<&Path>,
    member: Option<&str>,
    signed_at: Option<u128>,
    json: bool,
) -> Result<()> {
    use auths_sdk::workflows::org::{AirGappedOrgBundle, AuthorityAtSigning, verify_org_bundle};
    use auths_sdk::workflows::roots::parse_roots_typed;
    use auths_verifier::Prefix;
    use auths_verifier::types::IdentityDID;

    let bundle_json =
        fs::read_to_string(file).with_context(|| format!("Failed to read bundle file {file:?}"))?;
    let bundle = AirGappedOrgBundle::from_json(&bundle_json)
        .context("Failed to parse air-gapped org bundle")?;

    let roots_path = roots
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".auths/roots"));
    let pinned_roots: Vec<IdentityDID> = if roots_path.exists() {
        let content = fs::read_to_string(&roots_path)
            .with_context(|| format!("Failed to read roots file {roots_path:?}"))?;
        parse_roots_typed(&content).context("Failed to parse pinned roots")?
    } else {
        // No verifier-side roots configured — trust the bundle's declared roots
        // (trust-on-first-use). Supply --roots to pin explicitly.
        bundle.pinned_roots.clone()
    };

    let member_prefix =
        member.map(|m| Prefix::new_unchecked(m.strip_prefix("did:keri:").unwrap_or(m).to_string()));
    let query = member_prefix.as_ref().map(|p| (p, signed_at));

    let report =
        verify_org_bundle(&bundle, &pinned_roots, query).context("Offline verification failed")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Air-gapped verification of {file:?}");
        println!("  Org:            {}", report.org_did.as_str());
        println!(
            "  Verified as-of: KEL seq {} (by position, not wall-clock)",
            report.as_of_org_seq
        );
        let root = if report.root_pinned {
            "✅ yes"
        } else {
            "🛑 NO (untrusted root)"
        };
        println!("  Root pinned:    {root}");
        let dup = if report.duplicity_detected {
            "🛑 DETECTED"
        } else {
            "✅ none"
        };
        println!("  Duplicity:      {dup}");
        if let Some(authority) = &report.authority {
            match authority {
                AuthorityAtSigning::AuthorizedBeforeRevocation => {
                    println!("  Authority:      ✅ AuthorizedBeforeRevocation")
                }
                AuthorityAtSigning::RejectedAfterRevocation { revoked_at } => {
                    println!(
                        "  Authority:      🛑 RejectedAfterRevocation {{ revoked_at: {revoked_at} }}"
                    )
                }
                AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at } => {
                    println!(
                        "  Authority:      🛑 RejectedRevokedPositionUnknown {{ revoked_at: {revoked_at} }}"
                    )
                }
                AuthorityAtSigning::NeverDelegated => {
                    println!("  Authority:      ❌ NeverDelegated")
                }
            }
        }
    }

    // Fail-closed exit: anything short of a trusted, non-duplicitous, authorized
    // verdict is a hard failure (so CI gates reject it).
    if !report.root_pinned {
        return Err(anyhow!(
            "unauthorized: the bundle's org is not in the pinned trust roots"
        ));
    }
    if report.duplicity_detected {
        return Err(anyhow!(
            "org KEL duplicity detected — divergent history; resolve before trusting"
        ));
    }
    match report.authority {
        None | Some(AuthorityAtSigning::AuthorizedBeforeRevocation) => Ok(()),
        Some(AuthorityAtSigning::RejectedAfterRevocation { revoked_at }) => Err(anyhow!(
            "unauthorized: signed at/after revocation (KEL seq {revoked_at})"
        )),
        Some(AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at }) => Err(anyhow!(
            "unauthorized: member revoked at KEL seq {revoked_at}; artifact has no in-band signing position"
        )),
        Some(AuthorityAtSigning::NeverDelegated) => {
            Err(anyhow!("unauthorized: the org never delegated this member"))
        }
    }
}
