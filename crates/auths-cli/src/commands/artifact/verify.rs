use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use auths_keri::witness::SignedReceipt;
use auths_verifier::core::Attestation;
use auths_verifier::evidence_pack::{
    TransparencyInclusion, parse_log_key_hex, verify_artifact_log_inclusion,
};
use auths_verifier::oidc_policy::{OidcPolicyJoin, OidcSubjectPolicy};
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
    oidc_join: Option<OidcPolicyJoin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// How an ephemeral (`did:key:`) attestation's commit-anchor leg is treated.
///
/// An ephemeral CI signature trust-chains to a maintainer through its
/// `commit_sha` (artifact ← ephemeral key ← commit ← maintainer). Resolving
/// that leg needs the maintainer's repository and pinned roots — which the
/// scrubbed runner that *produced* the signature does not have. The runner
/// can still confirm what it just emitted: the artifact's digest and the
/// ephemeral signature over it. That standalone self-check is [`Self::SignatureOnly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralAnchor {
    /// Trust an ephemeral attestation only after its commit-anchor leg
    /// resolves to a trusted maintainer. The full chain; the default.
    Required,
    /// Confirm an ephemeral attestation from its digest + signature alone,
    /// without the commit-anchor leg. The signer's self-check: valid means
    /// "this artifact's digest matches and the ephemeral key signed it",
    /// not "this signer trust-chains to a maintainer".
    SignatureOnly,
}

/// Inputs for [`handle_verify`] beyond the artifact path — named fields
/// (the `AttestationInput` pattern) so call sites stay readable as the
/// verify surface grows.
pub struct VerifyArtifactArgs {
    /// Path to the signature file (defaults to `<FILE>.auths.json`).
    pub signature: Option<PathBuf>,
    /// Identity bundle for stateless verification.
    pub identity_bundle: Option<PathBuf>,
    /// Witness receipts file.
    pub witness_receipts: Option<PathBuf>,
    /// Witness public keys as DID:hex pairs.
    pub witness_keys: Vec<String>,
    /// Number of witnesses required.
    pub witness_threshold: usize,
    /// Also verify the source commit's signing attestation.
    pub verify_commit: bool,
    /// How to treat an ephemeral attestation's commit-anchor leg.
    pub ephemeral_anchor: EphemeralAnchor,
    /// OIDC-subject policy to JOIN against the signed OIDC binding.
    pub oidc_policy: Option<PathBuf>,
    /// Org `did:keri:` whose KEL-anchored OIDC-subject policy to resolve and
    /// JOIN — the witnessed log as the policy's source of truth.
    pub oidc_policy_did: Option<String>,
    /// Offline transparency-log inclusion evidence (`auths log prove --out`).
    pub log_evidence: Option<PathBuf>,
    /// The log operator's pinned Ed25519 key (64 hex chars); paired with
    /// `log_evidence` at the clap boundary.
    pub log_key: Option<String>,
}

/// Execute the `artifact verify` command.
///
/// Exit codes: 0=valid, 1=invalid, 2=error.
pub async fn handle_verify(file: &Path, args: VerifyArtifactArgs) -> Result<()> {
    let VerifyArtifactArgs {
        signature,
        identity_bundle,
        witness_receipts,
        witness_keys,
        witness_threshold,
        verify_commit,
        ephemeral_anchor,
        oidc_policy,
        oidc_policy_did,
        log_evidence,
        log_key,
    } = args;
    let witness_keys = &witness_keys;
    let file_str = file.to_string_lossy().to_string();

    // 0. Resolve the OIDC-subject policy up front: an unreadable or malformed
    //    policy is a "could not attempt" (exit 2), not a verdict — except a
    //    KEL-anchored blob that fails its digest check, which IS a verdict (1).
    let oidc_policy = match (&oidc_policy, &oidc_policy_did) {
        (None, None) => None,
        (Some(path), _) => {
            let raw = match fs::read_to_string(path) {
                Ok(r) => r,
                Err(e) => {
                    return output_error(
                        &file_str,
                        2,
                        &format!("Failed to read OIDC policy {path:?}: {e}"),
                    );
                }
            };
            match OidcSubjectPolicy::parse(&raw) {
                Ok(p) => Some(p),
                Err(e) => {
                    return output_error(&file_str, 2, &format!("{e}"));
                }
            }
        }
        (None, Some(org_did)) => match resolve_anchored_oidc_policy(org_did) {
            Ok(p) => Some(p),
            Err((exit_code, message)) => {
                return output_error(&file_str, exit_code, &message);
            }
        },
    };

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
                oidc_join: None,
                error: Some(format!(
                    "Digest mismatch: file={}, attestation={}",
                    file_digest.hex, artifact_meta.digest.hex
                )),
            },
        );
    }

    // 5. Resolve identity public key
    // Exit-code contract: 0 = verified, 1 = verification failed (a trust or
    // signature verdict — an unresolvable/untrusted issuer is a verdict), 2 =
    // could not attempt (I/O, malformed input).
    let (root_pk, identity_did) = match resolve_identity_key(&identity_bundle, &attestation) {
        Ok(v) => v,
        Err(e) => {
            return output_error(&file_str, 1, &format!("{e:#}"));
        }
    };

    // 6. Verify attestation chain authenticity (signatures, linkage, expiry).
    //    Capability authority is no longer gated here: an artifact-signer capability
    //    grant must come from a holder-verified ACDC credential, not the attestation.
    let chain = vec![attestation.clone()];
    let chain_result = verify_chain(&chain, &root_pk).await;

    let (chain_valid, mut chain_report) = match chain_result {
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

    // 6b. Offline transparency anchoring. With inclusion evidence supplied,
    //     the verdict's `anchored` field is decided by the proof: Anchored
    //     only when the evidence binds to THIS artifact's digest, its Merkle
    //     inclusion verifies, and the checkpoint is attested by the pinned
    //     log key. Fail-closed: evidence that does not prove is a verdict
    //     (exit 1), never a skip.
    let mut log_anchor_error: Option<String> = None;
    if let Some(evidence_path) = &log_evidence {
        let raw = match fs::read_to_string(evidence_path) {
            Ok(r) => r,
            Err(e) => {
                return output_error(
                    &file_str,
                    2,
                    &format!("Failed to read log evidence {evidence_path:?}: {e}"),
                );
            }
        };
        let evidence: TransparencyInclusion = match serde_json::from_str(&raw) {
            Ok(t) => t,
            Err(e) => {
                return output_error(&file_str, 2, &format!("Failed to parse log evidence: {e}"));
            }
        };
        // clap enforces the pair; a bare evidence path here is could-not-attempt.
        let Some(key_hex) = log_key.as_deref() else {
            return output_error(&file_str, 2, "--log-evidence requires --log-key");
        };
        let pinned_key = match parse_log_key_hex(key_hex) {
            Ok(k) => k,
            Err(e) => return output_error(&file_str, 2, &format!("{e}")),
        };
        // The log's leaf data is the canonical `sha256:<hex>` digest string —
        // derive it through the same parsed type the append path uses.
        let canonical_digest = match auths_sdk::workflows::compliance::ArtifactDigest::parse(
            &format!("{}:{}", file_digest.algorithm, file_digest.hex),
        ) {
            Ok(d) => d,
            Err(e) => {
                return output_error(
                    &file_str,
                    2,
                    &format!("Cannot derive the artifact's canonical log leaf: {e}"),
                );
            }
        };
        match verify_artifact_log_inclusion(canonical_digest.as_str(), &evidence, &pinned_key) {
            Ok(()) => {
                if let Some(report) = chain_report.as_mut() {
                    report.anchored = Some(auths_keri::AnchorStatus::Anchored);
                }
                if !is_json_mode() {
                    eprintln!(
                        "  Transparency: {} anchored in log '{}' \
                         (offline inclusion proof, operator key pinned)",
                        canonical_digest.as_str(),
                        evidence.signed_checkpoint.checkpoint.origin
                    );
                }
            }
            Err(e) => {
                if let Some(report) = chain_report.as_mut() {
                    report.anchored = Some(auths_keri::AnchorStatus::NotAnchored);
                }
                log_anchor_error = Some(format!("Transparency anchoring failed: {e}"));
            }
        }
    }

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

    if let Some(ref msg) = log_anchor_error {
        valid = false;
        if !is_json_mode() {
            eprintln!("  {msg}");
        }
    }

    // 8a. Ephemeral attestation: trust chains through the commit anchor.
    //     `--signature-only` confines the verdict to digest + signature — the
    //     self-check the runner that emitted the attestation can run without the
    //     maintainer's repo/roots. It does NOT chase the commit-anchor leg, so it
    //     never claims the signer trust-chains to a maintainer.
    let is_ephemeral = attestation.issuer.as_str().starts_with("did:key:");
    if is_ephemeral && valid {
        match ephemeral_anchor {
            EphemeralAnchor::SignatureOnly => {
                if !is_json_mode() {
                    eprintln!(
                        "  Signature-only: ephemeral signature over the artifact digest \
                         verifies; commit-anchor leg NOT checked (signer self-check)."
                    );
                }
            }
            EphemeralAnchor::Required => match &attestation.commit_sha {
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
                    let commit_sig_ok = verify_commit_in_process(sha).await;

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
            },
        }
    }

    // 8a2. The keyless exchange, verify side: JOIN the attestation's
    //      signature-covered OIDC binding against the org's pinned policy.
    //      Fail-closed: only a chain-valid attestation has a trustworthy
    //      binding, and a missing binding or any claim mismatch is a
    //      verification failure, never a pass.
    let mut oidc_error: Option<String> = None;
    let oidc_join = match &oidc_policy {
        None => None,
        Some(_) if !valid => {
            // Already failing — the binding's claims can't be trusted, so the
            // join is not attempted (and cannot rescue the verdict).
            None
        }
        Some(policy) => match &attestation.oidc_binding {
            None => {
                valid = false;
                oidc_error = Some(
                    "OIDC policy join failed: attestation carries no OIDC binding \
                     — signer presented no verified OIDC identity"
                        .to_string(),
                );
                None
            }
            Some(binding) => match policy.join(binding) {
                Ok(join) => {
                    if !is_json_mode() {
                        eprintln!(
                            "  OIDC policy join: {} via {} (issuer {})",
                            join.repository,
                            join.workflow_ref.as_deref().unwrap_or("any workflow"),
                            join.issuer
                        );
                    }
                    Some(join)
                }
                Err(e) => {
                    valid = false;
                    oidc_error = Some(format!("OIDC policy join failed: {e}"));
                    None
                }
            },
        },
    };
    if let Some(ref msg) = oidc_error
        && !is_json_mode()
    {
        eprintln!("  {msg}");
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
            oidc_join,
            error: log_anchor_error.or(oidc_error),
        },
    )
}

/// Resolve the org's KEL-anchored OIDC-subject policy from the local registry.
///
/// The org seals the policy digest on its KEL (`auths org anchor-oidc-policy`);
/// this reads the latest seal, loads the content-addressed blob, and refuses a
/// digest mismatch — the verifier trusts the org's witnessed log, not a file
/// someone handed them. Errors carry the verify exit-code contract: a tampered
/// blob is a verdict (1); everything else is could-not-attempt (2).
fn resolve_anchored_oidc_policy(org_did: &str) -> Result<OidcSubjectPolicy, (i32, String)> {
    use auths_sdk::workflows::org::load_org_oidc_policy;

    let Some(prefix) = org_did.strip_prefix("did:keri:") else {
        return Err((
            2,
            format!("--oidc-policy-did requires a did:keri: identifier, got '{org_did}'"),
        ));
    };
    let auths_home = auths_sdk::paths::auths_home()
        .map_err(|e| (2, format!("Could not locate ~/.auths: {e}")))?;
    let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(&auths_home),
    );
    let org_prefix = auths_verifier::Prefix::new_unchecked(prefix.to_string());

    match load_org_oidc_policy(&registry, &org_prefix) {
        Ok(Some(loaded)) => {
            if !is_json_mode() {
                eprintln!(
                    "  OIDC policy resolved from the org KEL (digest {})",
                    loaded.policy_digest
                );
            }
            Ok(loaded.policy)
        }
        Ok(None) => Err((
            2,
            format!(
                "organization {org_did} has no OIDC-subject policy anchored on its KEL \
                 — anchor one with `auths org anchor-oidc-policy`"
            ),
        )),
        Err(e @ auths_sdk::domains::org::error::OrgError::PolicyIntegrity { .. }) => {
            Err((1, format!("OIDC policy resolution failed: {e}")))
        }
        Err(e) => Err((
            2,
            format!("Failed to resolve the anchored OIDC policy: {e}"),
        )),
    }
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

        // The bundle is attacker-controlled input. Authenticate it into a trust
        // anchor before believing anything it claims. `BundleTrust::parse`
        // enforces freshness + RT-005 self-certification (the bundle's
        // `identity_did` MUST name the inception its KEL carries) + RT-002 KEL
        // signature authentication. RT-005 is what kills the impersonation:
        // without it an attacker could export their OWN valid bundle, rewrite
        // only `identity_did` to a victim's DID, and have the artifact certified
        // "signed by <victim>". The DID and the key material would come from the
        // same forged input.
        let trust = auths_verifier::BundleTrust::parse(&bundle, chrono::Utc::now())
            .map_err(|e| anyhow!("identity bundle is not a trustworthy anchor: {e}"))?;

        // Derive the verification key from the AUTHENTICATED KEL's current
        // key-state — never from the bundle's self-asserted `public_key_hex`,
        // which an attacker can set to any value. Replaying the trusted KEL
        // yields the post-rotation current key and fails closed for an empty KEL
        // (no events → no current key → rejected). Mirrors the stateful resolver
        // (auths-sdk keri::resolver::resolve_current_public_key) on the
        // in-memory KEL.
        let state = auths_keri::TrustedKel::from_trusted_source(trust.kel())
            .replay()
            .map_err(|e| anyhow!("identity bundle KEL is not replayable: {e}"))?;
        let key = state
            .current_key()
            .ok_or_else(|| anyhow!("identity bundle KEL has no current key"))?;
        let (key_bytes, curve) = match key
            .parse()
            .map_err(|e| anyhow!("identity bundle current key is unsupported: {e}"))?
        {
            auths_keri::KeriPublicKey::Ed25519 { key, .. } => {
                (key.to_vec(), auths_crypto::CurveType::Ed25519)
            }
            auths_keri::KeriPublicKey::P256 { key, .. } => {
                (key.to_vec(), auths_crypto::CurveType::P256)
            }
        };
        let pk = auths_verifier::DevicePublicKey::try_new(curve, &key_bytes)
            .map_err(|e| anyhow!("Invalid bundle public key: {e}"))?;

        // The identity_did is now PROVEN equal to the authenticated KEL's
        // inception (RT-005), so it is safe to return as the certified signer.
        let (root_did, _kel) = trust.into_parts();
        Ok((pk, CanonicalDid::new_unchecked(root_did)))
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

/// Resolve a DID's current public key bytes.
///
/// `did:keri:` resolves by replaying the issuer's KEL from the local registry —
/// a KERI prefix is a digest of its inception event, never raw key bytes, and
/// only KEL replay yields the post-rotation *current* key. This is what makes
/// self-verification work: the signer's own KEL is always in the local registry.
/// `did:key:` decodes in-band (the key IS the identifier).
fn resolve_pk_from_did(did: &str) -> Result<(Vec<u8>, auths_crypto::CurveType)> {
    if did.starts_with("did:keri:") {
        let auths_home = auths_sdk::paths::auths_home()
            .map_err(|e| anyhow!("Could not locate ~/.auths: {e}"))?;
        let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
            auths_sdk::storage::RegistryConfig::single_tenant(&auths_home),
        );
        let (pk, curve) = auths_sdk::keri::resolve_current_public_key(&registry, did)?;
        Ok((pk, curve))
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
            oidc_join: None,
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
async fn verify_commit_in_process(sha: &str) -> bool {
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

    // The SSH signature is computed over the commit object's EXACT bytes
    // (what `git cat-file commit <sha>` prints). Read them from the object
    // database — never reconstruct them by joining header/message strings;
    // a single byte of drift makes a valid signature unverifiable.
    let commit_content = match raw_commit_bytes(&repo, oid) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(e) => {
            if !is_json_mode() {
                eprintln!("Commit {} not found: {e}", &sha[..8.min(sha.len())]);
            }
            return false;
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

    let short = &sha[..8.min(sha.len())];
    match auths_sdk::workflows::commit_trust::verify_commit_local(
        &registry,
        &pinned_roots,
        commit_content.as_bytes(),
        &provider,
    )
    .await
    {
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

/// The raw commit object bytes, exactly as `git cat-file commit <oid>` prints
/// them — the payload an SSH commit signature is computed over.
///
/// Args:
/// * `repo`: An open git repository.
/// * `oid`: The commit's object id.
///
/// Usage:
/// ```ignore
/// let bytes = raw_commit_bytes(&repo, oid)?;
/// ```
pub(crate) fn raw_commit_bytes(repo: &git2::Repository, oid: git2::Oid) -> Result<Vec<u8>> {
    let odb = repo.odb().context("open git object database")?;
    let obj = odb.read(oid).context("read commit object")?;
    Ok(obj.data().to_vec())
}

#[cfg(test)]
mod tests {
    use super::raw_commit_bytes;
    use std::process::Command;

    /// Regression: the bytes the verifier checks the SSH signature over must
    /// be byte-identical to `git cat-file commit`. A prior implementation
    /// reconstructed them from raw_header + "\n\n" + message, drifting by one
    /// newline and making every valid signature report SshSignatureInvalid.
    #[test]
    fn raw_commit_bytes_matches_git_cat_file() {
        let (dir, repo) = auths_test_utils::git::init_test_repo();
        let sig = git2::Signature::now("t", "t@example.com").expect("sig");
        let tree_id = {
            let mut index = repo.index().expect("index");
            index.write_tree().expect("tree")
        };
        let tree = repo.find_tree(tree_id).expect("find tree");
        let oid = repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                "subject line\n\nbody with trailing newline drift potential\n",
                &tree,
                &[],
            )
            .expect("commit");

        let via_helper = raw_commit_bytes(&repo, oid).expect("helper");
        let via_git = Command::new("git")
            .args(["cat-file", "commit", &oid.to_string()])
            .current_dir(dir.path())
            .output()
            .expect("git cat-file");
        assert!(via_git.status.success());
        assert_eq!(
            via_helper, via_git.stdout,
            "verifier payload must be byte-identical to git cat-file commit"
        );
    }
}
