pub mod core;
pub mod file;
pub mod oidc;
pub mod publish;
pub mod sign;
pub mod verify;

use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::signing::service::EphemeralSignRequest;
use auths_sdk::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::signing::validate_commit_sha;

#[derive(Args, Debug, Clone)]
#[command(
    about = "Sign and verify arbitrary artifacts (tarballs, binaries, etc.).",
    after_help = "Examples:
  auths artifact sign package.tar.gz     # Sign an artifact
  auths artifact sign package.tar.gz --expires-in 2592000
                                         # Sign with 30-day expiry
  auths artifact verify package.tar.gz.auths.json
                                         # Verify artifact signature
  auths artifact publish package.tar.gz --package npm:react@18.3.0
                                         # Sign and publish to registry

Signature Files:
  Signatures are stored as <file>.auths.json next to the artifact.
  Contains identity, device, and signature information.

Related:
  auths sign    — Sign commits and other files
  auths verify  — Verify signatures
  auths trust   — Manage trusted identities"
)]
pub struct ArtifactCommand {
    #[command(subcommand)]
    pub command: ArtifactSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ArtifactSubcommand {
    /// Sign an artifact file with your Auths identity.
    Sign {
        /// Path to the artifact file to sign.
        #[arg(help = "Path to the artifact file to sign.")]
        file: PathBuf,

        /// Output path for the signature file. Defaults to <FILE>.auths.json.
        #[arg(long = "sig-output", value_name = "PATH")]
        sig_output: Option<PathBuf>,

        /// Local alias of the identity key (used for signing). Omit for CI device-only signing.
        #[arg(
            long,
            help = "Local alias of the identity key. Omit for device-only CI signing."
        )]
        key: Option<String>,

        /// Local alias of the device key (used for dual-signing).
        /// Auto-detected when only one key exists for the identity.
        #[arg(
            long,
            help = "Local alias of the device key. Auto-detected when only one key exists."
        )]
        device_key: Option<String>,

        /// Duration in seconds until expiration (per RFC 6749).
        #[arg(long = "expires-in", value_name = "N")]
        expires_in: Option<u64>,

        /// Optional note to embed in the attestation.
        #[arg(long)]
        note: Option<String>,

        /// Git commit SHA to embed in the attestation (provenance binding; embedded only when given, never inferred from git state).
        #[arg(long, conflicts_with = "no_commit")]
        commit: Option<String>,

        /// Do not embed any commit SHA in the attestation.
        #[arg(long, conflicts_with = "commit")]
        no_commit: bool,

        /// Use ephemeral CI signing (no keychain needed). Requires --commit.
        #[arg(long)]
        ci: bool,

        /// Curve for the ephemeral CI key (`p256` or `ed25519`). Only meaningful
        /// with --ci; defaults to p256.
        #[arg(long, value_name = "CURVE", requires = "ci")]
        curve: Option<auths_crypto::CurveType>,

        /// CI platform override when --ci is used outside a detected CI environment.
        #[arg(long, requires = "ci")]
        ci_platform: Option<String>,

        /// Path to the runner's OIDC token (the keyless exchange: the token is
        /// validated against the issuer's JWKS and the verified claims are
        /// embedded in the signed attestation as an OIDC binding).
        #[arg(
            long,
            value_name = "TOKEN-FILE",
            requires = "ci",
            requires = "oidc_audience"
        )]
        oidc_token: Option<PathBuf>,

        /// Expected OIDC token audience (exact match). Required with --oidc-token.
        #[arg(long, value_name = "AUD", requires = "oidc_token")]
        oidc_audience: Option<String>,

        /// Expected OIDC token issuer (exact match).
        #[arg(
            long,
            value_name = "URL",
            requires = "oidc_token",
            default_value = oidc::DEFAULT_OIDC_ISSUER
        )]
        oidc_issuer: String,

        /// Pinned JWKS file for offline/air-gapped token validation
        /// (default: fetch the issuer's published JWKS over HTTPS).
        #[arg(long, value_name = "JWKS-FILE", requires = "oidc_token")]
        oidc_jwks: Option<PathBuf>,

        /// Transparency log to submit to (overrides default from trust config).
        #[arg(long, value_name = "LOG_ID")]
        log: Option<String>,

        /// Skip transparency log submission (local testing only).
        /// Produces an unlogged attestation that verifiers reject by default.
        #[arg(long)]
        allow_unlogged: bool,
    },

    /// Sign and publish an artifact attestation to a registry.
    ///
    /// Auto-signs the artifact when no --signature is provided.
    Publish {
        /// Artifact file to sign and publish (auto-signs if no --signature).
        #[arg(help = "Artifact file to sign and publish (auto-signs if no --signature).")]
        file: Option<PathBuf>,

        /// Path to an existing .auths.json signature file. Defaults to <FILE>.auths.json.
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,

        /// Package identifier for registry indexing (e.g., npm:react@18.3.0).
        #[arg(long)]
        package: Option<String>,

        /// Registry URL to publish to.
        #[arg(long, env = "AUTHS_REGISTRY_URL", default_value = DEFAULT_REGISTRY_URL)]
        registry: String,

        /// Local alias of the identity key. Omit for device-only CI signing.
        #[arg(long)]
        key: Option<String>,

        /// Local alias of the device key. Auto-detected when only one key exists.
        #[arg(long)]
        device_key: Option<String>,

        /// Duration in seconds until expiration.
        #[arg(long = "expires-in", value_name = "N")]
        expires_in: Option<u64>,

        /// Optional note to embed in the attestation.
        #[arg(long)]
        note: Option<String>,

        /// Git commit SHA to embed in the attestation (provenance binding; embedded only when given, never inferred from git state).
        #[arg(long, conflicts_with = "no_commit")]
        commit: Option<String>,

        /// Do not embed any commit SHA in the attestation.
        #[arg(long, conflicts_with = "commit")]
        no_commit: bool,
    },

    /// Verify an artifact's signature against an Auths identity.
    Verify {
        /// Path to the artifact file to verify.
        #[arg(help = "Path to the artifact file to verify.")]
        file: PathBuf,

        /// Path to the signature file. Defaults to <FILE>.auths.json.
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,

        /// Path to identity bundle JSON (for CI/CD stateless verification).
        #[arg(long, value_parser)]
        identity_bundle: Option<PathBuf>,

        /// Path to witness signatures JSON file.
        #[arg(long = "witness-signatures")]
        witness_receipts: Option<PathBuf>,

        /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
        #[arg(long, num_args = 1..)]
        witness_keys: Vec<String>,

        /// Number of witnesses required (default: 1).
        #[arg(long = "witnesses-required", default_value = "1")]
        witness_threshold: usize,

        /// Also verify the source commit's signing attestation.
        #[arg(long)]
        verify_commit: bool,

        /// For an ephemeral (`did:key:`) attestation, confirm the signature over
        /// the artifact digest WITHOUT chasing the commit-anchor leg. This is the
        /// runner's self-check: it has no maintainer repo/roots, but it can prove
        /// it signed what it emitted. A pass means "digest matches, ephemeral key
        /// signed it", not "the signer trust-chains to a maintainer".
        #[arg(long, conflicts_with = "verify_commit")]
        signature_only: bool,

        /// Verify an air-gapped org bundle entirely offline (no network access).
        #[arg(long)]
        offline: bool,

        /// Override the pinned trust roots path (default: `.auths/roots`).
        #[arg(long, value_name = "PATH")]
        roots: Option<PathBuf>,

        /// (offline) Member `did:keri` to classify authority for.
        #[arg(long = "member", visible_alias = "member-did")]
        member: Option<String>,

        /// (offline) The artifact's in-band signing KEL position.
        #[arg(long)]
        signed_at: Option<u128>,

        /// (offline) Emit the typed verdict as JSON.
        #[arg(long)]
        json: bool,

        /// OIDC-subject policy file to JOIN against the attestation's signed
        /// OIDC binding (issuer + repository [+ workflow_ref] the org trusts).
        /// Fail-closed: a missing binding or any mismatch fails verification.
        #[arg(long, value_name = "POLICY-FILE")]
        oidc_policy: Option<PathBuf>,

        /// Resolve the OIDC-subject policy from the org's KEL instead of a
        /// pinned file: reads the latest policy digest the org anchored
        /// (`auths org anchor-oidc-policy`) from the local registry and refuses
        /// a digest mismatch — the witnessed log is the source of truth.
        #[arg(long, value_name = "ORG-DID", conflicts_with = "oidc_policy")]
        oidc_policy_did: Option<String>,

        /// Offline transparency-log inclusion evidence for this artifact
        /// (`auths log prove --out`). Verified fully offline; the verdict's
        /// `anchored` field reports the outcome. Requires --log-key — an
        /// inclusion proof without a pinned operator proves nothing.
        #[arg(long, value_name = "EVIDENCE-FILE", requires = "log_key")]
        log_evidence: Option<PathBuf>,

        /// The log operator's Ed25519 public key (64 hex chars), pinned out
        /// of band — never trusted from the evidence file itself.
        #[arg(long, value_name = "HEX", requires = "log_evidence")]
        log_key: Option<String>,

        /// Require the verified signer to be exactly this identity (e.g. a release
        /// signer). Fails closed on a signer mismatch — an allowlist applied after
        /// verification, it can only narrow a valid verdict, never widen it.
        #[arg(long = "expect-signer", value_name = "DID")]
        expect_signer: Option<String>,
        /// Require the verified signer to be a rooted did:keri identity (a rotatable, revocable
        /// key-state log), rejecting a bare did:key self-attestation. Fails closed; applied after
        /// verification, it can only narrow a valid verdict, never widen it.
        #[arg(long = "require-rooted-signer")]
        require_rooted_signer: bool,
    },
}

fn is_rate_limited(err: &auths_sdk::workflows::log_submit::LogSubmitError) -> bool {
    matches!(
        err,
        auths_sdk::workflows::log_submit::LogSubmitError::LogError(
            auths_sdk::ports::LogError::RateLimited { .. }
        )
    )
}

fn rate_limit_secs(err: &auths_sdk::workflows::log_submit::LogSubmitError) -> u64 {
    match err {
        auths_sdk::workflows::log_submit::LogSubmitError::LogError(
            auths_sdk::ports::LogError::RateLimited { retry_after_secs },
        ) => *retry_after_secs,
        _ => 10,
    }
}

/// Re-export DSSE PAE from the SDK for use in CLI signing paths.
pub use auths_sdk::domains::signing::service::dsse_pae;

/// Submit an attestation to a transparency log and return the JSON to embed.
///
/// The `dsse_signature` is the signature over the DSSE PAE of the attestation,
/// computed by the caller while the signing key is still available.
///
/// Returns `None` if `allow_unlogged` is set or `--log` wasn't passed.
fn submit_to_log(
    attestation_json: &str,
    log: &Option<String>,
    allow_unlogged: bool,
    dsse_signature: Option<&[u8]>,
) -> Result<Option<serde_json::Value>> {
    if allow_unlogged {
        eprintln!(
            "WARNING: Signing without transparency log. \
             This artifact will not be verifiable against any log."
        );
        return Ok(None);
    }

    // If --log wasn't passed, skip silently (non-CI default behavior)
    if log.is_none() {
        return Ok(None);
    }

    let sig_bytes = dsse_signature
        .ok_or_else(|| anyhow::anyhow!("DSSE signature required for log submission"))?;

    let attestation_value: serde_json::Value = serde_json::from_str(attestation_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse attestation: {e}"))?;

    // device_public_key may be a hex string or {"curve": "...", "key": "..."}
    let pk_hex = if let Some(s) = attestation_value["device_public_key"].as_str() {
        s.to_string()
    } else if let Some(key_field) = attestation_value["device_public_key"]["key"].as_str() {
        key_field.to_string()
    } else {
        return Err(anyhow::anyhow!("missing device_public_key"));
    };
    let pk_bytes =
        hex::decode(&pk_hex).map_err(|e| anyhow::anyhow!("invalid public key hex: {e}"))?;

    let pk_curve = match attestation_value["device_public_key"]["curve"].as_str() {
        Some("ed25519") | Some("Ed25519") => auths_crypto::CurveType::Ed25519,
        _ => auths_crypto::CurveType::P256,
    };

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {e}"))?;

    let log_client: std::sync::Arc<dyn auths_sdk::ports::TransparencyLog> = match log.as_deref() {
        Some("sigstore-rekor") => std::sync::Arc::new(
            auths_infra_rekor::RekorClient::public()
                .map_err(|e| anyhow::anyhow!("Failed to create Rekor client: {e}"))?,
        ),
        Some(other) => bail!("Unknown log '{}'. Available: sigstore-rekor", other),
        None => unreachable!(),
    };

    let submit = || {
        rt.block_on(auths_sdk::workflows::log_submit::submit_attestation_to_log(
            attestation_json.as_bytes(),
            &pk_bytes,
            pk_curve,
            sig_bytes,
            log_client.as_ref(),
        ))
    };

    let submission_result = match submit() {
        Ok(bundle) => Ok(bundle),
        Err(ref e) if is_rate_limited(e) => {
            let secs = rate_limit_secs(e);
            eprintln!("Rate limited by transparency log. Retrying in {secs}s...");
            std::thread::sleep(std::time::Duration::from_secs(secs));
            submit()
        }
        Err(e) => Err(e),
    };

    match submission_result {
        Ok(bundle) => {
            eprintln!(
                "  Logged to {} at index {}",
                bundle.log_id, bundle.leaf_index
            );
            Ok(Some(serde_json::to_value(&bundle).map_err(|e| {
                anyhow::anyhow!("Failed to serialize: {e}")
            })?))
        }
        Err(e) => Err(anyhow::anyhow!("Transparency log submission failed: {e}")),
    }
}

/// Merge transparency JSON into an attestation and return the final JSON string.
fn merge_transparency(attestation_json: &str, transparency: serde_json::Value) -> Result<String> {
    let mut attestation: serde_json::Value = serde_json::from_str(attestation_json)
        .map_err(|e| anyhow::anyhow!("Failed to re-parse attestation: {e}"))?;
    if let serde_json::Value::Object(ref mut map) = attestation {
        map.insert("transparency".to_string(), transparency);
    }
    serde_json::to_string_pretty(&attestation)
        .map_err(|e| anyhow::anyhow!("Failed to serialize attestation: {e}"))
}

/// Resolve the commit SHA from CLI flags.
fn resolve_commit_sha_from_flags(
    commit: Option<String>,
    no_commit: bool,
) -> Result<Option<String>> {
    if no_commit {
        return Ok(None);
    }
    // A commit SHA records provenance ("this artifact is the subject of that commit"), so
    // it is bound only when explicitly given with --commit. It is never inferred from the
    // ambient git HEAD, which would conflate "I signed this file" with "this file came
    // from the surrounding commit".
    commit
        .map(|sha| validate_commit_sha(&sha).map_err(anyhow::Error::from))
        .transpose()
}

/// Handle the `artifact` command dispatch.
pub fn handle_artifact(
    cmd: ArtifactCommand,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    match cmd.command {
        ArtifactSubcommand::Sign {
            file,
            sig_output,
            key,
            device_key,
            expires_in,
            note,
            commit,
            no_commit,
            ci,
            curve,
            ci_platform,
            oidc_token,
            oidc_audience,
            oidc_issuer,
            oidc_jwks,
            log,
            allow_unlogged,
        } => {
            if ci {
                // Ephemeral CI signing — no keychain, no passphrase
                use auths_sdk::domains::signing::ci_env::{
                    CiEnvironment, CiPlatform, detect_ci_environment,
                };

                let commit_sha = match commit {
                    Some(sha) => sha,
                    None => bail!("--ci requires --commit <sha>. Pass the commit SHA explicitly."),
                };

                // Explicit --ci-platform takes precedence over auto-detection so
                // tests can opt out of the CI runner's auto-detected platform.
                let ci_env = match ci_platform.as_deref() {
                    Some("local") => CiEnvironment {
                        platform: CiPlatform::Local,
                        repository: None,
                        workflow_ref: None,
                        sha: None,
                        run_id: None,
                        actor: None,
                        runner_os: None,
                    },
                    Some(name) => CiEnvironment {
                        platform: CiPlatform::Generic,
                        repository: None,
                        workflow_ref: None,
                        sha: None,
                        run_id: None,
                        actor: None,
                        runner_os: Some(name.to_string()),
                    },
                    None => match detect_ci_environment() {
                        Some(env) => env,
                        None => bail!(
                            "No CI environment detected. If this is intentional (e.g., testing), \
                             pass --ci-platform local. Otherwise run inside GitHub Actions, \
                             GitLab CI, or a recognized CI runner."
                        ),
                    },
                };

                let ci_env_json = serde_json::to_value(&ci_env)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize CI env: {}", e))?;

                let data = std::fs::read(&file)
                    .with_context(|| format!("Failed to read artifact {:?}", file))?;
                let artifact_name = file.file_name().map(|n| n.to_string_lossy().to_string());

                #[allow(clippy::disallowed_methods)]
                let now = chrono::Utc::now();

                // The keyless exchange, sign side: validate the runner's OIDC
                // token and embed the verified claims in the signed envelope.
                let oidc_binding = match &oidc_token {
                    Some(token_path) => {
                        let audience = oidc_audience.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "--oidc-token requires --oidc-audience <AUD> \
                                 (the audience the token was minted for)"
                            )
                        })?;
                        let binding = oidc::resolve_oidc_binding(
                            token_path,
                            &oidc_issuer,
                            audience,
                            oidc_jwks.as_deref(),
                            &ci_env.platform,
                            now,
                        )?;
                        eprintln!(
                            "  OIDC identity verified: {} (issuer {})",
                            binding.subject, binding.issuer
                        );
                        Some(binding)
                    }
                    None => None,
                };

                let result = auths_sdk::domains::signing::service::sign_artifact_ephemeral(
                    now,
                    EphemeralSignRequest {
                        data: &data,
                        artifact_name,
                        commit_sha,
                        curve: curve.unwrap_or_default(),
                        expires_in,
                        note,
                        ci_env: Some(ci_env_json),
                        oidc_binding,
                    },
                )
                .map_err(|e| anyhow::anyhow!("Ephemeral signing failed: {}", e))?;

                // Submit to transparency log (unless --allow-unlogged)
                let transparency_json = submit_to_log(
                    &result.attestation_json,
                    &log,
                    allow_unlogged,
                    result.dsse_signature.as_deref(),
                )?;

                let final_json = if let Some(transparency) = transparency_json {
                    merge_transparency(&result.attestation_json, transparency)?
                } else {
                    result.attestation_json.clone()
                };

                let output_path = sig_output.unwrap_or_else(|| {
                    let mut p = file.clone();
                    let new_name = format!(
                        "{}.auths.json",
                        p.file_name().unwrap_or_default().to_string_lossy()
                    );
                    p.set_file_name(new_name);
                    p
                });

                std::fs::write(&output_path, &final_json)
                    .with_context(|| format!("Failed to write signature to {:?}", output_path))?;

                println!(
                    "Signed {:?} -> {:?} (ephemeral CI key)",
                    file.file_name().unwrap_or_default(),
                    output_path
                );
                println!("  RID:    {}", result.rid);
                println!("  Digest: sha256:{}", result.digest);

                Ok(())
            } else {
                // Standard device-key signing
                let commit_sha = resolve_commit_sha_from_flags(commit, no_commit)?;
                let resolved_alias = match device_key {
                    Some(alias) => alias,
                    None => crate::commands::key_detect::auto_detect_device_key(
                        repo_opt.as_deref(),
                        env_config,
                    )?,
                };
                sign::handle_sign(
                    &file,
                    sig_output,
                    key.as_deref(),
                    &resolved_alias,
                    expires_in,
                    note,
                    commit_sha,
                    repo_opt,
                    passphrase_provider,
                    env_config,
                    &log,
                    allow_unlogged,
                )
            }
        }
        ArtifactSubcommand::Publish {
            file,
            signature,
            package,
            registry,
            key,
            device_key,
            expires_in,
            note,
            commit,
            no_commit,
        } => {
            let commit_sha = resolve_commit_sha_from_flags(commit, no_commit)?;
            let sig_path = match (signature, file.as_ref()) {
                (Some(sig), _) => sig,
                (None, Some(artifact)) => {
                    let default_sig = derive_signature_path(artifact);
                    if default_sig.exists() {
                        default_sig
                    } else {
                        let resolved_alias = match device_key {
                            Some(alias) => alias,
                            None => crate::commands::key_detect::auto_detect_device_key(
                                repo_opt.as_deref(),
                                env_config,
                            )?,
                        };
                        sign::handle_sign(
                            artifact,
                            None,
                            key.as_deref(),
                            &resolved_alias,
                            expires_in,
                            note,
                            commit_sha,
                            repo_opt.clone(),
                            passphrase_provider,
                            env_config,
                            &None,
                            false,
                        )?;
                        default_sig
                    }
                }
                (None, None) => bail!(
                    "Provide an artifact file to sign-and-publish, or --signature for an existing signature"
                ),
            };
            publish::handle_publish(&sig_path, package.as_deref(), &registry)
        }
        ArtifactSubcommand::Verify {
            file,
            signature,
            identity_bundle,
            witness_receipts,
            witness_keys,
            witness_threshold,
            verify_commit,
            signature_only,
            offline,
            roots,
            member,
            signed_at,
            json,
            oidc_policy,
            oidc_policy_did,
            log_evidence,
            log_key,
            expect_signer,
            require_rooted_signer,
        } => {
            if offline {
                return verify::handle_offline_verify(
                    &file,
                    roots.as_deref(),
                    member.as_deref(),
                    signed_at,
                    json,
                );
            }
            let ephemeral_anchor = if signature_only {
                verify::EphemeralAnchor::SignatureOnly
            } else {
                verify::EphemeralAnchor::Required
            };
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(verify::handle_verify(
                &file,
                verify::VerifyArtifactArgs {
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
                    expect_signer,
                    require_rooted_signer,
                },
            ))
        }
    }
}

fn derive_signature_path(file: &Path) -> PathBuf {
    let mut p = file.to_path_buf();
    let new_name = format!(
        "{}.auths.json",
        p.file_name().unwrap_or_default().to_string_lossy()
    );
    p.set_file_name(new_name);
    p
}

impl crate::commands::executable::ExecutableCommand for ArtifactCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_artifact(
            self.clone(),
            ctx.repo_path.clone(),
            ctx.passphrase_provider.clone(),
            &ctx.env_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: ArtifactSubcommand,
    }

    #[test]
    fn derive_signature_path_appends_auths_json() {
        let path = derive_signature_path(Path::new("/tmp/my-pkg-1.0.0.tar.gz"));
        assert_eq!(path, PathBuf::from("/tmp/my-pkg-1.0.0.tar.gz.auths.json"));
    }

    #[test]
    fn derive_signature_path_handles_bare_filename() {
        let path = derive_signature_path(Path::new("artifact.bin"));
        assert_eq!(path, PathBuf::from("artifact.bin.auths.json"));
    }

    #[test]
    fn publish_accepts_file_positional_arg() {
        let cli = Cli::try_parse_from(["test", "publish", "my-file.tar.gz"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert_eq!(file, Some(PathBuf::from("my-file.tar.gz")));
                assert!(signature.is_none());
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_signature_flag_without_file() {
        let cli =
            Cli::try_parse_from(["test", "publish", "--signature", "my-file.auths.json"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert!(file.is_none());
                assert_eq!(signature, Some(PathBuf::from("my-file.auths.json")));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_both_file_and_signature() {
        let cli = Cli::try_parse_from([
            "test",
            "publish",
            "my-file.tar.gz",
            "--signature",
            "custom.auths.json",
        ])
        .unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert_eq!(file, Some(PathBuf::from("my-file.tar.gz")));
                assert_eq!(signature, Some(PathBuf::from("custom.auths.json")));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_no_args() {
        let cli = Cli::try_parse_from(["test", "publish"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert!(file.is_none());
                assert!(signature.is_none());
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn verify_oidc_policy_did_conflicts_with_policy_file() {
        // A pinned file and a KEL-resolved policy are two trust postures —
        // exactly one may be chosen.
        let err = Cli::try_parse_from([
            "test",
            "verify",
            "a.tar.gz",
            "--oidc-policy",
            "p.json",
            "--oidc-policy-did",
            "did:keri:EOrg",
        ]);
        assert!(err.is_err(), "the two policy sources must be exclusive");

        let ok = Cli::try_parse_from([
            "test",
            "verify",
            "a.tar.gz",
            "--oidc-policy-did",
            "did:keri:EOrg",
        ])
        .unwrap();
        match ok.command {
            ArtifactSubcommand::Verify {
                oidc_policy,
                oidc_policy_did,
                ..
            } => {
                assert!(oidc_policy.is_none());
                assert_eq!(oidc_policy_did.as_deref(), Some("did:keri:EOrg"));
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn verify_log_evidence_and_log_key_are_a_pair() {
        // An inclusion proof without a pinned operator key proves nothing,
        // and a pinned key with nothing to check is operator error — clap
        // enforces both-or-neither.
        assert!(
            Cli::try_parse_from(["test", "verify", "a.tar.gz", "--log-evidence", "e.json"])
                .is_err(),
            "--log-evidence without --log-key must be rejected"
        );
        assert!(
            Cli::try_parse_from(["test", "verify", "a.tar.gz", "--log-key", "ab12"]).is_err(),
            "--log-key without --log-evidence must be rejected"
        );

        let ok = Cli::try_parse_from([
            "test",
            "verify",
            "a.tar.gz",
            "--log-evidence",
            "e.json",
            "--log-key",
            "ab12",
        ])
        .unwrap();
        match ok.command {
            ArtifactSubcommand::Verify {
                log_evidence,
                log_key,
                ..
            } => {
                assert_eq!(log_evidence, Some(PathBuf::from("e.json")));
                assert_eq!(log_key.as_deref(), Some("ab12"));
            }
            _ => panic!("expected Verify"),
        }
    }

    #[test]
    fn publish_forwards_signing_flags() {
        let cli = Cli::try_parse_from([
            "test",
            "publish",
            "my-file.tar.gz",
            "--key",
            "main",
            "--device-key",
            "device-1",
            "--expires-in",
            "3600",
            "--note",
            "release build",
        ])
        .unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                key,
                device_key,
                expires_in,
                note,
                ..
            } => {
                assert_eq!(key.as_deref(), Some("main"));
                assert_eq!(device_key.as_deref(), Some("device-1"));
                assert_eq!(expires_in, Some(3600));
                assert_eq!(note.as_deref(), Some("release build"));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn commit_sha_is_not_inferred_from_ambient_git_state() {
        // Signing without --commit must embed NO commit SHA — never the ambient HEAD of
        // whatever git tree surrounds the file, which would conflate "I signed this file"
        // with "this file came from that commit". (This test runs inside a git repo, so a
        // fallback to HEAD would resolve to a real SHA here.)
        let resolved = resolve_commit_sha_from_flags(None, false).unwrap();
        assert_eq!(
            resolved, None,
            "no --commit must embed no commit_sha, got {resolved:?}"
        );
    }

    #[test]
    fn explicit_commit_sha_is_bound() {
        let sha = "a".repeat(40);
        let resolved = resolve_commit_sha_from_flags(Some(sha.clone()), false).unwrap();
        assert_eq!(resolved, Some(sha));
    }

    #[test]
    fn no_commit_flag_embeds_nothing() {
        assert_eq!(resolve_commit_sha_from_flags(None, true).unwrap(), None);
    }
}
