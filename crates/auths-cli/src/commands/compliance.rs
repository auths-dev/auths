//! `auths compliance` — compliance-as-a-query evidence packs.
//!
//! Thin presentation layer over [`auths_sdk::workflows::compliance`]: it reads the
//! period's releases (from a caller file, or **discovered** from the release
//! attestations anchored in the org KEL), calls the SDK query engine to classify
//! each signer's authority **at release** (by KEL position), embeds the honest
//! witness verdict, optionally embeds the org KEL bundle for offline verification,
//! and optionally org-signs the pack as a DSSE-wrapped in-toto statement.
//! `compliance attest` is the signing-time half: it anchors the release fact so the
//! report can derive it. No domain logic lives here.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};

use auths_crypto::CurveType;
use auths_sdk::context::AuthsContext;
use auths_sdk::keychain::{KeyAlias, extract_public_key_bytes};
use auths_sdk::storage_layout::layout;
use auths_sdk::workflows::compliance::{
    ArtifactDigest, ComplianceFramework, ReleaseRecord, TransparencyInclusion,
    VerifiedEvidencePack, VsaParams, attest_release, build_evidence_pack, build_framework_report,
    build_offline_evidence_pack, discover_releases, load_witness_policy, sign_evidence_pack,
    sign_framework_report, verify_signed_evidence_pack_offline,
};
use auths_sdk::workflows::roots::parse_roots_typed;
use auths_verifier::{Ed25519PublicKey, IdentityDID, Prefix};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, Output, is_json_mode};

/// Default keychain alias for an org's signing key (`org-{slug}`), matching the
/// `auths org` convention.
fn org_slug_alias(org: &str) -> String {
    format!(
        "org-{}",
        org.chars()
            .filter(|c| c.is_alphanumeric())
            .take(20)
            .collect::<String>()
            .to_lowercase()
    )
}

/// Resolve the org signing alias (defaulting to the slug alias) and its in-band curve.
fn resolve_org_signing(
    sdk_ctx: &AuthsContext,
    org: &str,
    key: Option<String>,
) -> Result<(KeyAlias, CurveType)> {
    let org_alias = KeyAlias::new_unchecked(key.unwrap_or_else(|| org_slug_alias(org)));
    let (_pk, curve) = extract_public_key_bytes(
        sdk_ctx.key_storage.as_ref(),
        &org_alias,
        sdk_ctx.passphrase_provider.as_ref(),
    )
    .with_context(|| format!("Failed to resolve org signing key '{org_alias}'"))?;
    Ok((org_alias, curve))
}

/// Hash an artifact file with SHA-256 into a parsed `sha256:<hex>` digest.
fn file_artifact_digest(path: &Path) -> Result<ArtifactDigest> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).with_context(|| format!("Failed to read artifact file {path:?}"))?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    ArtifactDigest::parse(&digest).map_err(|e| anyhow!("computed digest rejected: {e}"))
}

/// One release entry in the `--releases` JSON file. `signer` accepts a `did:keri:`
/// or a bare KEL prefix; `transparency` is the optional log inclusion evidence.
#[derive(Debug, Clone, serde::Deserialize)]
struct ReleaseInput {
    artifact_digest: String,
    signer: String,
    #[serde(default)]
    signed_at: Option<u128>,
    #[serde(default)]
    transparency: Option<TransparencyInclusion>,
}

impl ReleaseInput {
    fn into_record(self) -> ReleaseRecord {
        let signer_prefix = Prefix::new_unchecked(
            self.signer
                .strip_prefix("did:keri:")
                .unwrap_or(&self.signer)
                .to_string(),
        );
        ReleaseRecord {
            artifact_digest: self.artifact_digest,
            signer_prefix,
            signed_at: self.signed_at,
            transparency: self.transparency,
        }
    }
}

/// CLI wrapper for the target compliance framework.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliFramework {
    /// SLSA provenance.
    Slsa,
    /// SPDX software bill of materials.
    Sbom,
    /// EU Cyber Resilience Act obligation mapping.
    Cra,
    /// SOC 2 Trust Services Criteria (TSC) control mapping.
    Soc2,
    /// ISO/IEC 27001:2022 Annex-A control mapping.
    Iso27001,
}

impl From<CliFramework> for ComplianceFramework {
    fn from(f: CliFramework) -> Self {
        match f {
            CliFramework::Slsa => ComplianceFramework::Slsa,
            CliFramework::Sbom => ComplianceFramework::Sbom,
            CliFramework::Cra => ComplianceFramework::Cra,
            CliFramework::Soc2 => ComplianceFramework::Soc2,
            CliFramework::Iso27001 => ComplianceFramework::Iso27001,
        }
    }
}

/// The `compliance` subcommand: compliance as a query over the org's event log.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Compliance as a query — offline-verifiable evidence packs",
    after_help = "Examples:
  auths compliance attest --org did:keri:EOrg --artifact dist/cli-v2.4.0.tar.gz \\
      --signer did:keri:EMember
                        # At signing time: anchor the release (artifact digest +
                        # signer) in the org KEL — the position becomes log fact

  auths compliance report --org did:keri:EOrg --period 2026-Q3 \\
      --framework slsa --discover --offline --out acme-2026Q3.evidence
                        # Build an offline-verifiable evidence pack from the
                        # releases anchored in the org KEL (signed_at derived)

  auths compliance verify --pack acme-2026Q3.evidence --roots auths-roots \\
      --log-key auths-log.pub
                        # Auditor-side: verify a signed pack offline (exit 0
                        # authentic / exit 1 rejected) — no account, no network.
                        # --log-key pins the log operator: every row's checkpoint
                        # signature must verify, not just its Merkle membership

Releases file (JSON array, caller-asserted alternative to --discover):
  [{\"artifact_digest\":\"sha256:…\",\"signer\":\"did:keri:EMember\",\"signed_at\":41}]"
)]
pub struct ComplianceCommand {
    #[clap(subcommand)]
    pub subcommand: ComplianceSubcommand,
}

/// Subcommands for compliance queries.
#[derive(Subcommand, Debug, Clone)]
pub enum ComplianceSubcommand {
    /// Anchor a release attestation (artifact digest + signer) in the org KEL —
    /// the signing position becomes part of the tamper-evident log
    #[command(group(clap::ArgGroup::new("artifact_source").required(true)))]
    Attest {
        /// Organization identity ID (`did:keri:…`) or bare prefix
        #[arg(long)]
        org: String,

        /// Artifact file to hash (sha256) and attest
        #[arg(long, group = "artifact_source")]
        artifact: Option<PathBuf>,

        /// Pre-computed artifact digest (`sha256:<64 hex>`)
        #[arg(long, group = "artifact_source")]
        digest: Option<String>,

        /// The signing member's identity (`did:keri:…`) or bare prefix
        #[arg(long)]
        signer: String,

        /// Org signing key alias (defaults to the org slug alias)
        #[arg(long)]
        key: Option<String>,
    },

    /// Produce a compliance evidence pack for a reporting period.
    #[command(group(clap::ArgGroup::new("release_source").required(true)))]
    Report {
        /// Organization identity ID (`did:keri:…`) or bare prefix
        #[arg(long)]
        org: String,

        /// Reporting period label (free-form, e.g. `2026-Q3`)
        #[arg(long)]
        period: String,

        /// Target framework (tags the pack; with `--predicate`, selects the
        /// rendered predicate: SLSA provenance+VSA / SPDX SBOM / CRA mapping /
        /// SOC 2 TSC mapping / ISO 27001 Annex-A mapping)
        #[arg(long, value_enum, default_value = "slsa")]
        framework: CliFramework,

        /// Render the framework predicate (in-toto Statement) instead of the raw pack
        #[arg(long)]
        predicate: bool,

        /// Verifier id recorded in the SLSA VSA (with `--predicate --framework slsa`)
        #[arg(long, default_value = "https://auths.dev/compliance")]
        verifier_id: String,

        /// JSON file: array of `{ artifact_digest, signer, signed_at?, transparency? }`
        /// — caller-asserted positions (alternative to `--discover`)
        #[arg(long, group = "release_source")]
        releases: Option<PathBuf>,

        /// Derive the rows from the release attestations anchored in the org KEL
        /// (`compliance attest`); each row's `signed_at` IS its anchoring position
        #[arg(long, group = "release_source")]
        discover: bool,

        /// Embed the org KEL bundle so each row verifies offline (no network)
        #[arg(long)]
        offline: bool,

        /// Org-sign the pack as a DSSE-wrapped in-toto statement
        #[arg(long)]
        sign: bool,

        /// Org signing key alias (defaults to the org slug alias); used with `--sign`
        #[arg(long)]
        key: Option<String>,

        /// Pinned witness-policy path (default: `$AUTHS_WITNESS_POLICY_PATH`, else fail-closed)
        #[arg(long)]
        witness_policy: Option<PathBuf>,

        /// Output file (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a DSSE-signed evidence pack offline — no account, no network, no keychain
    Verify {
        /// The DSSE-signed pack file (from `compliance report --offline --sign`)
        #[arg(long)]
        pack: PathBuf,

        /// Pinned trust-roots file (one `did:keri:…` per line) — the only trust input
        #[arg(long)]
        roots: PathBuf,

        /// Pinned log-operator key file (one hex Ed25519 key, `#` comments
        /// allowed). When given, every row's transparency checkpoint must be
        /// SIGNED by this operator — "in the log" becomes operator-attested
        /// non-repudiation, not bare Merkle membership
        #[arg(long)]
        log_key: Option<PathBuf>,
    },
}

/// Parse a pinned log-operator key file: the first non-empty, non-comment line,
/// as a 64-hex-char Ed25519 public key. Fail-closed on anything else.
fn parse_pinned_log_key(path: &Path) -> Result<Ed25519PublicKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pinned log-key file {path:?}"))?;
    let line = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("pinned log-key file {path:?} contains no key"))?;
    let bytes = hex::decode(line)
        .map_err(|e| anyhow!("pinned log-key file {path:?} is not valid hex: {e}"))?;
    Ed25519PublicKey::try_from_slice(&bytes)
        .map_err(|e| anyhow!("pinned log-key file {path:?} rejected: {e}"))
}

/// Handle `auths compliance` subcommands.
///
/// Args:
/// * `cmd`: The parsed compliance command.
/// * `ctx`: The CLI config (repo path, passphrase provider, env).
/// * `now`: The presentation-boundary timestamp (injected into the pack).
///
/// Usage:
/// ```ignore
/// handle_compliance(cmd, ctx, Utc::now())?;
/// ```
pub fn handle_compliance(
    cmd: ComplianceCommand,
    ctx: &CliConfig,
    now: DateTime<Utc>,
) -> Result<()> {
    match cmd.subcommand {
        ComplianceSubcommand::Attest {
            org,
            artifact,
            digest,
            signer,
            key,
        } => {
            let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let signer_prefix = Prefix::new_unchecked(
                signer
                    .strip_prefix("did:keri:")
                    .unwrap_or(&signer)
                    .to_string(),
            );

            let artifact_digest = match (&artifact, &digest) {
                (Some(path), None) => file_artifact_digest(path)?,
                (None, Some(d)) => {
                    ArtifactDigest::parse(d).map_err(|e| anyhow!("invalid --digest value: {e}"))?
                }
                _ => unreachable!("clap requires exactly one of --artifact/--digest"),
            };

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(ctx.passphrase_provider.clone()),
            )?;
            let (org_alias, _curve) = resolve_org_signing(&sdk_ctx, &org, key)?;
            let anchored = attest_release(
                &sdk_ctx,
                &org_prefix,
                &org_alias,
                artifact_digest,
                signer_prefix,
            )
            .context("Failed to anchor the release attestation in the org KEL")?;

            if is_json_mode() {
                JsonResponse {
                    success: true,
                    command: "compliance attest".to_string(),
                    data: Some(serde_json::json!({
                        "org": format!("did:keri:{}", org_prefix.as_str()),
                        "artifact_digest": anchored.artifact_digest.as_str(),
                        "signer": format!("did:keri:{}", anchored.signer.as_str()),
                        "signed_at": anchored.signed_at.to_string(),
                        "attestation_said": anchored.attestation_said.as_str(),
                    })),
                    error: None,
                }
                .print()?;
            } else {
                let out = Output::stdout();
                println!(
                    "{}",
                    out.success("Release attestation anchored in the org KEL")
                );
                println!("  Artifact:  {}", anchored.artifact_digest);
                println!("  Signer:    did:keri:{}", anchored.signer.as_str());
                println!("  Signed at: org KEL seq {}", anchored.signed_at);
                println!("  SAID:      {}", anchored.attestation_said.as_str());
            }
            Ok(())
        }

        ComplianceSubcommand::Report {
            org,
            period,
            framework,
            predicate,
            verifier_id,
            releases,
            discover,
            offline,
            sign,
            key,
            witness_policy,
            out,
        } => {
            let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
            let passphrase_provider = ctx.passphrase_provider.clone();

            let org_prefix =
                Prefix::new_unchecked(org.strip_prefix("did:keri:").unwrap_or(&org).to_string());
            let org_did = IdentityDID::from_prefix(org_prefix.as_str())
                .map_err(|e| anyhow!("invalid org identifier '{org}': {e}"))?;

            let policy_path = witness_policy.or_else(|| {
                std::env::var("AUTHS_WITNESS_POLICY_PATH")
                    .ok()
                    .map(PathBuf::from)
            });
            let policy_result = load_witness_policy(policy_path.as_deref());

            let sdk_ctx = build_auths_context(
                &repo_path,
                &ctx.env_config,
                Some(passphrase_provider.clone()),
            )?;

            let records: Vec<ReleaseRecord> = if discover {
                discover_releases(sdk_ctx.registry.as_ref(), &org_prefix)
                    .context("Failed to discover anchored releases from the org KEL")?
            } else {
                // clap's release_source group guarantees one of the two is set.
                let Some(releases) = releases else {
                    return Err(anyhow!("one of --releases or --discover is required"));
                };
                let raw = fs::read_to_string(&releases)
                    .with_context(|| format!("Failed to read releases file {releases:?}"))?;
                let inputs: Vec<ReleaseInput> = serde_json::from_str(&raw)
                    .with_context(|| format!("Invalid JSON in releases file {releases:?}"))?;
                inputs.into_iter().map(ReleaseInput::into_record).collect()
            };
            let framework = ComplianceFramework::from(framework);

            let pack = if offline {
                build_offline_evidence_pack(
                    &sdk_ctx,
                    org_did.clone(),
                    &org_prefix,
                    period,
                    framework,
                    &records,
                    &policy_result,
                    now,
                )
            } else {
                build_evidence_pack(
                    &sdk_ctx,
                    org_did.clone(),
                    &org_prefix,
                    period,
                    framework,
                    &records,
                    &policy_result,
                    now,
                )
            }
            .context("Failed to build compliance evidence pack")?;

            let output = if predicate {
                let vsa = VsaParams {
                    verifier_id: verifier_id.clone(),
                    time_verified: now,
                    allow_list: Default::default(),
                };
                let report = build_framework_report(&pack, &vsa)
                    .context("Failed to render the framework predicate")?;
                if sign {
                    let (org_alias, curve) = resolve_org_signing(&sdk_ctx, &org, key)?;
                    sign_framework_report(&sdk_ctx, org_did.as_str(), &org_alias, curve, &report)
                        .context("Failed to org-sign the framework predicate")?
                        .to_canonical_json()
                        .context("Failed to serialize DSSE envelope")?
                } else {
                    report
                        .to_intoto_statement()
                        .context("Failed to serialize the framework predicate")?
                }
            } else if sign {
                let (org_alias, curve) = resolve_org_signing(&sdk_ctx, &org, key)?;
                sign_evidence_pack(&sdk_ctx, org_did.as_str(), &org_alias, curve, &pack)
                    .context("Failed to org-sign the evidence pack")?
                    .to_canonical_json()
                    .context("Failed to serialize DSSE envelope")?
            } else {
                pack.canonicalize()
                    .context("Failed to serialize evidence pack")?
            };

            match &out {
                Some(path) => {
                    fs::write(path, &output)
                        .with_context(|| format!("Failed to write pack to {path:?}"))?;
                    eprintln!("✅ Compliance evidence pack written to {path:?}");
                    eprintln!("   Rows:               {}", pack.rows.len());
                    eprintln!("   Offline-verifiable: {}", pack.org_bundle.is_some());
                    eprintln!("   Org-signed (DSSE):  {sign}");
                    eprintln!(
                        "   Witness verdict:    {}",
                        pack.equivocation_visibility.label
                    );
                }
                None => println!("{output}"),
            }
            Ok(())
        }

        ComplianceSubcommand::Verify {
            pack,
            roots,
            log_key,
        } => {
            let envelope_json = fs::read_to_string(&pack)
                .with_context(|| format!("Failed to read evidence pack {pack:?}"))?;
            let roots_raw = fs::read_to_string(&roots)
                .with_context(|| format!("Failed to read pinned-roots file {roots:?}"))?;
            let pinned = parse_roots_typed(&roots_raw)
                .map_err(|e| anyhow!("pinned roots file rejected: {e}"))?;
            let pinned_log_key = log_key.as_deref().map(parse_pinned_log_key).transpose()?;

            // Hard rejections (no envelope, bad DSSE signature, unpinned org,
            // KEL tamper, duplicity) surface here as errors → exit 1.
            let verified = verify_signed_evidence_pack_offline(
                &envelope_json,
                &pinned,
                pinned_log_key.as_ref(),
            )
            .map_err(|e| anyhow!("evidence REJECTED: {e}"))?;
            let authentic = verified.authentic();

            if is_json_mode() {
                JsonResponse {
                    success: authentic,
                    command: "compliance verify".to_string(),
                    data: Some(verify_verdict_json(
                        &pack,
                        &verified,
                        authentic,
                        pinned_log_key.is_some(),
                    )),
                    error: (!authentic)
                        .then(|| "a row is inconsistent with the embedded log".to_string()),
                }
                .print()?;
            } else {
                print_verify_report(&pack, &verified, authentic, pinned_log_key.is_some());
            }

            // A verified envelope whose rows diverge from the embedded log is
            // still a rejection — the auditor's contract is the exit code.
            if !authentic {
                return Err(anyhow!(
                    "evidence REJECTED — a row is inconsistent with the embedded log"
                ));
            }
            Ok(())
        }
    }
}

/// The wire label of a row's authority verdict, read from its serde tag (the
/// single source of truth for the vocabulary the pack itself carries).
fn authority_label(verdict: &auths_sdk::workflows::compliance::RowVerdict) -> String {
    serde_json::to_value(&verdict.authority_at_release)
        .ok()
        .and_then(|v| v["authority_at_signing"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "?".to_string())
}

/// The machine-readable verdict for `compliance verify --json`.
fn verify_verdict_json(
    pack_path: &Path,
    verified: &VerifiedEvidencePack,
    authentic: bool,
    log_key_pinned: bool,
) -> serde_json::Value {
    serde_json::json!({
        "pack": pack_path,
        "org": verified.pack.org.as_str(),
        "period": verified.pack.period,
        "framework": verified.pack.framework,
        "dsse_signature": "verified",
        "org_key_source": "authenticated embedded KEL",
        "org_kel_seq": verified.org_kel_seq.to_string(),
        "root_pinned": true,
        "log_key_pinned": log_key_pinned,
        "rows": verified.verdicts,
        "authentic": authentic,
    })
}

/// Render the auditor-facing verification report (green = proven, red = rejected).
fn print_verify_report(
    pack_path: &Path,
    verified: &VerifiedEvidencePack,
    authentic: bool,
    log_key_pinned: bool,
) {
    let out = Output::stdout();
    println!(
        "Offline evidence-pack verification of {}",
        pack_path.display()
    );
    println!("  Org:      {}", verified.pack.org.as_str());
    println!(
        "  Period:   {}   Framework: {:?}",
        verified.pack.period, verified.pack.framework
    );
    println!(
        "  {}",
        out.success(
            "DSSE signature verified — org key resolved from the authenticated KEL, not a keychain"
        )
    );
    println!(
        "  {}",
        out.success(&format!(
            "Root pinned · no duplicity · org KEL signature-authenticated (seq {})",
            verified.org_kel_seq
        ))
    );
    if log_key_pinned {
        println!(
            "  {}",
            out.success(
                "Log-operator key pinned — checkpoint signatures verified, not just Merkle membership"
            )
        );
    }
    println!("  Rows:");
    for v in &verified.verdicts {
        let label = authority_label(v);
        let row_ok = v.authority_consistent && label.starts_with("authorized");
        let mark = if v.authority_consistent { "✓" } else { "✗" };
        let transparency = match (v.transparency_verified, v.checkpoint_attested) {
            (Some(true), Some(true)) => "logged+operator-attested",
            (Some(true), Some(false)) => "CHECKPOINT-UNATTESTED",
            (Some(true), None) => "logged",
            (Some(false), _) => "TRANSPARENCY-FAIL",
            (None, _) => "unlogged",
        };
        let line = format!(
            "{mark} {}  {}  {label}",
            truncated(&v.artifact_digest, 19),
            truncated(v.signer.as_str(), 21),
        );
        let line = if row_ok {
            out.success(&line)
        } else {
            out.error(&line)
        };
        println!(
            "    {line}  {}",
            out.dim(&format!(
                "consistent={} transparency={transparency}",
                v.authority_consistent
            ))
        );
    }
    if authentic {
        println!(
            "  {}",
            out.success(
                "Verdict:  AUTHENTIC — evidence verified offline, trusting only the pinned roots"
            )
        );
    } else {
        println!(
            "  {}",
            out.error("Verdict:  REJECTED — evidence inconsistent with its own log")
        );
    }
}

/// First `n` characters with an ellipsis when truncated (row alignment helper).
fn truncated(s: &str, n: usize) -> String {
    let cut: String = s.chars().take(n).collect();
    if cut.len() < s.len() {
        format!("{cut}…")
    } else {
        cut
    }
}

impl ExecutableCommand for ComplianceCommand {
    #[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_compliance(self.clone(), ctx, Utc::now())
    }
}
