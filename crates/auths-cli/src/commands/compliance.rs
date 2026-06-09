//! `auths compliance` — compliance-as-a-query evidence packs.
//!
//! Thin presentation layer over [`auths_sdk::workflows::compliance`]: it reads the
//! period's releases, calls the SDK query engine to classify each signer's authority
//! **at release** (by KEL position), embeds the honest witness verdict, optionally
//! embeds the org KEL bundle for offline verification, and optionally org-signs the
//! pack as a DSSE-wrapped in-toto statement. No domain logic lives here.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;

use auths_crypto::CurveType;
use auths_sdk::context::AuthsContext;
use auths_sdk::keychain::{KeyAlias, extract_public_key_bytes};
use auths_sdk::storage_layout::layout;
use auths_sdk::workflows::compliance::{
    ComplianceFramework, ReleaseRecord, TransparencyInclusion, VsaParams, build_evidence_pack,
    build_framework_report, build_offline_evidence_pack, load_witness_policy, sign_evidence_pack,
    sign_framework_report,
};
use auths_verifier::{IdentityDID, Prefix};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;

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
}

impl From<CliFramework> for ComplianceFramework {
    fn from(f: CliFramework) -> Self {
        match f {
            CliFramework::Slsa => ComplianceFramework::Slsa,
            CliFramework::Sbom => ComplianceFramework::Sbom,
            CliFramework::Cra => ComplianceFramework::Cra,
        }
    }
}

/// The `compliance` subcommand: compliance as a query over the org's event log.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Compliance as a query — offline-verifiable evidence packs",
    after_help = "Examples:
  auths compliance report --org did:keri:EOrg --period 2026-Q3 \\
      --framework slsa --releases releases.json --offline --out acme-2026Q3.evidence
                        # Build an offline-verifiable evidence pack

Releases file (JSON array):
  [{\"artifact_digest\":\"sha256:…\",\"signer\":\"did:keri:EMember\",\"signed_at\":41}]"
)]
pub struct ComplianceCommand {
    #[clap(subcommand)]
    pub subcommand: ComplianceSubcommand,
}

/// Subcommands for compliance queries.
#[derive(Subcommand, Debug, Clone)]
pub enum ComplianceSubcommand {
    /// Produce a compliance evidence pack for a reporting period.
    Report {
        /// Organization identity ID (`did:keri:…`) or bare prefix
        #[arg(long)]
        org: String,

        /// Reporting period label (free-form, e.g. `2026-Q3`)
        #[arg(long)]
        period: String,

        /// Target framework (tags the pack; with `--predicate`, selects the
        /// rendered predicate: SLSA provenance+VSA / SPDX SBOM / CRA mapping)
        #[arg(long, value_enum, default_value = "slsa")]
        framework: CliFramework,

        /// Render the framework predicate (in-toto Statement) instead of the raw pack
        #[arg(long)]
        predicate: bool,

        /// Verifier id recorded in the SLSA VSA (with `--predicate --framework slsa`)
        #[arg(long, default_value = "https://auths.dev/compliance")]
        verifier_id: String,

        /// JSON file: array of `{ artifact_digest, signer, signed_at?, transparency? }`
        #[arg(long)]
        releases: PathBuf,

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
        ComplianceSubcommand::Report {
            org,
            period,
            framework,
            predicate,
            verifier_id,
            releases,
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

            let raw = fs::read_to_string(&releases)
                .with_context(|| format!("Failed to read releases file {releases:?}"))?;
            let inputs: Vec<ReleaseInput> = serde_json::from_str(&raw)
                .with_context(|| format!("Invalid JSON in releases file {releases:?}"))?;
            let records: Vec<ReleaseRecord> =
                inputs.into_iter().map(ReleaseInput::into_record).collect();

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
    }
}

impl ExecutableCommand for ComplianceCommand {
    #[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_compliance(self.clone(), ctx, Utc::now())
    }
}
