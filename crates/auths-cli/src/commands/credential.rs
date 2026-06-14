//! `auths credential …` — issue / revoke / list / verify capability credentials.
//!
//! A credential is an ACDC anchored to the issuer's KEL via a backerless TEL. This is
//! the thin presentation layer; all orchestration (issuee guard, registry, issuer-sign,
//! `iss`/`rev` anchor, the verify resolution + freshness layer) lives in
//! `auths_sdk::domains::credentials`. The clock (`Utc::now()`) is read only here.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;

use auths_rp::{Nonce, WirePresentation};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::credentials::{
    CredentialVerdict, PresentationChallenge, UsageObservation, VerifierWitnessPolicy, issue, list,
    present_credential, revoke, verify_by_said_with_usage,
};
use auths_sdk::keychain::KeyAlias;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::storage_layout::layout;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Issue, revoke, list, and verify capability credentials.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Issue, revoke, list, and verify capability credentials.",
    after_help = "Examples:
  auths credential issue --issuer my-key --to did:keri:E… --cap sign --role deployer
  auths credential revoke ECred… --issuer my-key
  auths credential list --issuer my-key
  auths credential verify ECred… --issuer my-key --require-witnesses"
)]
pub struct CredentialCommand {
    #[clap(subcommand)]
    pub subcommand: CredentialSubcommand,
}

/// Credential subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum CredentialSubcommand {
    /// Issue a capability credential to an issuee (its KEL must already exist).
    Issue {
        /// The issuer's signing key name (your identity's key).
        #[arg(long, help = "The issuer's signing key name (your identity's key).")]
        issuer: String,

        /// The issuee/subject `did:keri:` to credential.
        #[arg(long = "to", help = "The issuee/subject did:keri to credential.")]
        to: String,

        /// Capability to grant (repeatable).
        #[arg(long = "cap", help = "Capability to grant (repeatable).")]
        cap: Vec<auths_keri::Capability>,

        /// Informational role claim.
        #[arg(long, help = "Informational role claim (e.g. deployer).")]
        role: Option<String>,

        /// Expire the credential this many seconds from now.
        #[arg(long = "expires-in", help = "Expire the credential after N seconds.")]
        expires_in: Option<i64>,
    },

    /// Revoke a credential (anchors a `rev` in the issuer's KEL). Idempotent.
    Revoke {
        /// The credential SAID to revoke.
        #[arg(help = "The credential SAID to revoke.")]
        credential_said: String,

        /// The issuer's signing key name.
        #[arg(long, help = "The issuer's signing key name.")]
        issuer: String,
    },

    /// List the issuer's live credentials (issued − revoked).
    List {
        /// The issuer's signing key name.
        #[arg(long, help = "The issuer's signing key name.")]
        issuer: Option<String>,

        /// Include revoked credentials in the listing.
        #[arg(long, help = "Include revoked credentials.")]
        include_revoked: bool,
    },

    /// Verify a credential, resolving the issuer KEL/TEL + witness receipts.
    Verify {
        /// The credential SAID to verify.
        #[arg(help = "The credential SAID to verify.")]
        credential_said: String,

        /// The issuer's signing key name (whose namespace holds the credential).
        #[arg(long, help = "The issuer's signing key name.")]
        issuer: String,

        /// Fail closed unless every lifecycle anchor reaches witness quorum.
        #[arg(
            long = "require-witnesses",
            help = "Fail closed unless every lifecycle anchor reaches witness quorum."
        )]
        require_witnesses: bool,

        /// Enforce a quantitative usage cap against an observed call count.
        ///
        /// Path to a JSON usage observation `{"said":"…","calls_used":N}`. When the
        /// credential carries a `calls:<N>` cap, the observed count is checked
        /// against the verifier's monotonic usage ledger: an over-budget count fails
        /// with `cap_exceeded`, a replayed (lower) count fails with
        /// `usage_counter_rolled_back`. Omitted for credentials without a usage cap.
        #[arg(
            long = "usage-counter",
            value_name = "FILE",
            help = "Enforce a quantitative usage cap against an observed call count (JSON: {\"said\":…,\"calls_used\":N})."
        )]
        usage_counter: Option<PathBuf>,
    },

    /// Present a credential: prove control of the subject AID and emit an `Auths-Presentation` header.
    Present {
        /// The subject (holder/agent) keychain alias whose current key signs the presentation.
        #[arg(long, help = "The subject (holder) keychain alias to sign with.")]
        subject: String,

        /// The credential SAID to present.
        #[arg(long = "said", help = "The credential SAID to present.")]
        said: String,

        /// The relying-party audience the presentation binds to.
        #[arg(long, help = "The relying-party audience to bind to.")]
        audience: String,

        /// The base64url challenge nonce issued by the relying party.
        #[arg(
            long,
            allow_hyphen_values = true,
            help = "The base64url challenge nonce from /v1/auth/challenge."
        )]
        nonce: String,
    },
}

/// JSON response for `credential issue`.
#[derive(Debug, Serialize)]
struct IssueResponse {
    credential_said: String,
    registry_said: String,
    issuer_did: String,
    issuee_did: String,
}

impl ExecutableCommand for CredentialCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
        handle_credential(
            self.clone(),
            repo_path,
            &ctx.env_config,
            ctx.passphrase_provider.clone(),
        )
    }
}

/// Dispatch an `auths credential …` subcommand.
///
/// Args:
/// * `cmd`: The parsed credential command.
/// * `repo_path`: Resolved registry repository path.
/// * `env_config`: Environment configuration for context building.
/// * `passphrase_provider`: Passphrase source for issuer key access.
///
/// Usage:
/// ```ignore
/// handle_credential(cmd, repo_path, &env_config, passphrase_provider)?;
/// ```
pub fn handle_credential(
    cmd: CredentialCommand,
    repo_path: PathBuf,
    env_config: &EnvironmentConfig,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
) -> Result<()> {
    match cmd.subcommand {
        CredentialSubcommand::Issue {
            issuer,
            to,
            cap,
            role,
            expires_in,
        } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let issuer_alias = KeyAlias::new_unchecked(issuer);
            // Clock at the presentation boundary (the SDK/core never call Utc::now()).
            #[allow(clippy::disallowed_methods)]
            let expires_at =
                expires_in.map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));
            let issued = issue(&ctx, &issuer_alias, &to, &cap, role.as_deref(), expires_at)
                .map_err(anyhow::Error::new)?;

            if is_json_mode() {
                JsonResponse::success(
                    "credential issue",
                    IssueResponse {
                        credential_said: issued.credential_said.clone(),
                        registry_said: issued.registry_said.clone(),
                        issuer_did: issued.issuer_did.clone(),
                        issuee_did: issued.issuee_did.clone(),
                    },
                )
                .print()?;
            } else {
                println!(
                    "✓ Credential issued and recorded in the issuer's tamper-evident history:"
                );
                println!("  credential: {}", issued.credential_said);
                println!(
                    "  issuee:     {}",
                    crate::ux::product_id(&issued.issuee_did)
                );
            }
            Ok(())
        }

        CredentialSubcommand::Present {
            subject,
            said,
            audience,
            nonce,
        } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let subject_alias = KeyAlias::new_unchecked(subject);
            let challenge_nonce = Nonce::parse_b64url(&nonce).map_err(anyhow::Error::new)?;
            let envelope = present_credential(
                &ctx,
                &subject_alias,
                &said,
                &audience,
                PresentationChallenge::Challenge {
                    nonce: challenge_nonce.as_bytes().to_vec(),
                },
            )
            .map_err(anyhow::Error::new)?;
            let token = WirePresentation::from_envelope(&envelope)
                .to_token()
                .map_err(anyhow::Error::new)?;
            let header = format!("Auths-Presentation {token}");

            if is_json_mode() {
                JsonResponse::success(
                    "credential present",
                    serde_json::json!({ "authorization": header }),
                )
                .print()?;
            } else {
                println!("{header}");
            }
            Ok(())
        }

        CredentialSubcommand::Revoke {
            credential_said,
            issuer,
        } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let issuer_alias = KeyAlias::new_unchecked(issuer);
            revoke(&ctx, &issuer_alias, &credential_said).map_err(anyhow::Error::new)?;

            if is_json_mode() {
                JsonResponse::success(
                    "credential revoke",
                    serde_json::json!({ "credential_said": credential_said, "revoked": true }),
                )
                .print()?;
            } else {
                println!(
                    "✓ Credential revoked (recorded in the issuer's tamper-evident history): {credential_said}"
                );
            }
            Ok(())
        }

        CredentialSubcommand::List {
            issuer,
            include_revoked,
        } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let issuer_alias = KeyAlias::new_unchecked(issuer.unwrap_or_default());
            let credentials = list(&ctx, &issuer_alias).map_err(anyhow::Error::new)?;
            let shown: Vec<_> = credentials
                .into_iter()
                .filter(|c| include_revoked || !c.revoked)
                .collect();

            if is_json_mode() {
                let data: Vec<_> = shown
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "credential_said": c.credential_said,
                            "subject_did": c.subject_did,
                            "capabilities": c.capabilities,
                            "revoked": c.revoked,
                        })
                    })
                    .collect();
                JsonResponse::success(
                    "credential list",
                    serde_json::json!({ "credentials": data }),
                )
                .print()?;
            } else if shown.is_empty() {
                println!("No credentials issued by this identity.");
            } else {
                println!("Issued credentials:");
                for c in &shown {
                    let status = if c.revoked { " (revoked)" } else { "" };
                    println!(
                        "  {} → {} [{}]{}",
                        c.credential_said,
                        crate::ux::product_id(&c.subject_did),
                        c.capabilities
                            .iter()
                            .map(|cap| cap.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        status
                    );
                }
            }
            Ok(())
        }

        CredentialSubcommand::Verify {
            credential_said,
            issuer,
            require_witnesses,
            usage_counter,
        } => {
            let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;
            let issuer_alias = KeyAlias::new_unchecked(issuer);
            let policy = if require_witnesses {
                VerifierWitnessPolicy::RequireWitnesses
            } else {
                VerifierWitnessPolicy::Warn
            };
            let observation = match usage_counter {
                Some(path) => Some(load_usage_observation(&path)?),
                None => None,
            };
            // Clock at the presentation boundary.
            #[allow(clippy::disallowed_methods)]
            let now = chrono::Utc::now();
            let rt = tokio::runtime::Runtime::new()?;
            let verdict = rt
                .block_on(verify_by_said_with_usage(
                    &ctx,
                    &issuer_alias,
                    &credential_said,
                    policy,
                    now,
                    &repo_path,
                    observation,
                ))
                .map_err(anyhow::Error::new)?;
            print_verdict(&credential_said, &verdict)
        }
    }
}

/// Load an observed usage count from a `{"said":…,"calls_used":N}` JSON file.
///
/// The presented count is *untrusted* caller input (e.g. an agent's reported call
/// count); the verifier checks it against its own monotonic usage ledger. A missing
/// or malformed file is a hard error — the cap was requested, so it must be enforced.
fn load_usage_observation(path: &PathBuf) -> Result<UsageObservation> {
    #[derive(serde::Deserialize)]
    struct UsageCounterFile {
        calls_used: u64,
    }
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("usage counter file read failed ({}): {e}", path.display()))?;
    let parsed: UsageCounterFile = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow::anyhow!("usage counter file parse failed ({}): {e}", path.display())
    })?;
    Ok(UsageObservation {
        calls_used: parsed.calls_used,
    })
}

/// Render a verification verdict to stdout (JSON or human-readable).
fn print_verdict(credential_said: &str, verdict: &CredentialVerdict) -> Result<()> {
    let valid = verdict.is_valid();
    let (status, detail, as_of) = describe(verdict);

    if is_json_mode() {
        JsonResponse::success(
            "credential verify",
            serde_json::json!({
                "credential_said": credential_said,
                "valid": valid,
                "status": status,
                "detail": detail,
                "as_of": as_of,
            }),
        )
        .print()?;
    } else if valid {
        println!("✓ Credential is valid: {credential_said}");
        if let Some(seq) = as_of {
            println!("  as of the issuer's history revision {seq}");
        }
    } else {
        println!("✗ Credential did not verify: {credential_said}");
        println!("  status: {status}");
        if let Some(d) = detail {
            println!("  detail: {d}");
        }
    }
    Ok(())
}

/// A `(status, detail, as_of_seq)` summary of a verdict for presentation.
fn describe(verdict: &CredentialVerdict) -> (&'static str, Option<String>, Option<u128>) {
    use auths_verifier::CredentialVerdict as Inner;
    match verdict {
        CredentialVerdict::StaleOrUnresolvable { as_of, reason } => (
            "stale_or_unresolvable",
            Some(reason.clone()),
            Some(as_of.seq),
        ),
        CredentialVerdict::UsageCapExceeded {
            as_of,
            observed,
            cap,
        } => (
            "cap_exceeded",
            Some(format!(
                "usage cap reached: {observed} of {cap} calls already spent"
            )),
            Some(as_of.seq),
        ),
        CredentialVerdict::UsageCounterRolledBack {
            as_of,
            observed,
            high_water,
        } => (
            "usage_counter_rolled_back",
            Some(format!(
                "replayed usage counter: presented {observed}, but {high_water} already observed"
            )),
            Some(as_of.seq),
        ),
        CredentialVerdict::Resolved { verdict, as_of } => {
            let seq = Some(as_of.seq);
            match verdict {
                Inner::Valid { .. } => ("valid", None, seq),
                Inner::SaidMismatch => ("said_mismatch", None, seq),
                Inner::SchemaInvalid => ("schema_invalid", None, seq),
                Inner::IssuerSignatureInvalid => ("issuer_signature_invalid", None, seq),
                Inner::RegistryNotEstablished => ("registry_not_established", None, seq),
                Inner::CredentialRevoked { revoked_at } => (
                    "revoked",
                    Some(format!(
                        "revoked at the issuer's history revision {revoked_at}"
                    )),
                    seq,
                ),
                Inner::Expired { expired_at, .. } => {
                    ("expired", Some(format!("expired at {expired_at}")), seq)
                }
                Inner::WitnessQuorumNotMet {
                    event,
                    collected,
                    required,
                } => (
                    "witness_quorum_not_met",
                    Some(format!(
                        "{event} anchor: {collected}/{required} witness receipts"
                    )),
                    seq,
                ),
                Inner::IssuerKelDuplicitous => ("issuer_kel_duplicitous", None, seq),
            }
        }
    }
}
