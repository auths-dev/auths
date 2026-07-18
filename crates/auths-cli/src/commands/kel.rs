//! `auths kel validate` — read-only structural check of a Key Event Log.
//!
//! Replays a KEL and reports the first defect that would make it fail at sign or
//! verify time: a stale or mismatched SAID encoding, or a broken chain link.
//! Exits nonzero when the log is unsound, so a corrupt KEL is caught up front
//! instead of silently breaking signing later.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use auths_keri::{Event, TrustedKel, parse_kel_json, verify_event_said};
use auths_sdk::keri::KelResolverChain;
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

use crate::config::CliConfig;
use crate::ux::format::is_json_mode;

/// Inspect a Key Event Log (read-only).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Inspect a Key Event Log (read-only)",
    after_help = "Examples:
  auths kel validate                    # validate your own identity's local KEL
  auths kel validate --did did:keri:... # validate another identity's local KEL
  auths kel validate --kel kel.json     # validate a KEL JSON file"
)]
pub struct KelCommand {
    #[command(subcommand)]
    pub command: KelSubcommand,
}

/// KEL subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum KelSubcommand {
    /// Structurally validate a KEL: SAID encodings and chain linkage.
    ///
    /// Exits nonzero on a stale encoding or a broken chain so a corrupt log is
    /// caught before it fails silently at sign time.
    Validate(KelValidateArgs),
}

/// Arguments for `auths kel validate`.
#[derive(Parser, Debug, Clone)]
pub struct KelValidateArgs {
    /// Validate this KEL JSON file instead of a stored identity's KEL.
    #[arg(long, value_name = "KEL.json")]
    pub kel: Option<PathBuf>,

    /// Validate this identity's local KEL (defaults to your own identity).
    #[arg(long, value_name = "did:keri:...", conflicts_with = "kel")]
    pub did: Option<String>,
}

impl KelCommand {
    /// Run the command.
    pub fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            KelSubcommand::Validate(args) => validate(args, ctx),
        }
    }
}

/// Validate a KEL and report the first structural defect, if any.
fn validate(args: &KelValidateArgs, ctx: &CliConfig) -> Result<()> {
    let (source, events) = load_events(args, ctx)?;
    if events.is_empty() {
        return Err(anyhow!("{source} contains no key events"));
    }

    // Stale or mismatched encodings: each event's SAID must match its content
    // hash. A stale encoding (wrong version string / re-serialized shape) breaks
    // this before any chain check.
    for (idx, event) in events.iter().enumerate() {
        if let Err(e) = verify_event_said(event) {
            return Err(anyhow!(
                "{source}: stale or invalid encoding at event {idx}: {e}"
            ));
        }
    }

    // Broken chains: structural replay checks sequence monotonicity, prev-event
    // linkage, and the pre-rotation commitment across the whole log.
    if let Err(e) = TrustedKel::from_trusted_source(&events).replay() {
        return Err(anyhow!("{source}: broken chain: {e}"));
    }

    report_ok(&source, events.len());
    Ok(())
}

/// Print the success line in the active output mode.
fn report_ok(source: &str, count: usize) {
    if is_json_mode() {
        let out = serde_json::json!({
            "valid": true,
            "source": source,
            "events": count,
        });
        println!("{out}");
    } else {
        println!("OK: {source} — {count} event(s), SAIDs and chain linkage valid");
    }
}

/// Resolve the KEL events to validate, plus a human label for the source.
fn load_events(args: &KelValidateArgs, ctx: &CliConfig) -> Result<(String, Vec<Event>)> {
    if let Some(path) = &args.kel {
        let json = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;
        let events = parse_kel_json(&json).map_err(|e| anyhow!("cannot parse KEL JSON: {e}"))?;
        return Ok((path.display().to_string(), events));
    }

    let auths_home = auths_sdk::storage_layout::resolve_repo_path(ctx.repo_path.clone())?;
    let did = match &args.did {
        Some(d) => d.clone(),
        None => {
            let sdk_ctx =
                crate::factories::storage::build_auths_context(&auths_home, &ctx.env_config, None)?;
            auths_sdk::workflows::commit_trust::local_self_root(&sdk_ctx).ok_or_else(|| {
                anyhow!("no local identity found — run `auths init` first, or pass --kel/--did")
            })?
        }
    };
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&auths_home));
    let events = KelResolverChain::local(&registry)
        .resolve_kel(&did)
        .map_err(|e| anyhow!("cannot resolve local KEL for {did}: {e}"))?;
    Ok((did, events))
}
