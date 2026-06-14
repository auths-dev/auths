//! Registry propagation commands: push/pull `refs/auths/registry` over a git
//! remote, so a second machine sees this machine's identity events (rotations,
//! revocations, new devices) over a wire instead of a shared filesystem.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use serde::Serialize;

use auths_sdk::storage::{
    MergeOutcome, MergedCredentials, MergedKel, PushOutcome, pull_registry, push_registry,
};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, Output, is_json_mode};

/// Sync the local identity registry with a git remote.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "registry",
    about = "Push/pull the identity registry to/from a git remote",
    after_help = "The registry travels as the packed git ref refs/auths/registry, so any
git remote (a bare repo over file://, git://, ssh://, https://) can carry it
between machines. Push is fast-forward-only (the registry is append-only).
Pull authenticates every fetched KEL (prefix binding, signature replay,
fork refusal) before merging it into the local registry.

Examples:
  auths registry push git://wire.local/registry.git   # publish this machine's registry
  auths registry pull git://wire.local/registry.git   # merge another machine's events

Related:
  auths id show      — The identity whose events the registry carries
  auths device list  — Devices learned from merged registries"
)]
pub struct RegistryCommand {
    #[command(subcommand)]
    pub subcommand: RegistrySubcommand,
}

/// Registry sync subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum RegistrySubcommand {
    /// Publish the local registry ref to a git remote (fast-forward only).
    Push {
        /// Git remote URL (file://, git://, ssh://, https://).
        #[arg(value_name = "REMOTE")]
        remote: String,
    },
    /// Fetch a remote registry and merge its authenticated KELs locally.
    Pull {
        /// Git remote URL (file://, git://, ssh://, https://).
        #[arg(value_name = "REMOTE")]
        remote: String,
    },
}

#[derive(Debug, Serialize)]
struct PushReport {
    remote: String,
    outcome: PushOutcome,
}

#[derive(Debug, Serialize)]
struct PullReport {
    remote: String,
    merged: Vec<MergedKel>,
    #[serde(flatten)]
    credentials: MergedCredentials,
}

impl ExecutableCommand for RegistryCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let registry_root = resolve_registry_root(ctx)?;
        match &self.subcommand {
            RegistrySubcommand::Push { remote } => {
                let outcome = push_registry(&registry_root, remote)?;
                if is_json_mode() {
                    JsonResponse::success(
                        "registry push",
                        PushReport {
                            remote: remote.clone(),
                            outcome,
                        },
                    )
                    .print()?;
                } else {
                    let out = Output::new();
                    match outcome {
                        PushOutcome::Updated => {
                            out.print_success(&format!("Registry pushed to {remote}"));
                        }
                        PushOutcome::AlreadyCurrent => {
                            out.print_info(&format!("Remote {remote} is already current"));
                        }
                    }
                }
                Ok(())
            }
            RegistrySubcommand::Pull { remote } => {
                let report = pull_registry(&registry_root, remote)?;
                if is_json_mode() {
                    JsonResponse::success(
                        "registry pull",
                        PullReport {
                            remote: remote.clone(),
                            merged: report.merged,
                            credentials: report.credentials,
                        },
                    )
                    .print()?;
                } else {
                    let out = Output::new();
                    out.print_success(&format!("Registry pulled from {remote}"));
                    for kel in &report.merged {
                        let line = match &kel.outcome {
                            MergeOutcome::Imported { events } => {
                                format!("{} imported ({events} events)", kel.prefix)
                            }
                            MergeOutcome::Advanced { events } => {
                                format!("{} advanced (+{events} events)", kel.prefix)
                            }
                            MergeOutcome::AlreadyCurrent => {
                                format!("{} already current", kel.prefix)
                            }
                        };
                        out.print_info(&line);
                    }
                    let creds = &report.credentials;
                    if creds.credentials_imported > 0 || creds.tel_events_imported > 0 {
                        out.print_info(&format!(
                            "{} credential(s) and {} status event(s) imported",
                            creds.credentials_imported, creds.tel_events_imported
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// The registry root the sync operates on: the global `--repo` override when
/// given, otherwise the configured Auths home.
fn resolve_registry_root(ctx: &CliConfig) -> Result<PathBuf> {
    if let Some(repo) = &ctx.repo_path {
        return Ok(repo.clone());
    }
    auths_sdk::paths::auths_home_with_config(&ctx.env_config)
        .map_err(|e| anyhow!("Could not locate ~/.auths: {e}"))
}
