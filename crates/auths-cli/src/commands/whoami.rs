use anyhow::{Result, anyhow};
use auths_id::storage::identity::IdentityStorage;
use auths_id::storage::layout;
use auths_storage::git::RegistryIdentityStorage;
use clap::Parser;
use serde::Serialize;

use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, Output, is_json_mode};

/// Show the current identity on this machine.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "whoami",
    about = "Show the current identity on this machine",
    after_help = "Examples:
  auths whoami              # Show the current identity
  auths whoami --json       # JSON output

Related:
  auths status  — Show full identity and device status
  auths init    — Initialize a new identity"
)]
pub struct WhoamiCommand {}

#[derive(Debug, Serialize)]
struct WhoamiResponse {
    identity_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

pub fn handle_whoami(_cmd: WhoamiCommand, repo: Option<std::path::PathBuf>) -> Result<()> {
    let repo_path = layout::resolve_repo_path(repo).map_err(|e| anyhow!(e))?;

    if crate::factories::storage::open_git_repo(&repo_path).is_err() {
        if is_json_mode() {
            JsonResponse::<()>::error(
                "whoami",
                "No identity found. Run `auths init` to get started.",
            )
            .print()?;
        } else {
            let out = Output::new();
            out.print_error("No identity found. Run `auths init` to get started.");
        }
        return Ok(());
    }

    let storage = RegistryIdentityStorage::new(&repo_path);
    match storage.load_identity() {
        Ok(identity) => {
            let response = WhoamiResponse {
                identity_did: identity.controller_did.to_string(),
                label: None,
            };

            if is_json_mode() {
                JsonResponse::success("whoami", &response).print()?;
            } else {
                let out = Output::new();
                out.println(&format!("Identity: {}", out.info(&response.identity_did)));
            }
        }
        Err(_) => {
            if is_json_mode() {
                JsonResponse::<()>::error(
                    "whoami",
                    "No identity found. Run `auths init` to get started.",
                )
                .print()?;
            } else {
                let out = Output::new();
                out.print_error("No identity found. Run `auths init` to get started.");
            }
        }
    }

    Ok(())
}

impl crate::commands::executable::ExecutableCommand for WhoamiCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_whoami(self.clone(), ctx.repo_path.clone())
    }
}
