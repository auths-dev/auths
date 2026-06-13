use anyhow::{Result, anyhow};
use auths_sdk::domains::identity::local::{LocalSigner, resolve_local_signer};
use auths_sdk::storage_layout as layout;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    device_did: Option<String>,
    /// The identity's *current* signing public key (post-rotation), hex-encoded —
    /// the value `trust pin --key` and `verify --signer-key` accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    curve: Option<String>,
}

/// Resolve the identity's current public key (hex) and curve from its local KEL.
/// Best-effort: `None` never blocks `whoami` from reporting the DID.
fn current_key_hex(repo_path: &std::path::Path, did: &str) -> Option<(String, String)> {
    let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(repo_path),
    );
    let (pk, curve) = auths_sdk::keri::resolve_current_public_key(&registry, did).ok()?;
    Some((hex::encode(pk), format!("{curve:?}").to_lowercase()))
}

/// Resolve this machine's signing identity, uniformly across root and delegate.
/// Best-effort: `None` lets the caller emit the un-initialised message.
fn local_signer(repo_path: &std::path::Path) -> Option<LocalSigner> {
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let ctx = crate::factories::storage::build_auths_context(repo_path, &env_config, None).ok()?;
    resolve_local_signer(&ctx).ok()
}

pub fn handle_whoami(_cmd: WhoamiCommand, repo: Option<std::path::PathBuf>) -> Result<()> {
    let repo_path = layout::resolve_repo_path(repo).map_err(|e| anyhow!(e))?;

    // One resolver for both machine shapes: `resolve_local_signer` returns the
    // root identity (`root_did`) and this machine's signer (`signer_did`), which
    // differ only on a paired delegate. A missing repo or no local signer is the
    // same "not initialised" outcome.
    let signer = crate::factories::storage::open_git_repo(&repo_path)
        .ok()
        .and_then(|_| local_signer(&repo_path));

    let Some(signer) = signer else {
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
    };

    // The signer's own KEL (the device dip on a delegate, the controller icp on a
    // root) is always local, so its current key resolves on both shapes.
    let key = current_key_hex(&repo_path, &signer.signer_did);
    let response = WhoamiResponse {
        identity_did: signer.root_did.clone(),
        label: None,
        device_did: Some(signer.signer_did.clone()),
        public_key_hex: key.as_ref().map(|(hex, _)| hex.clone()),
        curve: key.as_ref().map(|(_, curve)| curve.clone()),
    };

    if is_json_mode() {
        JsonResponse::success("whoami", &response).print()?;
    } else {
        let out = Output::new();
        out.println(&format!("Identity: {}", out.info(&response.identity_did)));
        if let Some(ref device) = response.device_did {
            out.println(&format!("Device:   {}", out.dim(device)));
        }
    }

    Ok(())
}

impl crate::commands::executable::ExecutableCommand for WhoamiCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_whoami(self.clone(), ctx.repo_path.clone())
    }
}
