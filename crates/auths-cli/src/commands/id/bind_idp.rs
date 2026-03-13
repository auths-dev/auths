use anyhow::{Result, anyhow};
use clap::Parser;

const CLOUD_BINARY: &str = "auths-cloud";

/// Stub command that delegates to the `auths-cloud` binary.
///
/// If `auths-cloud` is on `$PATH`, forwards all arguments.
/// Otherwise, prints an informational message about Auths Cloud.
#[derive(Parser, Debug, Clone)]
#[command(about = "Bind this identity to an enterprise IdP (requires Auths Cloud)")]
pub struct BindIdpStubCommand {
    /// All arguments are forwarded to auths-cloud.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

pub fn handle_bind_idp(cmd: BindIdpStubCommand) -> Result<()> {
    match which::which(CLOUD_BINARY) {
        Ok(path) => {
            let status = std::process::Command::new(path)
                .args(["id", "bind-idp"])
                .args(&cmd.args)
                .status()
                .map_err(|e| anyhow!("failed to execute {CLOUD_BINARY}: {e}"))?;

            if status.success() {
                Ok(())
            } else {
                Err(anyhow!(
                    "{CLOUD_BINARY} exited with status {}",
                    status.code().unwrap_or(-1)
                ))
            }
        }
        Err(_) => {
            let out = crate::ux::format::Output::new();
            out.newline();
            out.print_info("IdP binding requires Auths Cloud.");
            out.newline();
            out.println("  Bind your Auths identity to enterprise identity providers");
            out.println("  like Okta, Microsoft Entra ID, Google Workspace, or SAML 2.0.");
            out.newline();
            out.println("  Learn more: https://auths.dev/cloud");
            out.newline();
            Ok(())
        }
    }
}
