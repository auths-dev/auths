use clap::{Parser, Subcommand};

use crate::config::CliConfig;
use crate::errors::registry;

/// Look up error codes and their explanations.
///
/// Usage:
/// ```ignore
/// auths error show AUTHS-E3001
/// auths error list
/// ```
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Look up an error code or list all known codes",
    after_help = "Examples:
  auths error list          # List all known error codes
  auths error show AUTHS-E3001  # Show details for a specific code
  auths error AUTHS-E3001   # Short form (same as show)

Related:
  auths doctor  — Run health checks to diagnose issues
  auths status  — Check your identity and device status"
)]
pub struct ErrorLookupCommand {
    #[command(subcommand)]
    pub subcommand: Option<ErrorSubcommand>,

    /// The error code to look up (e.g. AUTHS-E3001). Deprecated: use `auths error show CODE`.
    pub code: Option<String>,

    /// List all known error codes. Deprecated: use `auths error list`.
    #[arg(long)]
    pub list: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ErrorSubcommand {
    /// List all known error codes
    List,
    /// Show explanation for an error code
    Show { code: String },
}

impl ErrorLookupCommand {
    pub fn execute(&self, ctx: &CliConfig) -> anyhow::Result<()> {
        // Handle new subcommand path
        if let Some(ref subcommand) = self.subcommand {
            match subcommand {
                ErrorSubcommand::List => return list_codes(ctx),
                ErrorSubcommand::Show { code } => return explain_code(code, ctx),
            }
        }

        // Handle legacy flag/positional path
        if self.list {
            return list_codes(ctx);
        }

        match &self.code {
            Some(code) => explain_code(code, ctx),
            None => {
                // No subcommand, no flag, no code → show help
                list_codes(ctx)
            }
        }
    }
}

fn explain_code(code: &str, ctx: &CliConfig) -> anyhow::Result<()> {
    let normalized = code.to_uppercase();

    if ctx.is_json() {
        match registry::explain(&normalized) {
            Some(text) => {
                let json = serde_json::json!({
                    "code": normalized,
                    "explanation": text,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            None => {
                let json = serde_json::json!({
                    "error": { "message": format!("Unknown error code: {normalized}") }
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
    } else {
        match registry::explain(&normalized) {
            Some(text) => println!("{text}"),
            None => {
                eprintln!("Unknown error code: {normalized}");
                eprintln!();
                // Provide helpful suggestion if they try to use the old --list flag
                if normalized == "LIST" {
                    eprintln!("Did you mean: auths error list");
                } else {
                    eprintln!("Run `auths error list` to see all known codes.");
                }
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn list_codes(ctx: &CliConfig) -> anyhow::Result<()> {
    let codes = registry::all_codes();

    if ctx.is_json() {
        let json = serde_json::json!({ "codes": codes });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        for code in codes {
            println!("{code}");
        }
        eprintln!("\n{} error codes registered", codes.len());
        eprintln!("Run `auths error show CODE` to see details for a specific code.");
    }
    Ok(())
}
