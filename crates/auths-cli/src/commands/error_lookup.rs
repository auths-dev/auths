use clap::Parser;

use crate::config::CliConfig;
use crate::errors::registry;

/// Look up error codes and their explanations.
///
/// Usage:
/// ```ignore
/// auths error AUTHS-E3001
/// auths error --list
/// ```
#[derive(Parser, Debug, Clone)]
#[command(about = "Look up an error code or list all known codes")]
pub struct ErrorLookupCommand {
    /// The error code to look up (e.g. AUTHS-E3001).
    pub code: Option<String>,

    /// List all known error codes.
    #[arg(long)]
    pub list: bool,
}

impl ErrorLookupCommand {
    pub fn execute(&self, ctx: &CliConfig) -> anyhow::Result<()> {
        if self.list {
            return list_codes(ctx);
        }

        match &self.code {
            Some(code) => explain_code(code, ctx),
            None => list_codes(ctx),
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
                eprintln!("Run `auths error --list` to see all known codes.");
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
    }
    Ok(())
}
