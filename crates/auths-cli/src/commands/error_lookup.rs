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

/// Normalize a user-typed error code to its canonical `AUTHS-E####` form.
///
/// Accepts the fully-qualified form and the shorthands people actually type:
/// `E4203`, `4203`, `auths-e4203` all resolve to `AUTHS-E4203`. Anything that is
/// not a bare numeric code is upper-cased and passed through unchanged.
///
/// Args:
/// * `code`: the raw code string from the CLI.
///
/// Usage:
/// ```ignore
/// assert_eq!(normalize_error_code("E4203"), "AUTHS-E4203");
/// ```
pub fn normalize_error_code(code: &str) -> String {
    let upper = code.trim().to_uppercase();
    let without_prefix = upper.strip_prefix("AUTHS-").unwrap_or(&upper);
    let digits = without_prefix.strip_prefix('E').unwrap_or(without_prefix);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        format!("AUTHS-E{digits}")
    } else {
        upper
    }
}

fn explain_code(code: &str, ctx: &CliConfig) -> anyhow::Result<()> {
    let normalized = normalize_error_code(code);

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

#[cfg(test)]
mod tests {
    use super::normalize_error_code;
    use crate::errors::registry;

    #[test]
    fn bare_and_prefixed_codes_resolve_the_same() {
        // A user who types the short form must reach the same doc as the canonical
        // one — `E4203`, `4203`, `auths-e4203` all mean AUTHS-E4203.
        assert_eq!(normalize_error_code("E4203"), "AUTHS-E4203");
        assert_eq!(normalize_error_code("4203"), "AUTHS-E4203");
        assert_eq!(normalize_error_code("auths-e4203"), "AUTHS-E4203");
        assert_eq!(normalize_error_code("AUTHS-E4203"), "AUTHS-E4203");
        assert_eq!(
            registry::explain(&normalize_error_code("E4203")),
            registry::explain("AUTHS-E4203")
        );
        assert!(registry::explain(&normalize_error_code("E4203")).is_some());
    }

    #[test]
    fn non_numeric_input_passes_through_uppercased() {
        // The `LIST` shorthand (and any unknown token) must not be mangled into a
        // fake code.
        assert_eq!(normalize_error_code("list"), "LIST");
    }
}
