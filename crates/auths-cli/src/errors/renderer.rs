use anyhow::Error;
use auths_core::error::{AgentError, AuthsErrorInfo as CoreErrorInfo};
use auths_sdk::signing::SigningError;
use auths_verifier::{AttestationError, AuthsErrorInfo as VerifierErrorInfo};
use colored::Colorize;

use crate::errors::cli_error::CliError;
use crate::ux::format::Output;

const DOCS_BASE_URL: &str = "https://docs.auths.dev";

/// Render an error to stderr in either text or JSON format.
///
/// Attempts to downcast the anyhow error to known Auths error types
/// (`AgentError`, `AttestationError`) to extract structured metadata
/// (error code, suggestion, docs URL). Falls back to a plain message
/// for unknown error types.
pub fn render_error(err: &Error, json_mode: bool) {
    if json_mode {
        render_json(err);
    } else {
        render_text(err);
    }
}

/// Render a styled error message to stderr.
fn render_text(err: &Error) {
    let out = Output::new();

    // Try CliError first (most specific)
    if let Some(cli_err) = err.downcast_ref::<CliError>() {
        eprintln!("\n{} {}", "Error:".red().bold(), cli_err);
        eprintln!("\n{}", cli_err.suggestion());
        if let Some(url) = cli_err.docs_url() {
            eprintln!("Docs: {}", url);
        }
        eprintln!();
        return;
    }

    if let Some(signing_err) = err.downcast_ref::<SigningError>() {
        let message = format!("{signing_err}");
        out.print_error(&out.bold(&message));
        eprintln!();
        let suggestion = match signing_err {
            SigningError::PassphraseExhausted { attempts } => Some(format!(
                "All {attempts} passphrase attempt(s) failed.\n     Forgot your passphrase? Run: auths key reset <alias>"
            )),
            SigningError::IdentityFrozen(_) => {
                Some("To unfreeze: auths emergency unfreeze".to_string())
            }
            SigningError::KeychainUnavailable(_) => Some(format!(
                "Cannot access system keychain.\n\n     If running headless (CI/Docker), set:\n       export AUTHS_KEYCHAIN_BACKEND=file\n       export AUTHS_PASSPHRASE=<your-passphrase>\n\n     See: {DOCS_BASE_URL}/cli/troubleshooting/"
            )),
            _ => None,
        };
        if let Some(suggestion) = suggestion {
            eprintln!("  fix:  {suggestion}");
        }
        return;
    }

    if let Some(agent_err) = err.downcast_ref::<AgentError>() {
        let code = CoreErrorInfo::error_code(agent_err);
        let message = format!("{agent_err}");
        out.print_error(&out.bold(&message));
        eprintln!();
        if let Some(suggestion) = CoreErrorInfo::suggestion(agent_err) {
            eprintln!("  fix:  {suggestion}");
        }
        if let Some(url) = docs_url(code) {
            eprintln!("  docs: {url}");
        }
    } else if let Some(att_err) = err.downcast_ref::<AttestationError>() {
        let code = VerifierErrorInfo::error_code(att_err);
        let message = format!("{att_err}");
        out.print_error(&out.bold(&message));
        eprintln!();
        if let Some(suggestion) = VerifierErrorInfo::suggestion(att_err) {
            eprintln!("  fix:  {suggestion}");
        }
        if let Some(url) = docs_url(code) {
            eprintln!("  docs: {url}");
        }
    } else {
        // Fallback for generic anyhow::Error
        let msg = err.to_string();
        let suggestion = match msg.as_str() {
            s if s.contains("No identity found") => Some(format!(
                "Run `auths init` to create one, or `auths key import` to restore from a backup.\n     See: {DOCS_BASE_URL}/getting-started/quickstart/"
            )),
            s if s.contains("keychain") || s.contains("Secret Service") => Some(format!(
                "Cannot access system keychain.\n\n     If running headless (CI/Docker), set:\n       export AUTHS_KEYCHAIN_BACKEND=file\n       export AUTHS_PASSPHRASE=<your-passphrase>\n\n     See: {DOCS_BASE_URL}/cli/troubleshooting/"
            )),
            s if s.contains("ssh-keygen") && s.contains("not found") => Some(
                "ssh-keygen not found on PATH.\n\n     Install OpenSSH:\n       Ubuntu: sudo apt install openssh-client\n       macOS:  ssh-keygen is pre-installed\n       Windows: Install OpenSSH via Settings > Apps > Optional features".to_string()
            ),
            _ => None,
        };

        if let Some(suggestion) = suggestion {
            out.print_error(&msg);
            eprintln!("\n{suggestion}");
        } else {
            // Unknown error — print the message and any causal chain
            out.print_error(&format!("{err}"));
            for cause in err.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
        }
    }
}

/// Render a JSON error object to stderr.
fn render_json(err: &Error) {
    let json = if let Some(cli_err) = err.downcast_ref::<CliError>() {
        build_json(
            None,
            &format!("{cli_err}"),
            Some(cli_err.suggestion()),
            cli_err.docs_url().map(|s| s.to_string()),
        )
    } else if let Some(signing_err) = err.downcast_ref::<SigningError>() {
        let suggestion = match signing_err {
            SigningError::PassphraseExhausted { attempts } => Some(format!(
                "All {} passphrase attempt(s) failed. Run: auths key reset <alias>",
                attempts
            )),
            SigningError::IdentityFrozen(_) => {
                Some("To unfreeze: auths emergency unfreeze".to_string())
            }
            _ => None,
        };
        build_json(None, &format!("{signing_err}"), suggestion.as_deref(), None)
    } else if let Some(agent_err) = err.downcast_ref::<AgentError>() {
        let code = CoreErrorInfo::error_code(agent_err);
        build_json(
            Some(code),
            &format!("{agent_err}"),
            CoreErrorInfo::suggestion(agent_err),
            docs_url(code),
        )
    } else if let Some(att_err) = err.downcast_ref::<AttestationError>() {
        let code = VerifierErrorInfo::error_code(att_err);
        build_json(
            Some(code),
            &format!("{att_err}"),
            VerifierErrorInfo::suggestion(att_err),
            docs_url(code),
        )
    } else {
        build_json(None, &format!("{err}"), None, None)
    };

    eprintln!("{json}");
}

/// Build a JSON error string from optional fields.
fn build_json(
    code: Option<&str>,
    message: &str,
    suggestion: Option<&str>,
    docs: Option<String>,
) -> String {
    let mut map = serde_json::Map::new();
    if let Some(c) = code {
        map.insert("code".into(), serde_json::Value::String(c.into()));
    }
    map.insert("message".into(), serde_json::Value::String(message.into()));
    if let Some(s) = suggestion {
        map.insert("suggestion".into(), serde_json::Value::String(s.into()));
    }
    if let Some(d) = docs {
        map.insert("docs".into(), serde_json::Value::String(d));
    }

    let wrapper = serde_json::json!({ "error": map });
    serde_json::to_string_pretty(&wrapper)
        .unwrap_or_else(|_| format!("{{\"error\":{{\"message\":\"{message}\"}}}}"))
}

/// Map an error code to a docs URL. Returns `None` for codes that don't
/// have actionable documentation.
fn docs_url(code: &str) -> Option<String> {
    match code {
        "AUTHS_KEY_NOT_FOUND"
        | "AUTHS_INCORRECT_PASSPHRASE"
        | "AUTHS_MISSING_PASSPHRASE"
        | "AUTHS_BACKEND_UNAVAILABLE"
        | "AUTHS_STORAGE_LOCKED"
        | "AUTHS_BACKEND_INIT_FAILED"
        | "AUTHS_AGENT_LOCKED"
        | "AUTHS_VERIFICATION_ERROR"
        | "AUTHS_MISSING_CAPABILITY"
        | "AUTHS_DID_RESOLUTION_ERROR"
        | "AUTHS_ORG_VERIFICATION_FAILED"
        | "AUTHS_ORG_ATTESTATION_EXPIRED"
        | "AUTHS_ORG_DID_RESOLUTION_FAILED"
        | "AUTHS_GIT_ERROR" => Some(format!("{DOCS_BASE_URL}/errors/#{code}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_url_returns_some_for_known_codes() {
        let url = docs_url("AUTHS_KEY_NOT_FOUND");
        assert_eq!(
            url,
            Some(format!("{DOCS_BASE_URL}/errors/#AUTHS_KEY_NOT_FOUND"))
        );
    }

    #[test]
    fn docs_url_returns_none_for_unknown_codes() {
        assert!(docs_url("AUTHS_IO_ERROR").is_none());
        assert!(docs_url("UNKNOWN").is_none());
    }

    #[test]
    fn build_json_with_all_fields() {
        let json = build_json(
            Some("AUTHS_KEY_NOT_FOUND"),
            "Key not found",
            Some("Run `auths key list`"),
            Some(format!("{DOCS_BASE_URL}/errors/#AUTHS_KEY_NOT_FOUND")),
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["code"], "AUTHS_KEY_NOT_FOUND");
        assert_eq!(parsed["error"]["message"], "Key not found");
        assert_eq!(parsed["error"]["suggestion"], "Run `auths key list`");
        assert!(
            parsed["error"]["docs"]
                .as_str()
                .unwrap()
                .contains("AUTHS_KEY_NOT_FOUND")
        );
    }

    #[test]
    fn build_json_without_optional_fields() {
        let json = build_json(None, "Something went wrong", None, None);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["message"], "Something went wrong");
        assert!(parsed["error"].get("code").is_none());
        assert!(parsed["error"].get("suggestion").is_none());
        assert!(parsed["error"].get("docs").is_none());
    }

    #[test]
    fn render_error_agent_error_text() {
        let err = Error::new(AgentError::KeyNotFound);
        // Should not panic — just writes to stderr
        render_error(&err, false);
    }

    #[test]
    fn render_error_agent_error_json() {
        let err = Error::new(AgentError::KeyNotFound);
        render_error(&err, true);
    }

    #[test]
    fn render_error_attestation_error_text() {
        let err = Error::new(AttestationError::VerificationError("bad sig".into()));
        render_error(&err, false);
    }

    #[test]
    fn render_error_unknown_error_text() {
        let err = anyhow::anyhow!("something unexpected");
        render_error(&err, false);
    }

    #[test]
    fn render_error_unknown_error_json() {
        let err = anyhow::anyhow!("something unexpected");
        render_error(&err, true);
    }
}
