use anyhow::Error;
use auths_core::error::{AgentError, AuthsErrorInfo};
use auths_sdk::error::{
    ApprovalError, DeviceError, DeviceExtensionError, McpAuthError, OrgError, RegistrationError,
    RotationError, SetupError,
};
use auths_sdk::signing::SigningError;
use auths_sdk::workflows::allowed_signers::AllowedSignersError;
use auths_verifier::AttestationError;
use colored::Colorize;

use crate::errors::cli_error::CliError;
use crate::ux::format::Output;

const DOCS_BASE_URL: &str = "https://docs.auths.dev";

/// Render an error to stderr in either text or JSON format.
///
/// Args:
/// * `err`: The error to render.
/// * `json_mode`: If `true`, output structured JSON; otherwise styled text.
pub fn render_error(err: &Error, json_mode: bool) {
    if json_mode {
        render_json(err);
    } else {
        render_text(err);
    }
}

/// Try to extract `AuthsErrorInfo` from an `anyhow::Error` by downcasting
/// through all known error types.
fn extract_error_info(err: &Error) -> Option<(&str, &str, Option<&str>)> {
    macro_rules! try_downcast {
        ($err:expr, $($ty:ty),+ $(,)?) => {
            $(
                if let Some(e) = $err.downcast_ref::<$ty>() {
                    let code = AuthsErrorInfo::error_code(e);
                    let msg = format!("{e}");
                    // SAFETY: we leak the String to get a &'static str because
                    // the caller consumes it immediately in the same scope.
                    // This is bounded to a single error render per invocation.
                    let msg: &str = Box::leak(msg.into_boxed_str());
                    return Some((code, msg, AuthsErrorInfo::suggestion(e)));
                }
            )+
        };
    }

    try_downcast!(
        err,
        AgentError,
        AttestationError,
        SetupError,
        DeviceError,
        DeviceExtensionError,
        RotationError,
        RegistrationError,
        McpAuthError,
        OrgError,
        ApprovalError,
        AllowedSignersError,
        SigningError,
    );

    None
}

fn render_text(err: &Error) {
    let out = Output::new();

    if let Some(cli_err) = err.downcast_ref::<CliError>() {
        eprintln!("\n{} {}", "Error:".red().bold(), cli_err);
        eprintln!("\n{}", cli_err.suggestion());
        if let Some(url) = cli_err.docs_url() {
            eprintln!("Docs: {}", url);
        }
        eprintln!();
        return;
    }

    if let Some((code, message, suggestion)) = extract_error_info(err) {
        let prefix = format!("[{code}]").yellow();
        out.print_error(&format!("{prefix} {}", out.bold(message)));
        eprintln!();
        if let Some(suggestion) = suggestion {
            eprintln!("  fix:  {suggestion}");
        }
        if let Some(url) = docs_url(code) {
            eprintln!("  docs: {url}");
        }
        return;
    }

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
        out.print_error(&format!("{err}"));
        for cause in err.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
    }
}

fn render_json(err: &Error) {
    let json = if let Some(cli_err) = err.downcast_ref::<CliError>() {
        build_json(
            None,
            &format!("{cli_err}"),
            Some(cli_err.suggestion()),
            cli_err.docs_url().map(|s| s.to_string()),
        )
    } else if let Some((code, message, suggestion)) = extract_error_info(err) {
        build_json(Some(code), message, suggestion, docs_url(code))
    } else {
        build_json(None, &format!("{err}"), None, None)
    };

    eprintln!("{json}");
}

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

fn docs_url(code: &str) -> Option<String> {
    if code.starts_with("AUTHS-E") {
        Some(format!("{DOCS_BASE_URL}/errors/#{code}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_url_returns_some_for_known_codes() {
        let url = docs_url("AUTHS-E3001");
        assert_eq!(url, Some(format!("{DOCS_BASE_URL}/errors/#AUTHS-E3001")));
    }

    #[test]
    fn docs_url_returns_none_for_unknown_codes() {
        assert!(docs_url("UNKNOWN").is_none());
        assert!(docs_url("SOME_OTHER").is_none());
    }

    #[test]
    fn build_json_with_all_fields() {
        let json = build_json(
            Some("AUTHS-E3001"),
            "Key not found",
            Some("Run `auths key list`"),
            Some(format!("{DOCS_BASE_URL}/errors/#AUTHS-E3001")),
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["code"], "AUTHS-E3001");
        assert_eq!(parsed["error"]["message"], "Key not found");
        assert_eq!(parsed["error"]["suggestion"], "Run `auths key list`");
        assert!(
            parsed["error"]["docs"]
                .as_str()
                .unwrap()
                .contains("AUTHS-E3001")
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
        render_error(&err, false);
    }

    #[test]
    fn render_error_agent_error_json() {
        let err = Error::new(AgentError::KeyNotFound);
        render_error(&err, true);
    }

    #[test]
    fn render_error_attestation_error_text() {
        let err = Error::new(AttestationError::IssuerSignatureFailed("bad sig".into()));
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

    #[test]
    fn extract_error_info_returns_code_for_agent_error() {
        let err = Error::new(AgentError::KeyNotFound);
        let (code, _, suggestion) = extract_error_info(&err).unwrap();
        assert_eq!(code, "AUTHS-E3001");
        assert!(suggestion.is_some());
    }
}
