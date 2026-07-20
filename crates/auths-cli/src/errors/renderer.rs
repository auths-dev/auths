use anyhow::Error;
use auths_sdk::domains::signing::service::{ArtifactSigningError, SigningError};
use auths_sdk::error::CoreTrustError;
use auths_sdk::error::IdDriverStorageError;
use auths_sdk::error::IdStorageError;
use auths_sdk::error::PairingError;
use auths_sdk::error::{AgentError, AuthsErrorInfo};
use auths_sdk::error::{
    ApprovalError, DeviceError, DeviceExtensionError, McpAuthError, OrgError, RegistrationError,
    RotationError, SdkStorageError, SetupError, TrustError,
};
use auths_sdk::error::{FreezeError, InitError};
use auths_sdk::workflows::auth::AuthChallengeError;
use auths_verifier::{AttestationError, CommitVerificationError};
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
/// through all known error types. Walks the full error chain so that
/// `.with_context()` wrapping doesn't hide typed errors.
fn extract_error_info(err: &Error) -> Option<(&str, &str, Option<&str>)> {
    macro_rules! try_downcast {
        ($source:expr, $($ty:ty),+ $(,)?) => {
            $(
                if let Some(e) = $source.downcast_ref::<$ty>() {
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

    for cause in err.chain() {
        try_downcast!(
            cause,
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
            ArtifactSigningError,
            SigningError,
            SdkStorageError,
            TrustError,
            AuthChallengeError,
            CommitVerificationError,
            PairingError,
            FreezeError,
            InitError,
            CoreTrustError,
            IdStorageError,
            IdDriverStorageError,
        );
    }

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
            eprintln!("  fix:  {}", suggestion.blue());
        }
        // The offline lookup is the real, working next step; the docs site's
        // /errors/ path 404s, so it is not advertised until it is published.
        if code.starts_with("AUTHS-E") {
            eprintln!("  look up: auths error show {code}");
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
        s if s.contains("not a git repository") => Some(
            "This command must be run inside a Git repository.\nRun `git init` first, or navigate to an existing repo.".to_string()
        ),
        s if s.contains("permission denied") || s.contains("Permission denied") => Some(format!(
            "Permission denied. Check file permissions on the relevant path.\n     Run `auths doctor` for a full health check.\n     See: {DOCS_BASE_URL}/cli/troubleshooting/"
        )),
        s if s.contains("connection refused") || s.contains("timed out") || s.contains("timeout") => Some(
            "Network connection failed. Check your internet connection and try again.\nIf using a registry, verify the URL with `auths config show`.".to_string()
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
        eprintln!(
            "\nhint: Run 'auths doctor' to check your setup, or 'auths error list' to browse known issues."
        );
    }
}

fn render_json(err: &Error) {
    let json = if let Some(cli_err) = err.downcast_ref::<CliError>() {
        build_json(
            None,
            &format!("{cli_err}"),
            Some(cli_err.suggestion()),
            cli_err.docs_url().map(|s| s.to_string()),
            None,
        )
    } else if let Some((code, message, suggestion)) = extract_error_info(err) {
        // Emit the offline lookup, not the 404 docs URL, as the machine-readable
        // next step (mirrors the text renderer's `look up:` line).
        build_json(
            Some(code),
            message,
            suggestion,
            docs_url(code),
            lookup(code),
        )
    } else {
        build_json(None, &format!("{err}"), None, None, None)
    };

    eprintln!("{json}");
}

fn build_json(
    code: Option<&str>,
    message: &str,
    suggestion: Option<&str>,
    docs: Option<String>,
    lookup: Option<String>,
) -> String {
    let mut map = serde_json::Map::new();
    if let Some(c) = code {
        map.insert("code".into(), serde_json::Value::String(c.into()));
    }
    map.insert("message".into(), serde_json::Value::String(message.into()));
    if let Some(s) = suggestion {
        map.insert("suggestion".into(), serde_json::Value::String(s.into()));
    }
    if let Some(l) = lookup {
        map.insert("lookup".into(), serde_json::Value::String(l));
    }
    if let Some(d) = docs {
        map.insert("docs".into(), serde_json::Value::String(d));
    }

    let wrapper = serde_json::json!({ "error": map });
    serde_json::to_string_pretty(&wrapper)
        .unwrap_or_else(|_| format!("{{\"error\":{{\"message\":\"{message}\"}}}}"))
}

/// The offline lookup command for an error code — the working next step.
fn lookup(code: &str) -> Option<String> {
    if code.starts_with("AUTHS-E") {
        Some(format!("auths error show {code}"))
    } else {
        None
    }
}

/// Deep docs link for an error code. Returns `None` until the docs site publishes
/// `docs/errors/` — its `/errors/` path 404s today, so `auths error show` (the
/// renderer's look-up line) is the actionable path instead.
fn docs_url(code: &str) -> Option<String> {
    let _ = code;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_url_returns_none_until_docs_site_publishes_errors() {
        // The docs `/errors/` path 404s, so no docs URL is emitted for any code —
        // `auths error show` is the working next step instead.
        assert!(docs_url("AUTHS-E3001").is_none());
        assert!(docs_url("UNKNOWN").is_none());
    }

    #[test]
    fn lookup_points_at_offline_command_for_auths_codes() {
        assert_eq!(
            lookup("AUTHS-E5909"),
            Some("auths error show AUTHS-E5909".to_string())
        );
        assert!(lookup("UNKNOWN").is_none());
    }

    #[test]
    fn json_error_carries_offline_lookup_not_docs_url() {
        // The machine-readable body advertises `auths error show <CODE>` and drops
        // the dead docs URL — the same repointing the text renderer does.
        let json = build_json(
            Some("AUTHS-E5909"),
            "keychain unavailable",
            Some("Run `auths doctor`"),
            docs_url("AUTHS-E5909"),
            lookup("AUTHS-E5909"),
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["lookup"], "auths error show AUTHS-E5909");
        assert!(parsed["error"].get("docs").is_none());
        assert!(!json.contains("docs.auths.dev/errors"));
    }

    #[test]
    fn build_json_without_optional_fields() {
        let json = build_json(None, "Something went wrong", None, None, None);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["message"], "Something went wrong");
        assert!(parsed["error"].get("code").is_none());
        assert!(parsed["error"].get("suggestion").is_none());
        assert!(parsed["error"].get("docs").is_none());
        assert!(parsed["error"].get("lookup").is_none());
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

    #[test]
    fn extract_error_info_walks_chain_through_context() {
        let err: Error = Error::new(AgentError::KeyNotFound).context("operation failed");
        let (code, _, _) = extract_error_info(&err).unwrap();
        assert_eq!(code, "AUTHS-E3001");
    }

    #[test]
    fn setup_error_storage_delegates_to_inner_code() {
        let inner = IdStorageError::NotFound("test".into());
        let sdk_err = auths_sdk::error::SdkStorageError::Identity(inner);
        let setup_err = SetupError::StorageError(sdk_err);
        let err = Error::new(setup_err);
        let (code, _, suggestion) = extract_error_info(&err).unwrap();
        assert_eq!(code, "AUTHS-E4104");
        assert!(suggestion.is_some());
    }

    #[test]
    fn setup_error_registration_delegates_to_inner_code() {
        let reg_err = RegistrationError::AlreadyRegistered;
        let setup_err = SetupError::RegistrationFailed(reg_err);
        let err = Error::new(setup_err);
        let (code, _, suggestion) = extract_error_info(&err).unwrap();
        assert_eq!(code, "AUTHS-E5401");
        assert!(suggestion.is_some());
    }
}
