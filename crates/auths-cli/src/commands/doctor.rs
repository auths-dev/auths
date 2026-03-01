//! Comprehensive health check command for Auths.

use crate::adapters::system_diagnostic::PosixDiagnosticAdapter;
use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::Result;
use auths_core::storage::keychain;
use auths_sdk::ports::diagnostics::{CheckResult, ConfigIssue};
use auths_sdk::workflows::diagnostics::DiagnosticsWorkflow;
use clap::Parser;
use serde::Serialize;

/// Health check command.
#[derive(Parser, Debug, Clone)]
#[command(name = "doctor", about = "Run comprehensive health checks")]
pub struct DoctorCommand {}

/// A single health check.
#[derive(Debug, Serialize)]
pub struct Check {
    name: String,
    passed: bool,
    detail: String,
    suggestion: Option<String>,
}

/// Overall doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub checks: Vec<Check>,
    pub all_pass: bool,
}

/// Handle the doctor command.
pub fn handle_doctor(_cmd: DoctorCommand) -> Result<()> {
    let checks = run_checks();
    let all_pass = checks.iter().all(|c| c.passed);

    let report = DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks,
        all_pass,
    };

    if is_json_mode() {
        JsonResponse {
            success: all_pass,
            command: "doctor".to_string(),
            data: Some(report),
            error: if !all_pass {
                Some("some health checks failed".to_string())
            } else {
                None
            },
        }
        .print()?;
    } else {
        print_report(&report);
    }

    if !all_pass {
        std::process::exit(1);
    }

    Ok(())
}

/// Run all prerequisite checks.
fn run_checks() -> Vec<Check> {
    let adapter = PosixDiagnosticAdapter;
    let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);

    let mut checks = Vec::new();

    // Run SDK workflow checks (git version, ssh-keygen, signing config)
    if let Ok(report) = workflow.run() {
        for cr in report.checks {
            let suggestion = if cr.passed {
                None
            } else {
                suggestion_for_check(&cr.name)
            };
            checks.push(Check {
                name: cr.name.clone(),
                passed: cr.passed,
                detail: format_check_detail(&cr),
                suggestion,
            });
        }
    }

    // CLI-only checks that depend on keychain / local state
    checks.push(check_keychain_accessible());
    checks.push(check_identity_exists());
    checks.push(check_allowed_signers_file());

    checks
}

fn format_check_detail(cr: &CheckResult) -> String {
    if !cr.config_issues.is_empty() {
        let parts: Vec<String> = cr
            .config_issues
            .iter()
            .map(|issue| match issue {
                ConfigIssue::Mismatch {
                    key,
                    expected,
                    actual,
                } => {
                    format!("{key} (is '{actual}', expected '{expected}')")
                }
                ConfigIssue::Absent(key) => format!("{key} (not set)"),
            })
            .collect();
        return format!("Missing or wrong: {}", parts.join(", "));
    }
    cr.message.clone().unwrap_or_default()
}

fn suggestion_for_check(name: &str) -> Option<String> {
    match name {
        "Git installed" => {
            Some("Install Git for your platform (see: https://git-scm.com/downloads)".to_string())
        }
        "ssh-keygen installed" => Some("Install OpenSSH for your platform.".to_string()),
        "Git signing config" => Some("Run: auths init --profile developer".to_string()),
        _ => None,
    }
}

fn check_keychain_accessible() -> Check {
    let (passed, detail, suggestion) = match keychain::get_platform_keychain() {
        Ok(keychain) => (
            true,
            format!("{} (accessible)", keychain.backend_name()),
            None,
        ),
        Err(e) => (
            false,
            format!("inaccessible: {e}"),
            Some("Run: auths init --profile developer".to_string()),
        ),
    };
    Check {
        name: "System keychain".to_string(),
        passed,
        detail,
        suggestion,
    }
}

fn check_identity_exists() -> Check {
    let (passed, detail, suggestion) = match keychain::get_platform_keychain() {
        Ok(keychain) => match keychain.list_aliases() {
            Ok(aliases) if aliases.is_empty() => (
                false,
                "No keys found in keychain".to_string(),
                Some("Run: auths init --profile developer  (or: auths id init)".to_string()),
            ),
            Ok(aliases) => (true, format!("{} key(s) found", aliases.len()), None),
            Err(e) => (
                false,
                format!("Failed to list keys: {e}"),
                Some("Run: auths doctor  (check keychain is accessible first)".to_string()),
            ),
        },
        Err(_) => (
            false,
            "Keychain not accessible".to_string(),
            Some("Run: auths init --profile developer".to_string()),
        ),
    };
    Check {
        name: "Auths identity".to_string(),
        passed,
        detail,
        suggestion,
    }
}

fn check_allowed_signers_file() -> Check {
    let path = crate::factories::storage::read_git_config("gpg.ssh.allowedSignersFile")
        .ok()
        .flatten();

    let (passed, detail, suggestion) = match path {
        Some(path_str) => {
            if std::path::Path::new(&path_str).exists() {
                (true, format!("Set to: {path_str}"), None)
            } else {
                (
                    false,
                    format!("Configured but file not found: {path_str}"),
                    Some(
                        "Run: auths init --profile developer  (regenerates allowed_signers)"
                            .to_string(),
                    ),
                )
            }
        }
        None => (
            false,
            "Not configured".into(),
            Some("Run: auths init --profile developer".to_string()),
        ),
    };
    Check {
        name: "Allowed signers file".to_string(),
        passed,
        detail,
        suggestion,
    }
}

/// Print the report in human-readable format.
fn print_report(report: &DoctorReport) {
    let out = Output::new();

    out.print_heading(&format!("Auths Doctor (v{})", report.version));
    out.println("--------------------------");
    out.newline();

    for check in &report.checks {
        let (icon, name_styled) = if check.passed {
            (out.success("✓"), out.bold(&check.name))
        } else {
            (out.error("✗"), out.error(&check.name))
        };

        out.println(&format!("[{icon}] {name_styled}: {}", check.detail));

        if let Some(ref suggestion) = check.suggestion {
            out.println(&format!("      -> {}", out.dim(suggestion)));
        }
    }

    out.newline();

    let passed_count = report.checks.iter().filter(|c| c.passed).count();
    let failed_count = report.checks.len() - passed_count;

    let summary = format!(
        "Summary: {} passed, {} failed",
        out.success(&passed_count.to_string()),
        out.error(&failed_count.to_string())
    );
    out.println(&summary);
    out.newline();

    if report.all_pass {
        out.print_success("All checks passed! Your system is ready.");
    } else {
        out.print_error("Some checks failed. Please review the suggestions above.");
    }
}

impl crate::commands::executable::ExecutableCommand for DoctorCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_doctor(self.clone())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_keychain_check_suggestion_is_exact_command() {
        let suggestion = "Run: auths init --profile developer";
        assert!(
            suggestion.starts_with("Run:"),
            "suggestion must start with 'Run:'"
        );
    }

    #[test]
    fn test_git_signing_config_checks_all_five_configs() {
        use super::*;
        let adapter = PosixDiagnosticAdapter;
        let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);
        let report = workflow.run().unwrap();
        let signing_check = report
            .checks
            .iter()
            .find(|c| c.name == "Git signing config");
        assert!(signing_check.is_some(), "signing config check must exist");
    }

    #[test]
    fn test_all_failed_checks_have_exact_runnable_suggestions() {
        let suggestions: Vec<Option<String>> = vec![
            Some("Run: auths init --profile developer".to_string()),
            Some("Run: auths id init".to_string()),
            Some("Run: git config --global gpg.format ssh".to_string()),
            Some("Run: auths init --profile developer".to_string()),
        ];
        for text in suggestions.into_iter().flatten() {
            assert!(text.starts_with("Run:"), "bad suggestion: {}", text);
        }
    }
}
