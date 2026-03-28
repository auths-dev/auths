//! Comprehensive health check command for Auths.

use crate::adapters::doctor_fixes::{AllowedSignersFix, GitSigningConfigFix};
use crate::adapters::system_diagnostic::PosixDiagnosticAdapter;
use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::Result;
use auths_core::storage::keychain;
use auths_sdk::ports::diagnostics::{
    CheckCategory, CheckResult, ConfigIssue, DiagnosticFix, FixApplied,
};
use auths_sdk::workflows::diagnostics::DiagnosticsWorkflow;
use clap::Parser;
use serde::Serialize;
use std::io::IsTerminal;

/// Health check command.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "doctor",
    about = "Run comprehensive health checks",
    after_help = "Examples:
  auths doctor              # Check all health aspects
  auths doctor --fix        # Auto-fix identified issues
  auths doctor --json       # JSON output

Exit Codes:
  0 — All checks pass
  1 — Critical check failed (Auths is non-functional)
  2 — Critical checks pass, advisory checks fail (environment could be better)

Related:
  auths status  — Show identity and device status
  auths init    — Initialize a new identity"
)]
pub struct DoctorCommand {
    /// Auto-fix issues where possible
    #[clap(long)]
    pub fix: bool,
}

/// A single health check.
#[derive(Debug, Serialize)]
pub struct Check {
    name: String,
    passed: bool,
    detail: String,
    suggestion: Option<String>,
    #[serde(skip_serializing_if = "is_advisory")]
    category: CheckCategory,
}

fn is_advisory(cat: &CheckCategory) -> bool {
    *cat == CheckCategory::Advisory
}

/// Overall doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub checks: Vec<Check>,
    pub all_pass: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixes_applied: Vec<FixApplied>,
}

/// Handle the doctor command.
pub fn handle_doctor(cmd: DoctorCommand) -> Result<()> {
    let checks = run_checks();
    let all_pass = checks.iter().all(|c| c.passed);

    let (final_checks, fixes_applied) = if cmd.fix && !all_pass {
        let out = if !is_json_mode() {
            Some(Output::new())
        } else {
            None
        };
        let fixes = apply_fixes(&checks, out.as_ref());
        if !fixes.is_empty() {
            let rechecked = run_checks();
            (rechecked, fixes)
        } else {
            (checks, fixes)
        }
    } else {
        (checks, Vec::new())
    };

    let all_pass = final_checks.iter().all(|c| c.passed);

    // Compute exit code based on check categories
    let exit_code = compute_exit_code(&final_checks);

    let report = DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks: final_checks,
        all_pass,
        fixes_applied,
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

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Compute exit code based on check categories.
///
/// Returns:
/// * 0 — all checks pass
/// * 1 — at least one Critical check fails (Auths is non-functional)
/// * 2 — all Critical checks pass, at least one Advisory check fails
fn compute_exit_code(checks: &[Check]) -> i32 {
    let critical_failures = checks
        .iter()
        .any(|c| !c.passed && c.category == CheckCategory::Critical);

    if critical_failures {
        return 1;
    }

    let advisory_failures = checks
        .iter()
        .any(|c| !c.passed && c.category == CheckCategory::Advisory);

    if advisory_failures {
        return 2;
    }

    0
}

/// Run all prerequisite checks.
fn run_checks() -> Vec<Check> {
    let adapter = PosixDiagnosticAdapter;
    let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);

    let mut checks = Vec::new();

    if let Ok(report) = workflow.run() {
        for cr in report.checks {
            // Categorize SDK checks: system tools are Advisory, git signing is Critical
            let category = if cr.name == "Git signing config" {
                CheckCategory::Critical
            } else {
                CheckCategory::Advisory
            };

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
                category,
            });
        }
    }

    // Domain checks are all Critical
    checks.push(check_keychain_accessible());
    checks.push(check_identity_exists());
    checks.push(check_allowed_signers_file());

    checks
}

fn apply_fixes(checks: &[Check], out: Option<&Output>) -> Vec<FixApplied> {
    let failed: Vec<CheckResult> = checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| CheckResult {
            name: c.name.clone(),
            passed: c.passed,
            message: Some(c.detail.clone()),
            config_issues: Vec::new(),
            category: c.category,
        })
        .collect();

    let fixes = build_available_fixes();
    let interactive = std::io::stdin().is_terminal();
    let mut applied = Vec::new();

    for fix in &fixes {
        let applicable: Vec<&CheckResult> = failed.iter().filter(|c| fix.can_fix(c)).collect();
        if applicable.is_empty() {
            continue;
        }

        if !fix.is_safe() && !interactive {
            if let Some(o) = out {
                o.print_warn(&format!(
                    "Skipping unsafe fix '{}' (non-interactive mode)",
                    fix.name()
                ));
            }
            continue;
        }

        if !fix.is_safe() && interactive {
            let confirm = dialoguer::Confirm::new()
                .with_prompt(format!(
                    "Apply fix '{}'? (may overwrite existing git config)",
                    fix.name()
                ))
                .default(true)
                .interact()
                .unwrap_or(false);
            if !confirm {
                continue;
            }
        }

        match fix.apply() {
            Ok(message) => {
                if let Some(o) = out {
                    o.print_success(&format!("Fixed: {}", message));
                }
                applied.push(FixApplied {
                    name: fix.name().to_string(),
                    message,
                });
            }
            Err(e) => {
                if let Some(o) = out {
                    o.print_error(&format!("Fix '{}' failed: {}", fix.name(), e));
                }
            }
        }
    }

    applied
}

fn build_available_fixes() -> Vec<Box<dyn DiagnosticFix>> {
    let mut fixes: Vec<Box<dyn DiagnosticFix>> = Vec::new();

    if let Ok(repo_path) = auths_core::paths::auths_home() {
        fixes.push(Box::new(AllowedSignersFix::new(repo_path)));
    }

    if let Ok(sign_path) = which::which("auths-sign") {
        let key_alias = resolve_key_alias().unwrap_or_else(|| "main".to_string());
        fixes.push(Box::new(GitSigningConfigFix::new(sign_path, key_alias)));
    }

    fixes
}

fn resolve_key_alias() -> Option<String> {
    let keychain = keychain::get_platform_keychain().ok()?;
    let aliases = keychain.list_aliases().ok()?;
    aliases
        .into_iter()
        .find(|a| !a.to_string().contains("--next-"))
        .map(|a| a.to_string())
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
        "Git signing config" => Some("Run: auths doctor --fix".to_string()),
        "Allowed signers file" => Some("Run: auths doctor --fix".to_string()),
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
        category: CheckCategory::Critical,
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
        category: CheckCategory::Critical,
    }
}

fn check_allowed_signers_file() -> Check {
    use auths_sdk::workflows::allowed_signers::{AllowedSigners, SignerSource};

    let path = crate::factories::storage::read_git_config("gpg.ssh.allowedSignersFile")
        .ok()
        .flatten();

    let (passed, detail, suggestion) = match path {
        Some(path_str) => {
            let file_path = std::path::Path::new(&path_str);
            if file_path.exists() {
                match AllowedSigners::load(
                    file_path,
                    &crate::adapters::allowed_signers_store::FileAllowedSignersStore,
                ) {
                    Ok(signers) => {
                        let entries = signers.list();
                        let attestation_count = entries
                            .iter()
                            .filter(|e| e.source == SignerSource::Attestation)
                            .count();
                        let manual_count = entries
                            .iter()
                            .filter(|e| e.source == SignerSource::Manual)
                            .count();

                        let has_markers = std::fs::read_to_string(file_path)
                            .map(|c| c.contains("# auths:attestation"))
                            .unwrap_or(false);

                        let mut detail = format!(
                            "{path_str} ({} attestation, {} manual)",
                            attestation_count, manual_count
                        );

                        if !has_markers && !entries.is_empty() {
                            detail.push_str(
                                " [no auths markers — run `auths signers sync` to add them]",
                            );
                        }

                        (true, detail, None)
                    }
                    Err(_) => (
                        true,
                        format!("{path_str} (exists, could not parse entries)"),
                        None,
                    ),
                }
            } else {
                (
                    false,
                    format!("Configured but file not found: {path_str}"),
                    Some("Run: auths doctor --fix".to_string()),
                )
            }
        }
        None => (
            false,
            "Not configured".into(),
            Some("Run: auths doctor --fix".to_string()),
        ),
    };
    Check {
        name: "Allowed signers file".to_string(),
        passed,
        detail,
        suggestion,
        category: CheckCategory::Critical,
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

    if !report.fixes_applied.is_empty() {
        out.newline();
        out.print_heading("Fixes applied:");
        for fix in &report.fixes_applied {
            out.println(&format!("  {} — {}", out.success(&fix.name), fix.message));
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
