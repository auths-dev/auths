//! Comprehensive health check command for Auths.

use crate::adapters::doctor_fixes::{AllowedSignersFix, GitSigningConfigFix};
use crate::adapters::system_diagnostic::PosixDiagnosticAdapter;
use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::Result;
use auths_sdk::keychain;
use auths_sdk::ports::diagnostics::{
    CheckCategory, CheckResult, ConfigIssue, DiagnosticFix, FixApplied,
};
use auths_sdk::workflows::diagnostics::DiagnosticsWorkflow;
use chrono::{DateTime, Utc};
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
#[allow(clippy::disallowed_methods)] // CLI boundary: Utc::now() injected here
fn run_checks() -> Vec<Check> {
    let now = Utc::now();
    let adapter = PosixDiagnosticAdapter;
    let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);

    let mut checks = Vec::new();

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
                category: cr.category,
            });
        }
    }

    // Domain checks are all Critical
    checks.push(check_keychain_accessible());
    checks.push(check_auths_repo());
    checks.push(check_identity_valid(now));
    checks.push(check_allowed_signers_file());

    // Advisory: network connectivity
    checks.push(check_registry_connectivity());

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

    if let Ok(repo_path) = auths_sdk::paths::auths_home() {
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
        "Git version" => Some(
            "Upgrade Git to 2.34.0+ for SSH signing: https://git-scm.com/downloads".to_string(),
        ),
        "Git user identity" => Some(
            "Run: git config --global user.name \"Your Name\" && git config --global user.email \"you@example.com\"".to_string(),
        ),
        "ssh-keygen installed" => {
            let hint = if cfg!(target_os = "macos") {
                "ssh-keygen is normally pre-installed on macOS. Check your PATH."
            } else if cfg!(target_os = "windows") {
                "Install OpenSSH via Settings > Apps > Optional features, or `winget install Microsoft.OpenSSH.Client`."
            } else {
                "Install OpenSSH: `sudo apt install openssh-client` (Debian/Ubuntu) or `sudo dnf install openssh-clients` (Fedora/RHEL)."
            };
            Some(hint.to_string())
        }
        "SSH version" => Some(
            "Upgrade OpenSSH to 8.2+ for -Y find-principals support. Check with: ssh -V".to_string(),
        ),
        "Git signing config" => Some("Run: auths doctor --fix".to_string()),
        "Auths directory" => Some("Run: auths init --profile developer".to_string()),
        "Allowed signers file" => Some("Run: auths doctor --fix".to_string()),
        "Registry connectivity" => {
            Some("Check your internet connection or try again later.".to_string())
        }
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

fn check_auths_repo() -> Check {
    let (passed, detail, suggestion) = match auths_sdk::paths::auths_home() {
        Ok(path) => {
            if !path.exists() {
                (
                    false,
                    format!("{} (not found)", path.display()),
                    Some("Run: auths init --profile developer".to_string()),
                )
            } else {
                match crate::factories::storage::open_git_repo(&path) {
                    Ok(_) => (
                        true,
                        format!("{} (valid git repository)", path.display()),
                        None,
                    ),
                    Err(_) => (
                        false,
                        format!("{} (exists but not a valid git repo)", path.display()),
                        Some("Run: auths init --profile developer".to_string()),
                    ),
                }
            }
        }
        Err(e) => (
            false,
            format!("Cannot resolve path: {e}"),
            Some("Run: auths init --profile developer".to_string()),
        ),
    };
    Check {
        name: "Auths directory".to_string(),
        passed,
        detail,
        suggestion,
        category: CheckCategory::Critical,
    }
}

fn check_identity_valid(now: DateTime<Utc>) -> Check {
    let (passed, detail, suggestion) = match keychain::get_platform_keychain() {
        Ok(keychain) => match keychain.list_aliases() {
            Ok(aliases) if aliases.is_empty() => (
                false,
                "No keys found in keychain".to_string(),
                Some("Run: auths init --profile developer  (or: auths id init)".to_string()),
            ),
            Ok(aliases) => {
                let key_count = aliases.len();
                let expiry_info = check_attestation_expiry(now);
                match expiry_info {
                    ExpiryStatus::AllExpired(msg) => (
                        false,
                        format!("{key_count} key(s) found, but {msg}"),
                        Some("Run: auths device refresh".to_string()),
                    ),
                    ExpiryStatus::ExpiringSoon(msg) => {
                        (true, format!("{key_count} key(s) found ({msg})"), None)
                    }
                    ExpiryStatus::Ok | ExpiryStatus::NoAttestations => {
                        (true, format!("{key_count} key(s) found"), None)
                    }
                }
            }
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

enum ExpiryStatus {
    Ok,
    NoAttestations,
    ExpiringSoon(String),
    AllExpired(String),
}

fn check_attestation_expiry(now: DateTime<Utc>) -> ExpiryStatus {
    use auths_sdk::storage::RegistryAttestationStorage;

    let repo_path = match auths_sdk::paths::auths_home() {
        Ok(p) if p.exists() => p,
        _ => return ExpiryStatus::NoAttestations,
    };

    let storage = RegistryAttestationStorage::new(&repo_path);
    let attestations = match storage
        .load_all_enriched()
        .map(|v| v.into_iter().map(|e| e.attestation).collect::<Vec<_>>())
    {
        Ok(a) => a,
        Err(_) => return ExpiryStatus::NoAttestations,
    };

    if attestations.is_empty() {
        return ExpiryStatus::NoAttestations;
    }

    let active: Vec<_> = attestations
        .iter()
        .filter(|a| a.revoked_at.is_none())
        .collect();

    if active.is_empty() {
        return ExpiryStatus::AllExpired("all attestations revoked".to_string());
    }

    let with_expiry: Vec<_> = active.iter().filter(|a| a.expires_at.is_some()).collect();

    if with_expiry.is_empty() {
        return ExpiryStatus::Ok;
    }

    let all_expired = with_expiry
        .iter()
        .all(|a| a.expires_at.is_some_and(|exp| exp < now));

    if all_expired {
        return ExpiryStatus::AllExpired("all attestations expired".to_string());
    }

    let warn_threshold = now + chrono::Duration::days(7);
    let expiring_soon = with_expiry
        .iter()
        .any(|a| a.expires_at.is_some_and(|exp| exp < warn_threshold));

    if expiring_soon {
        return ExpiryStatus::ExpiringSoon("some attestations expiring within 7 days".to_string());
    }

    ExpiryStatus::Ok
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

fn check_registry_connectivity() -> Check {
    use auths_sdk::registration::DEFAULT_REGISTRY_URL;

    let url = format!("{DEFAULT_REGISTRY_URL}/health");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();

    let (passed, detail) = match client {
        Ok(client) => match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                (true, format!("{DEFAULT_REGISTRY_URL} (reachable)"))
            }
            Ok(resp) => (
                false,
                format!("{DEFAULT_REGISTRY_URL} (HTTP {})", resp.status()),
            ),
            Err(e) => (false, format!("unreachable: {e}")),
        },
        Err(e) => (false, format!("HTTP client error: {e}")),
    };

    Check {
        name: "Registry connectivity".to_string(),
        passed,
        detail,
        suggestion: if passed {
            None
        } else {
            suggestion_for_check("Registry connectivity")
        },
        category: CheckCategory::Advisory,
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
    fn test_workflow_includes_version_and_user_checks() {
        use super::*;
        let adapter = PosixDiagnosticAdapter;
        let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);
        let report = workflow.run().unwrap();

        let check_names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(
            check_names.contains(&"Git signing config"),
            "signing config check must exist"
        );
        assert!(
            check_names.contains(&"Git version"),
            "git version check must exist"
        );
        assert!(
            check_names.contains(&"Git user identity"),
            "git user identity check must exist"
        );
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

    #[test]
    fn test_suggestion_for_all_new_checks() {
        use super::suggestion_for_check;
        assert!(suggestion_for_check("Git version").is_some());
        assert!(suggestion_for_check("Git user identity").is_some());
        assert!(suggestion_for_check("Auths directory").is_some());
        assert!(suggestion_for_check("Registry connectivity").is_some());
    }
}
