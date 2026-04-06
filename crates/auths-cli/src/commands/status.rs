//! Status overview command for Auths.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Result, anyhow};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::KeyStorage;
use auths_sdk::ports::AttestationSource;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::{RegistryAttestationStorage, RegistryIdentityStorage};
use auths_sdk::storage_layout::layout;
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use nix::sys::signal;
#[cfg(unix)]
use nix::unistd::Pid;

/// Show identity and agent status overview.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "status",
    about = "Show identity and agent status overview",
    after_help = "Output:
  Shows your identity DID, linked devices, key aliases, and agent status.
  Recommended after auths init to verify setup.

Next Steps:
  If no identity: run `auths init`
  If no devices: run `auths pair` to link this machine
  If agent not running: run `auths agent start`

Related:
  auths init   — Initialize your identity
  auths doctor — Run comprehensive health checks
  auths --json status — Machine-readable output"
)]
pub struct StatusCommand {}

/// Full status report.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub identity: Option<IdentityStatus>,
    pub agent: AgentStatusInfo,
    pub devices: DevicesSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next_steps: Vec<NextStep>,
}

/// Suggested next action for the user.
#[derive(Debug, Serialize)]
pub struct NextStep {
    pub summary: String,
    pub command: String,
}

/// Identity status information.
#[derive(Debug, Serialize)]
pub struct IdentityStatus {
    pub controller_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub key_aliases: Vec<String>,
}

/// Agent status information.
#[derive(Debug, Serialize)]
pub struct AgentStatusInfo {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
}

/// Devices summary.
#[derive(Debug, Serialize)]
pub struct DevicesSummary {
    pub linked: usize,
    pub revoked: usize,
    pub expiring_soon: Vec<ExpiringDevice>,
    pub devices_detail: Vec<DeviceStatus>,
}

/// Per-device status for expiry display.
#[derive(Debug, Serialize)]
pub struct DeviceStatus {
    pub device_did: String,
    pub status: String,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<i64>,
}

/// Device that is expiring soon.
#[derive(Debug, Serialize)]
pub struct ExpiringDevice {
    pub device_did: String,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: i64,
}

/// Handle the status command.
#[allow(clippy::disallowed_methods)]
pub fn handle_status(
    _cmd: StatusCommand,
    repo: Option<PathBuf>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let now = Utc::now();
    let repo_path = resolve_repo_path(repo)?;
    let identity = load_identity_status(&repo_path, env_config);
    let agent = get_agent_status();
    let devices = load_devices_summary(&repo_path, now);

    let next_steps = compute_next_steps(&identity, &agent, &devices);

    let report = StatusReport {
        identity,
        agent,
        devices,
        next_steps,
    };

    if is_json_mode() {
        JsonResponse::success("status", report).print()?;
    } else {
        print_status(&report, now);
    }

    Ok(())
}

/// Print status in human-readable format.
fn print_status(report: &StatusReport, now: DateTime<Utc>) {
    let out = Output::new();

    // Identity
    if let Some(ref id) = report.identity {
        out.println(&format!("Identity:    {}", out.info(&id.controller_did)));
        if let Some(ref alias) = id.alias {
            out.println(&format!("Alias:       {}", alias));
        }
        if id.key_aliases.is_empty() {
            out.println(&format!("Key aliases: {}", out.dim("none")));
        } else {
            out.println(&format!("Key aliases: {}", id.key_aliases.join(", ")));
        }
    } else {
        out.println(&format!("Identity:    {}", out.dim("not initialized")));
    }

    // Agent
    if report.agent.running {
        let pid_str = report
            .agent
            .pid
            .map(|p| format!("pid {}", p))
            .unwrap_or_default();
        let socket_str = report
            .agent
            .socket_path
            .as_ref()
            .map(|s| format!(", socket {}", s))
            .unwrap_or_default();
        out.println(&format!(
            "Agent:      {} ({}{})",
            out.success("running"),
            pid_str,
            socket_str
        ));
    } else {
        out.println(&format!("Agent:      {}", out.warn("stopped")));
    }

    // Devices
    let mut parts = Vec::new();
    if report.devices.linked > 0 {
        parts.push(format!("{} linked", report.devices.linked));
    }
    if report.devices.revoked > 0 {
        parts.push(format!("{} revoked", report.devices.revoked));
    }
    if !report.devices.expiring_soon.is_empty() {
        let expiring_count = report.devices.expiring_soon.len();
        let min_secs = report
            .devices
            .expiring_soon
            .iter()
            .map(|e| e.expires_in)
            .min()
            .unwrap_or(0);
        parts.push(format!(
            "{} expiring in {}",
            expiring_count,
            format_duration_human(min_secs)
        ));
    }

    if parts.is_empty() {
        out.println(&format!("Devices:    {}", out.dim("none")));
    } else {
        out.println(&format!("Devices:    {}", parts.join(", ")));
    }

    // Per-device expiry detail
    if !report.devices.devices_detail.is_empty() {
        out.newline();
        for device in &report.devices.devices_detail {
            if device.revoked_at.is_some() {
                continue;
            }
            out.println(&format!("  {}", out.dim(&device.device_did)));
            display_device_expiry(device.expires_at, &out, now);
        }
    }

    // Next steps
    if !report.next_steps.is_empty() {
        out.newline();
        out.print_heading("Next steps:");
        for step in &report.next_steps {
            out.println(&format!("  • {}", step.summary));
            out.println(&format!("    {}", out.dim(&format!("→ {}", step.command))));
        }
    }
}

/// Format seconds into a human-readable duration string.
fn format_duration_human(secs: i64) -> String {
    if secs < 0 {
        return "expired".to_string();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let remaining_secs = secs % 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else if mins > 0 {
        format!("{}m {}s", mins, remaining_secs)
    } else {
        format!("{}s", remaining_secs)
    }
}

/// Display color-coded device expiry information.
fn display_device_expiry(expires_at: Option<DateTime<Utc>>, out: &Output, now: DateTime<Utc>) {
    let Some(expires_at) = expires_at else {
        out.println(&format!("  Expires: {}", out.info("never")));
        return;
    };

    let remaining_secs = (expires_at - now).num_seconds();

    let (label, color_fn): (&str, fn(&Output, &str) -> String) = match remaining_secs {
        s if s < 0 => ("EXPIRED", Output::error),
        0..=604_799 => ("expiring soon", Output::warn),
        604_800..=2_591_999 => ("expiring", Output::warn),
        _ => ("active", Output::success),
    };

    let display = format!(
        "{} ({}, {} remaining)",
        expires_at.format("%Y-%m-%d"),
        label,
        format_duration_human(remaining_secs)
    );
    out.println(&format!("  Expires: {}", color_fn(out, &display)));

    if (0..=604_800).contains(&remaining_secs) {
        out.print_warn("  Run `auths device extend` to renew.");
    }
}

/// Load identity status from the repository, including key aliases from the keychain.
fn load_identity_status(
    repo_path: &PathBuf,
    env_config: &EnvironmentConfig,
) -> Option<IdentityStatus> {
    if crate::factories::storage::open_git_repo(repo_path).is_err() {
        return None;
    }

    let storage = RegistryIdentityStorage::new(repo_path);
    match storage.load_identity() {
        Ok(identity) => {
            let key_aliases = auths_sdk::keychain::get_platform_keychain_with_config(env_config)
                .ok()
                .and_then(|keychain| {
                    keychain
                        .list_aliases_for_identity(&identity.controller_did)
                        .ok()
                })
                .map(|aliases| aliases.iter().map(|a| a.as_str().to_string()).collect())
                .unwrap_or_default();

            Some(IdentityStatus {
                controller_did: identity.controller_did.to_string(),
                alias: None,
                key_aliases,
            })
        }
        Err(_) => None,
    }
}

/// Get agent status by checking PID file and socket.
fn get_agent_status() -> AgentStatusInfo {
    let auths_dir = match get_auths_dir() {
        Ok(dir) => dir,
        Err(_) => {
            return AgentStatusInfo {
                running: false,
                pid: None,
                socket_path: None,
            };
        }
    };

    let pid_path = auths_dir.join("agent.pid");
    let socket_path = auths_dir.join("agent.sock");

    // Read PID file
    let pid = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok());

    // Check if process is running
    let running = pid.map(is_process_running).unwrap_or(false);
    let socket_exists = socket_path.exists();

    AgentStatusInfo {
        running: running && socket_exists,
        pid: if running { pid } else { None },
        socket_path: if socket_exists && running {
            Some(socket_path.to_string_lossy().to_string())
        } else {
            None
        },
    }
}

/// Load devices summary from attestations.
fn load_devices_summary(repo_path: &PathBuf, now: DateTime<Utc>) -> DevicesSummary {
    let empty = DevicesSummary {
        linked: 0,
        revoked: 0,
        expiring_soon: Vec::new(),
        devices_detail: Vec::new(),
    };

    if crate::factories::storage::open_git_repo(repo_path).is_err() {
        return empty;
    }

    let storage = RegistryAttestationStorage::new(repo_path);
    let attestations = match storage.load_all_attestations() {
        Ok(a) => a,
        Err(_) => return empty,
    };

    let mut latest_by_device: std::collections::HashMap<
        String,
        &auths_verifier::core::Attestation,
    > = std::collections::HashMap::new();

    for att in &attestations {
        let key = att.subject.as_str().to_string();
        latest_by_device
            .entry(key)
            .and_modify(|existing| {
                if att.timestamp > existing.timestamp {
                    *existing = att;
                }
            })
            .or_insert(att);
    }

    let threshold = now + Duration::days(7);
    let mut linked = 0;
    let mut revoked = 0;
    let mut expiring_soon = Vec::new();
    let mut devices_detail = Vec::new();

    for (device_did, att) in &latest_by_device {
        let (status, expires_in) = compute_device_status(att, now);

        devices_detail.push(DeviceStatus {
            device_did: device_did.clone(),
            status,
            revoked_at: att.revoked_at,
            expires_at: att.expires_at,
            expires_in,
        });

        if att.is_revoked() {
            revoked += 1;
        } else {
            linked += 1;
            if let Some(expires_at) = att.expires_at
                && expires_at <= threshold
                && expires_at > now
            {
                let secs_left = (expires_at - now).num_seconds();
                expiring_soon.push(ExpiringDevice {
                    device_did: device_did.clone(),
                    expires_in: secs_left,
                });
            }
        }
    }

    expiring_soon.sort_by_key(|e| e.expires_in);

    DevicesSummary {
        linked,
        revoked,
        expiring_soon,
        devices_detail,
    }
}

fn compute_device_status(
    att: &auths_verifier::core::Attestation,
    now: DateTime<Utc>,
) -> (String, Option<i64>) {
    if att.is_revoked() {
        return ("revoked".to_string(), None);
    }
    match att.expires_at {
        None => ("active".to_string(), None),
        Some(expires_at) => {
            let secs = (expires_at - now).num_seconds();
            let status = if expires_at < now {
                "expired"
            } else if secs <= 7 * 86400 {
                "expiring_soon"
            } else {
                "active"
            };
            (status.to_string(), Some(secs))
        }
    }
}

/// Get the auths directory path (~/.auths), respecting AUTHS_HOME.
fn get_auths_dir() -> Result<PathBuf> {
    auths_sdk::paths::auths_home().map_err(|e| anyhow!(e))
}

/// Resolve the repository path from optional argument or default (~/.auths).
fn resolve_repo_path(repo_arg: Option<PathBuf>) -> Result<PathBuf> {
    layout::resolve_repo_path(repo_arg).map_err(|e| anyhow!(e))
}

/// Compute suggested next steps based on current state.
fn compute_next_steps(
    identity: &Option<IdentityStatus>,
    agent: &AgentStatusInfo,
    devices: &DevicesSummary,
) -> Vec<NextStep> {
    let mut steps = Vec::new();

    // No identity
    if identity.is_none() {
        steps.push(NextStep {
            summary: "Initialize your identity".to_string(),
            command: "auths init".to_string(),
        });
        return steps;
    }

    // No devices linked
    if devices.linked == 0 {
        steps.push(NextStep {
            summary: "Link your first device".to_string(),
            command: "auths pair".to_string(),
        });
    }

    // Agent not running
    if !agent.running {
        steps.push(NextStep {
            summary: "Start the agent service".to_string(),
            command: "auths agent start".to_string(),
        });
    }

    // Devices expiring soon
    if !devices.expiring_soon.is_empty() {
        steps.push(NextStep {
            summary: "Renew devices expiring soon".to_string(),
            command: "auths device extend".to_string(),
        });
    }

    steps
}

/// Check if a process with the given PID is running.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    false
}

impl crate::commands::executable::ExecutableCommand for StatusCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_status(self.clone(), ctx.repo_path.clone(), &ctx.env_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_get_auths_dir() {
        let dir = get_auths_dir().unwrap();
        assert!(dir.ends_with(".auths"));
    }

    #[test]
    fn status_json_snapshot() {
        let now = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let report = StatusReport {
            identity: Some(IdentityStatus {
                controller_did: "did:keri:ETestController123".to_string(),
                alias: Some("dev-machine".to_string()),
                key_aliases: vec!["main".to_string()],
            }),
            agent: AgentStatusInfo {
                running: true,
                pid: Some(12345),
                socket_path: Some("/tmp/agent.sock".to_string()),
            },
            devices: DevicesSummary {
                linked: 2,
                revoked: 1,
                expiring_soon: vec![ExpiringDevice {
                    device_did: "did:key:zExpiringSoon".to_string(),
                    expires_in: 259_200,
                }],
                devices_detail: vec![
                    DeviceStatus {
                        device_did: "did:key:zActiveDevice".to_string(),
                        status: "active".to_string(),
                        revoked_at: None,
                        expires_at: Some(now + Duration::days(90)),
                        expires_in: Some(7_776_000),
                    },
                    DeviceStatus {
                        device_did: "did:key:zExpiringSoon".to_string(),
                        status: "expiring_soon".to_string(),
                        revoked_at: None,
                        expires_at: Some(now + Duration::days(3)),
                        expires_in: Some(259_200),
                    },
                    DeviceStatus {
                        device_did: "did:key:zRevokedDevice".to_string(),
                        status: "revoked".to_string(),
                        revoked_at: Some(now - Duration::days(10)),
                        expires_at: Some(now + Duration::days(50)),
                        expires_in: None,
                    },
                ],
            },
            next_steps: vec![],
        };

        insta::assert_json_snapshot!(report);
    }
}
