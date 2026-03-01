//! Status overview command for Auths.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Result, anyhow};
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_storage::git::{RegistryAttestationStorage, RegistryIdentityStorage};
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
#[command(name = "status", about = "Show identity and agent status overview")]
pub struct StatusCommand {}

/// Full status report.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub identity: Option<IdentityStatus>,
    pub agent: AgentStatusInfo,
    pub devices: DevicesSummary,
}

/// Identity status information.
#[derive(Debug, Serialize)]
pub struct IdentityStatus {
    pub controller_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
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
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Device that is expiring soon.
#[derive(Debug, Serialize)]
pub struct ExpiringDevice {
    pub device_did: String,
    pub expires_in_days: i64,
}

/// Handle the status command.
pub fn handle_status(_cmd: StatusCommand, repo: Option<PathBuf>) -> Result<()> {
    // Determine repository path
    let repo_path = resolve_repo_path(repo)?;

    // Load identity
    let identity = load_identity_status(&repo_path);

    // Get agent status
    let agent = get_agent_status();

    // Load device attestations summary
    let devices = load_devices_summary(&repo_path);

    let report = StatusReport {
        identity,
        agent,
        devices,
    };

    if is_json_mode() {
        JsonResponse::success("status", report).print()?;
    } else {
        print_status(&report);
    }

    Ok(())
}

/// Print status in human-readable format.
fn print_status(report: &StatusReport) {
    let out = Output::new();

    // Identity
    if let Some(ref id) = report.identity {
        let did_display = truncate_did(&id.controller_did, 40);
        out.println(&format!("Identity:   {}", out.info(&did_display)));
        if let Some(ref alias) = id.alias {
            out.println(&format!("Alias:      {}", alias));
        }
    } else {
        out.println(&format!("Identity:   {}", out.dim("not initialized")));
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
        let min_days = report
            .devices
            .expiring_soon
            .iter()
            .map(|e| e.expires_in_days)
            .min()
            .unwrap_or(0);
        if min_days == 0 {
            parts.push(format!("{} expiring today", expiring_count));
        } else if min_days == 1 {
            parts.push(format!("{} expiring in 1 day", expiring_count));
        } else {
            parts.push(format!("{} expiring in {} days", expiring_count, min_days));
        }
    }

    if parts.is_empty() {
        out.println(&format!("Devices:    {}", out.dim("none")));
    } else {
        out.println(&format!("Devices:    {}", parts.join(", ")));
    }

    // Per-device expiry detail
    if !report.devices.devices_detail.is_empty() {
        out.newline();
        let now = Utc::now();
        for device in &report.devices.devices_detail {
            if device.revoked_at.is_some() {
                continue;
            }
            let did_display = truncate_did(&device.device_did, 40);
            out.println(&format!("  {}", out.dim(&did_display)));
            display_device_expiry(device.expires_at, &out, now);
        }
    }
}

/// Display color-coded device expiry information.
fn display_device_expiry(expires_at: Option<DateTime<Utc>>, out: &Output, now: DateTime<Utc>) {
    let Some(expires_at) = expires_at else {
        out.println(&format!("  Expires: {}", out.info("never")));
        return;
    };

    let remaining = expires_at - now;
    let days = remaining.num_days();

    let (label, color_fn): (&str, fn(&Output, &str) -> String) = match days {
        d if d < 0 => ("EXPIRED", Output::error),
        0..=6 => ("expiring soon", Output::warn),
        7..=29 => ("expiring", Output::warn),
        _ => ("active", Output::success),
    };

    let display = format!(
        "{} ({}, {}d remaining)",
        expires_at.format("%Y-%m-%d"),
        label,
        days
    );
    out.println(&format!("  Expires: {}", color_fn(out, &display)));

    if (0..=7).contains(&days) {
        out.print_warn("  Run `auths device extend` to renew.");
    }
}

/// Load identity status from the repository.
fn load_identity_status(repo_path: &PathBuf) -> Option<IdentityStatus> {
    if crate::factories::storage::open_git_repo(repo_path).is_err() {
        return None;
    }

    let storage = RegistryIdentityStorage::new(repo_path);
    match storage.load_identity() {
        Ok(identity) => Some(IdentityStatus {
            controller_did: identity.controller_did.to_string(),
            alias: None, // Would need to look up from keychain
        }),
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
fn load_devices_summary(repo_path: &PathBuf) -> DevicesSummary {
    if crate::factories::storage::open_git_repo(repo_path).is_err() {
        return DevicesSummary {
            linked: 0,
            revoked: 0,
            expiring_soon: Vec::new(),
            devices_detail: Vec::new(),
        };
    }

    let storage = RegistryAttestationStorage::new(repo_path);
    let attestations = match storage.load_all_attestations() {
        Ok(a) => a,
        Err(_) => {
            return DevicesSummary {
                linked: 0,
                revoked: 0,
                expiring_soon: Vec::new(),
                devices_detail: Vec::new(),
            };
        }
    };

    // Group by device and get latest attestation per device
    let mut latest_by_device: std::collections::HashMap<
        String,
        &auths_verifier::core::Attestation,
    > = std::collections::HashMap::new();

    for att in &attestations {
        let key = att.subject.as_str().to_string();
        latest_by_device
            .entry(key)
            .and_modify(|existing| {
                // Keep the one with later timestamp
                if att.timestamp > existing.timestamp {
                    *existing = att;
                }
            })
            .or_insert(att);
    }

    let now = Utc::now();
    let threshold = now + Duration::days(7);
    let mut linked = 0;
    let mut revoked = 0;
    let mut expiring_soon = Vec::new();
    let mut devices_detail = Vec::new();

    for (device_did, att) in &latest_by_device {
        devices_detail.push(DeviceStatus {
            device_did: device_did.clone(),
            revoked_at: att.revoked_at,
            expires_at: att.expires_at,
        });

        if att.is_revoked() {
            revoked += 1;
        } else {
            linked += 1;
            // Check if expiring soon
            if let Some(expires_at) = att.expires_at
                && expires_at <= threshold
                && expires_at > now
            {
                let days_left = (expires_at - now).num_days();
                expiring_soon.push(ExpiringDevice {
                    device_did: device_did.clone(),
                    expires_in_days: days_left,
                });
            }
        }
    }

    // Sort expiring devices by days remaining
    expiring_soon.sort_by_key(|e| e.expires_in_days);

    DevicesSummary {
        linked,
        revoked,
        expiring_soon,
        devices_detail,
    }
}

/// Get the auths directory path (~/.auths), respecting AUTHS_HOME.
fn get_auths_dir() -> Result<PathBuf> {
    auths_core::paths::auths_home().map_err(|e| anyhow!(e))
}

/// Resolve the repository path from optional argument or default.
fn resolve_repo_path(repo_arg: Option<PathBuf>) -> Result<PathBuf> {
    match repo_arg {
        Some(pathbuf) if !pathbuf.as_os_str().is_empty() => Ok(pathbuf),
        _ => {
            // Try current directory first
            let cwd = std::env::current_dir()?;
            if crate::factories::storage::discover_git_repo(&cwd).is_ok() {
                Ok(cwd)
            } else {
                // Fall back to ~/.auths
                get_auths_dir()
            }
        }
    }
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

/// Truncate a DID for display.
fn truncate_did(did: &str, max_len: usize) -> String {
    if did.len() <= max_len {
        did.to_string()
    } else {
        format!("{}...", &did[..max_len - 3])
    }
}

impl crate::commands::executable::ExecutableCommand for StatusCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_status(self.clone(), ctx.repo_path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_did_short() {
        let did = "did:key:z6Mk";
        assert_eq!(truncate_did(did, 20), did);
    }

    #[test]
    fn test_truncate_did_long() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let truncated = truncate_did(did, 24);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.len(), 24);
    }

    #[test]
    fn test_get_auths_dir() {
        let dir = get_auths_dir().unwrap();
        assert!(dir.ends_with(".auths"));
    }
}
