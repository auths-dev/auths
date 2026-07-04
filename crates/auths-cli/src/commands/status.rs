//! Status overview command for Auths.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Result, anyhow};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::KeyStorage;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::RegistryIdentityStorage;
use auths_sdk::storage_layout::layout;
use auths_sdk::workflows::status::StatusWorkflow;
use chrono::{DateTime, Utc};
use clap::Parser;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

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
    /// The identity's designated witness set (D.9), when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<WitnessSummary>,
}

/// Designated witness set for the identity (presentation of `WitnessConfig`).
#[derive(Debug, Serialize)]
pub struct WitnessSummary {
    /// Number of designated witnesses (`b[]` size).
    pub designated: usize,
    /// Required receipts threshold (`bt`).
    pub threshold: usize,
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
    /// The device the user is on right now (the root signing device). Always
    /// counted — "Devices: none" seconds after init authorized this machine
    /// reads as "setup didn't take".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub this_device: Option<String>,
    pub linked: usize,
    pub revoked: usize,
    pub unanchored: usize,
    pub expiring_soon: Vec<ExpiringDevice>,
    pub devices_detail: Vec<DeviceStatus>,
}

/// Per-device status for expiry display.
#[derive(Debug, Serialize)]
pub struct DeviceStatus {
    pub device_did: String,
    pub status: String,
    pub anchored: bool,
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
    let devices = load_devices_summary(&repo_path, env_config);

    // Next steps come from the one SDK-owned rule set (which includes the recovery
    // single-point-of-failure signpost); the CLI maps each device to its readiness and renders.
    let device_readinesses: Vec<_> = devices
        .devices_detail
        .iter()
        .map(|d| StatusWorkflow::compute_readiness(d.expires_at, d.revoked_at, now))
        .collect();
    let next_steps = StatusWorkflow::next_steps_from_readiness(
        identity.is_some(),
        &device_readinesses,
        agent.running,
    )
    .into_iter()
    .map(|s| NextStep {
        summary: s.summary,
        command: s.command,
    })
    .collect();

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

    // Shared-identity duplicity surfaces at the top so users see it
    // before anything else. Fail-open: exit code stays 0 regardless.
    if let Some(warning) = maybe_format_duplicity_warning(report) {
        out.println(&warning);
        out.newline();
    }

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
        match &id.witnesses {
            Some(w) => out.println(&format!(
                "Witnesses:   {} designated, threshold {}",
                w.designated, w.threshold
            )),
            None => out.println(&format!("Witnesses:   {}", out.dim("none designated"))),
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

    // Devices — the machine the user is on always counts.
    let mut parts = Vec::new();
    if let Some(ref this_device) = report.devices.this_device {
        parts.push(format!("this device ({})", out.dim(this_device)));
    }
    if report.devices.linked > 0 {
        parts.push(format!("{} other linked", report.devices.linked));
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

/// Render the pinned duplicity warning when the local KEL stream
/// contains a diverging rotation.
///
/// Walks `refs/auths/shared-kel/*` via git2, turns each matching ref
/// into a [`KelEventRef`] (prefix + sequence + SAID), and asks the
/// duplicity detector whether any same-prefix same-seq events carry
/// differing SAIDs. Fail-open: returns `None` if no shared KEL is
/// replicated locally or if the scan errors (a missing shared KEL is
/// the pre-first-pair norm, not an error state).
fn maybe_format_duplicity_warning(_report: &StatusReport) -> Option<String> {
    use auths_sdk::keri::copy::format_duplicity_warning;
    use auths_sdk::verify::{DuplicityReport, KelEventRef, detect_duplicity};

    // Resolve the auths home repo. Any failure → None (pre-first-pair
    // case is the common one; not worth a log line).
    let auths_dir = match auths_sdk::paths::auths_home() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let repo = match git2::Repository::open(&auths_dir) {
        Ok(r) => r,
        Err(_) => return None,
    };

    // Scan refs under the shared-KEL namespace. Ref names have the
    // shape `refs/auths/shared-kel/<prefix>/<seq>/<said-or-role>`;
    // we extract prefix + seq and treat the ref target OID as the
    // SAID for divergence purposes (two refs at the same (prefix,
    // seq) with different OIDs indicates a fork in the local replica).
    let prefix_str = "refs/auths/shared-kel/";
    let mut rows: Vec<(String, u64, String)> = Vec::new();
    let refs = match repo.references() {
        Ok(r) => r,
        Err(_) => return None,
    };
    for r in refs.filter_map(|r| r.ok()) {
        let Ok(name) = r.name() else { continue };
        let Some(rest) = name.strip_prefix(prefix_str) else {
            continue;
        };
        let mut parts = rest.splitn(3, '/');
        let Some(prefix) = parts.next() else { continue };
        let Some(seq_str) = parts.next() else {
            continue;
        };
        let Ok(seq) = seq_str.parse::<u64>() else {
            continue;
        };
        let said = r.target().map(|oid| oid.to_string()).unwrap_or_default();
        if said.is_empty() {
            continue;
        }
        rows.push((prefix.to_string(), seq, said));
    }

    if rows.is_empty() {
        return None;
    }

    // Build KelEventRefs on borrowed storage. `detect_duplicity`
    // returns the first divergence it finds.
    let events: Vec<KelEventRef<'_>> = rows
        .iter()
        .map(|(prefix, seq, said)| KelEventRef {
            prefix: prefix.as_str(),
            seq: *seq,
            said: said.as_str(),
        })
        .collect();

    match detect_duplicity(&events) {
        DuplicityReport::Clean => None,
        DuplicityReport::Diverging { seq, .. } => Some(format_duplicity_warning(seq)),
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

            let witnesses = identity
                .metadata
                .as_ref()
                .and_then(|m| m.get("witness_config"))
                .and_then(|wc| {
                    serde_json::from_value::<auths_sdk::witness::WitnessConfig>(wc.clone()).ok()
                })
                .filter(|c| !c.witnesses.is_empty())
                .map(|c| WitnessSummary {
                    designated: c.witnesses.len(),
                    threshold: c.threshold,
                });

            Some(IdentityStatus {
                controller_did: identity.controller_did.to_string(),
                alias: None,
                key_aliases,
                witnesses,
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

/// Load the devices summary from the delegation set (live = delegated − revoked).
fn load_devices_summary(repo_path: &Path, env_config: &EnvironmentConfig) -> DevicesSummary {
    let empty = DevicesSummary {
        this_device: None,
        linked: 0,
        revoked: 0,
        unanchored: 0,
        expiring_soon: Vec::new(),
        devices_detail: Vec::new(),
    };

    let ctx = match crate::factories::storage::build_auths_context(repo_path, env_config, None) {
        Ok(ctx) => ctx,
        Err(_) => return empty,
    };
    let this_device = auths_sdk::domains::identity::local::resolve_local_signer(&ctx)
        .ok()
        .map(|signer| signer.signer_did.to_string());
    let devices = match auths_sdk::domains::device::list_delegated_devices(&ctx) {
        Ok(devices) => devices,
        Err(_) => {
            return DevicesSummary {
                this_device,
                ..empty
            };
        }
    };

    let mut linked = 0;
    let mut revoked = 0;
    let mut devices_detail = Vec::new();
    for device in devices {
        if device.revoked {
            revoked += 1;
        } else {
            linked += 1;
        }
        devices_detail.push(DeviceStatus {
            device_did: device.device_did,
            status: if device.revoked {
                "revoked".to_string()
            } else {
                "active".to_string()
            },
            anchored: true,
            revoked_at: None,
            expires_at: None,
            expires_in: None,
        });
    }

    // KERI delegation carries no timestamps: no expiry / expiring-soon set, and a
    // delegated device is inherently anchored.
    DevicesSummary {
        this_device,
        linked,
        revoked,
        unanchored: 0,
        expiring_soon: Vec::new(),
        devices_detail,
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
/// Check if a process with the given PID is running.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

/// Windows: a PID is running if we can open it and `GetExitCodeProcess`
/// reports `STILL_ACTIVE` (259). `OpenProcess` failing (no such PID, or access
/// denied) is treated as not-running, matching the Unix `kill(pid, 0)` check.
#[cfg(windows)]
fn is_process_running(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    // SAFETY: standard Win32 open/query/close of a process handle; the handle is
    // always closed, and all pointers point to live stack locals.
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut code: u32 = 0;
        let running = GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE;
        let _ = CloseHandle(handle);
        running
    }
}

#[cfg(not(any(unix, windows)))]
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
    use chrono::Duration;
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
                witnesses: None,
            }),
            agent: AgentStatusInfo {
                running: true,
                pid: Some(12345),
                socket_path: Some("/tmp/agent.sock".to_string()),
            },
            devices: DevicesSummary {
                this_device: Some("did:keri:EThisDevice".to_string()),
                linked: 2,
                revoked: 1,
                unanchored: 0,
                expiring_soon: vec![ExpiringDevice {
                    device_did: "did:key:zExpiringSoon".to_string(),
                    expires_in: 259_200,
                }],
                devices_detail: vec![
                    DeviceStatus {
                        device_did: "did:key:zActiveDevice".to_string(),
                        status: "active".to_string(),
                        anchored: true,
                        revoked_at: None,
                        expires_at: Some(now + Duration::days(90)),
                        expires_in: Some(7_776_000),
                    },
                    DeviceStatus {
                        device_did: "did:key:zExpiringSoon".to_string(),
                        status: "expiring_soon".to_string(),
                        anchored: true,
                        revoked_at: None,
                        expires_at: Some(now + Duration::days(3)),
                        expires_in: Some(259_200),
                    },
                    DeviceStatus {
                        device_did: "did:key:zRevokedDevice".to_string(),
                        status: "revoked".to_string(),
                        anchored: true,
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

    #[test]
    fn status_shows_witness_set() {
        let id = IdentityStatus {
            controller_did: "did:keri:E1".to_string(),
            alias: None,
            key_aliases: vec![],
            witnesses: Some(WitnessSummary {
                designated: 3,
                threshold: 2,
            }),
        };
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.contains("\"designated\":3"));
        assert!(json.contains("\"threshold\":2"));
    }
}
