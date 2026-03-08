//! Platform-specific service installation (launchd on macOS, systemd on Linux).

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use std::fs;
use std::path::PathBuf;

use super::{get_default_socket_path, get_log_file_path};

/// Service manager type for platform-specific service installation.
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum ServiceManager {
    /// macOS launchd
    Launchd,
    /// Linux systemd (user mode)
    Systemd,
}

/// Detect the available service manager on the current platform.
///
/// Usage:
/// ```ignore
/// let manager = detect_service_manager()
///     .ok_or_else(|| anyhow!("No supported service manager found"))?;
/// ```
pub fn detect_service_manager() -> Option<ServiceManager> {
    #[cfg(target_os = "macos")]
    {
        Some(ServiceManager::Launchd)
    }
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/run/systemd/system").exists() {
            Some(ServiceManager::Systemd)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn get_launchd_plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("com.auths.agent.plist"))
}

fn get_systemd_unit_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home
        .join(".config")
        .join("systemd")
        .join("user")
        .join("auths-agent.service"))
}

fn generate_launchd_plist() -> Result<String> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;
    let exe_str = exe_path
        .to_str()
        .ok_or_else(|| anyhow!("Executable path is not valid UTF-8"))?;

    let socket_path = get_default_socket_path()?;
    let socket_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;

    let log_path = get_log_file_path()?;
    let log_str = log_path
        .to_str()
        .ok_or_else(|| anyhow!("Log path is not valid UTF-8"))?;

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.auths.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>agent</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SSH_AUTH_SOCK</key>
        <string>{socket}</string>
    </dict>
</dict>
</plist>
"#,
        exe = exe_str,
        log = log_str,
        socket = socket_str
    ))
}

fn generate_systemd_unit() -> Result<String> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;
    let exe_str = exe_path
        .to_str()
        .ok_or_else(|| anyhow!("Executable path is not valid UTF-8"))?;

    Ok(format!(
        r#"[Unit]
Description=Auths SSH Agent
Documentation=https://github.com/auths-rs/auths

[Service]
Type=simple
ExecStart={exe} agent start --foreground
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        exe = exe_str
    ))
}

/// Install the agent as a system service.
///
/// Args:
/// * `dry_run`: If true, print the service file without installing.
/// * `force`: If true, overwrite an existing service file.
/// * `manager`: Service manager to use, or auto-detect if `None`.
///
/// Usage:
/// ```ignore
/// install_service(false, false, None)?;
/// ```
pub fn install_service(dry_run: bool, force: bool, manager: Option<ServiceManager>) -> Result<()> {
    let manager = manager
        .or_else(detect_service_manager)
        .ok_or_else(|| anyhow!("No supported service manager found on this platform"))?;

    match manager {
        ServiceManager::Launchd => install_launchd_service(dry_run, force),
        ServiceManager::Systemd => install_systemd_service(dry_run, force),
    }
}

fn install_launchd_service(dry_run: bool, force: bool) -> Result<()> {
    let plist_content = generate_launchd_plist()?;
    let plist_path = get_launchd_plist_path()?;

    if dry_run {
        eprintln!("Would install to: {}", plist_path.display());
        eprintln!();
        println!("{}", plist_content);
        return Ok(());
    }

    if plist_path.exists() && !force {
        return Err(anyhow!(
            "Service already installed at {}. Use --force to overwrite.",
            plist_path.display()
        ));
    }

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    fs::write(&plist_path, &plist_content)
        .with_context(|| format!("Failed to write plist: {:?}", plist_path))?;

    eprintln!("Installed launchd service: {}", plist_path.display());
    eprintln!();
    eprintln!("To start the service now:");
    eprintln!("  launchctl load {}", plist_path.display());
    eprintln!();
    eprintln!("The agent will start automatically on login.");

    Ok(())
}

fn install_systemd_service(dry_run: bool, force: bool) -> Result<()> {
    let unit_content = generate_systemd_unit()?;
    let unit_path = get_systemd_unit_path()?;

    if dry_run {
        eprintln!("Would install to: {}", unit_path.display());
        eprintln!();
        println!("{}", unit_content);
        return Ok(());
    }

    if unit_path.exists() && !force {
        return Err(anyhow!(
            "Service already installed at {}. Use --force to overwrite.",
            unit_path.display()
        ));
    }

    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    fs::write(&unit_path, &unit_content)
        .with_context(|| format!("Failed to write unit file: {:?}", unit_path))?;

    eprintln!("Installed systemd service: {}", unit_path.display());
    eprintln!();
    eprintln!("To enable and start the service:");
    eprintln!("  systemctl --user daemon-reload");
    eprintln!("  systemctl --user enable --now auths-agent");
    eprintln!();
    eprintln!("The agent will start automatically on login.");

    Ok(())
}

/// Uninstall the agent system service.
///
/// Usage:
/// ```ignore
/// uninstall_service()?;
/// ```
pub fn uninstall_service() -> Result<()> {
    let manager = detect_service_manager()
        .ok_or_else(|| anyhow!("No supported service manager found on this platform"))?;

    match manager {
        ServiceManager::Launchd => uninstall_launchd_service(),
        ServiceManager::Systemd => uninstall_systemd_service(),
    }
}

fn uninstall_launchd_service() -> Result<()> {
    let plist_path = get_launchd_plist_path()?;

    if !plist_path.exists() {
        return Err(anyhow!("Service not installed at {}", plist_path.display()));
    }

    eprintln!("Unloading launchd service...");
    let _ = std::process::Command::new("launchctl")
        .arg("unload")
        .arg(&plist_path)
        .status();

    fs::remove_file(&plist_path)
        .with_context(|| format!("Failed to remove plist: {:?}", plist_path))?;

    eprintln!("Uninstalled launchd service: {}", plist_path.display());
    Ok(())
}

fn uninstall_systemd_service() -> Result<()> {
    let unit_path = get_systemd_unit_path()?;

    if !unit_path.exists() {
        return Err(anyhow!("Service not installed at {}", unit_path.display()));
    }

    eprintln!("Stopping and disabling systemd service...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "auths-agent"])
        .status();

    fs::remove_file(&unit_path)
        .with_context(|| format!("Failed to remove unit file: {:?}", unit_path))?;

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    eprintln!("Uninstalled systemd service: {}", unit_path.display());
    Ok(())
}
