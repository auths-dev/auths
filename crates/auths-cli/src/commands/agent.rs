//! SSH agent daemon commands (start, stop, status).

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::core::fs::{create_restricted_dir, write_sensitive_file};
use crate::ux::format::{JsonResponse, is_json_mode};

#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

/// Default socket filename within ~/.auths
const DEFAULT_SOCKET_NAME: &str = "agent.sock";
/// PID file name
const PID_FILE_NAME: &str = "agent.pid";
/// Environment file for SSH_AUTH_SOCK
const ENV_FILE_NAME: &str = "agent.env";
/// Log file for daemon output
const LOG_FILE_NAME: &str = "agent.log";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "agent",
    about = "SSH agent daemon management (start, stop, status)."
)]
pub struct AgentCommand {
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentSubcommand {
    /// Start the SSH agent daemon
    Start {
        /// Custom socket path (default: ~/.auths/agent.sock)
        #[arg(long, help = "Custom Unix socket path")]
        socket: Option<PathBuf>,

        /// Run in foreground (don't daemonize)
        #[arg(long, help = "Run in foreground instead of daemonizing")]
        foreground: bool,

        /// Idle timeout (e.g., "30m", "1h", "0" for never)
        #[arg(long, default_value = "30m", help = "Idle timeout before auto-lock")]
        timeout: String,
    },

    /// Stop the SSH agent daemon
    Stop,

    /// Show agent status
    Status,

    /// Output shell environment for SSH_AUTH_SOCK (use with eval)
    Env {
        /// Shell format for output
        #[arg(long, value_enum, default_value = "bash", help = "Shell format")]
        shell: ShellFormat,
    },

    /// Lock the agent (clear keys from memory)
    Lock,

    /// Unlock the agent (re-load keys)
    Unlock {
        /// Key alias to unlock
        #[arg(
            long = "agent-key-alias",
            visible_alias = "key",
            default_value = "default",
            help = "Key alias to unlock"
        )]
        agent_key_alias: String,
    },

    /// Install as a system service (launchd on macOS, systemd on Linux)
    InstallService {
        /// Don't install, just print the service file
        #[arg(long, help = "Print service file without installing")]
        dry_run: bool,

        /// Force overwrite if service already exists
        #[arg(long, help = "Overwrite existing service file")]
        force: bool,

        /// Service manager to use (auto-detect if not specified)
        #[arg(long, value_enum, help = "Service manager (auto-detect by default)")]
        manager: Option<ServiceManager>,
    },

    /// Uninstall the system service
    UninstallService,
}

/// Service manager type for platform-specific service installation
#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum ServiceManager {
    /// macOS launchd
    Launchd,
    /// Linux systemd (user mode)
    Systemd,
}

/// Shell format for environment output
#[derive(ValueEnum, Clone, Debug, Default)]
pub enum ShellFormat {
    #[default]
    Bash,
    Zsh,
    Fish,
}

/// Status information about the agent
#[derive(Serialize, Debug)]
pub struct AgentStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub socket_path: Option<String>,
    pub socket_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
}

/// Ensures the SSH agent is running, starting it if necessary.
///
/// Returns `Ok(true)` if the agent was already running, `Ok(false)` if it was started.
/// Returns an error if the agent could not be started.
///
/// This function can be called from commands that need the agent to be running
/// before performing signing operations, enabling auto-start functionality.
#[allow(dead_code)] // Used by bin/sign.rs (cross-target usage not tracked by lint)
pub fn ensure_agent_running(quiet: bool) -> Result<bool> {
    let socket_path = get_default_socket_path()?;

    // Check if already running
    if let Some(pid) = read_pid()?
        && is_process_running(pid)
        && socket_path.exists()
    {
        return Ok(true); // Already running
    }

    // Start agent
    if !quiet {
        eprintln!("Agent not running, starting...");
    }

    // Use default timeout of 30m
    start_agent(None, false, "30m", quiet)?;

    // Poll for socket with 2s timeout
    let timeout = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if socket_path.exists()
            && let Some(pid) = read_pid()?
            && is_process_running(pid)
        {
            if !quiet {
                eprintln!("Agent started (PID {})", pid);
            }
            return Ok(false); // Just started
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(anyhow!("Failed to start agent within 2 seconds"))
}

pub fn handle_agent(cmd: AgentCommand) -> Result<()> {
    match cmd.command {
        AgentSubcommand::Start {
            socket,
            foreground,
            timeout,
        } => start_agent(socket, foreground, &timeout, false),
        AgentSubcommand::Stop => stop_agent(),
        AgentSubcommand::Status => show_status(),
        AgentSubcommand::Env { shell } => output_env(shell),
        AgentSubcommand::Lock => lock_agent(),
        AgentSubcommand::Unlock { agent_key_alias } => unlock_agent(&agent_key_alias),
        AgentSubcommand::InstallService {
            dry_run,
            force,
            manager,
        } => install_service(dry_run, force, manager),
        AgentSubcommand::UninstallService => uninstall_service(),
    }
}

/// Parse a timeout string like "30m", "1h", "0", "5s"
fn parse_timeout(s: &str) -> Result<std::time::Duration> {
    use std::time::Duration;

    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }

    // Try to parse as number + suffix using strip_suffix
    let (num_str, suffix) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, "h")
    } else {
        // Assume minutes if no suffix
        (s, "m")
    };

    let num: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid timeout number: {}", num_str))?;

    let secs = match suffix {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        _ => return Err(anyhow!("Invalid timeout suffix: {}", suffix)),
    };

    Ok(Duration::from_secs(secs))
}

/// Get the auths directory path (~/.auths), respecting AUTHS_HOME.
fn get_auths_dir() -> Result<PathBuf> {
    auths_core::paths::auths_home().map_err(|e| anyhow!(e))
}

/// Get the default socket path
pub fn get_default_socket_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(DEFAULT_SOCKET_NAME))
}

/// Get the PID file path
fn get_pid_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(PID_FILE_NAME))
}

/// Get the environment file path
fn get_env_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(ENV_FILE_NAME))
}

/// Get the log file path
fn get_log_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(LOG_FILE_NAME))
}

/// Read PID from file
fn read_pid() -> Result<Option<u32>> {
    let pid_path = get_pid_file_path()?;
    if !pid_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&pid_path)
        .with_context(|| format!("Failed to read PID file: {:?}", pid_path))?;

    let pid: u32 = content
        .trim()
        .parse()
        .with_context(|| format!("Invalid PID in file: {}", content.trim()))?;

    Ok(Some(pid))
}

/// Check if a process with the given PID is running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    // Try to send signal 0 (doesn't actually send anything, just checks if process exists)
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    // Windows would need different implementation
    false
}

/// Start the agent
fn start_agent(
    socket_path: Option<PathBuf>,
    foreground: bool,
    timeout_str: &str,
    quiet: bool,
) -> Result<()> {
    let auths_dir = get_auths_dir()?;
    create_restricted_dir(&auths_dir)
        .with_context(|| format!("Failed to create auths directory: {:?}", auths_dir))?;

    let socket = socket_path.unwrap_or_else(|| get_default_socket_path().unwrap());
    let pid_path = get_pid_file_path()?;
    let env_path = get_env_file_path()?;
    let timeout = parse_timeout(timeout_str)?;

    // Check if already running
    if let Some(pid) = read_pid()? {
        if is_process_running(pid) {
            return Err(anyhow!(
                "Agent already running (PID {}). Use 'auths agent stop' first.",
                pid
            ));
        }
        // Stale PID file, clean it up
        let _ = fs::remove_file(&pid_path);
    }

    // Clean up stale socket file
    if socket.exists() {
        fs::remove_file(&socket)
            .with_context(|| format!("Failed to remove stale socket: {:?}", socket))?;
    }

    if foreground {
        // Run in foreground
        run_agent_foreground(&socket, &pid_path, &env_path, timeout)
    } else {
        // Daemonize
        #[cfg(unix)]
        {
            daemonize_agent(
                &socket,
                &pid_path,
                &env_path,
                &get_log_file_path()?,
                timeout_str,
                quiet,
            )
        }
        #[cfg(not(unix))]
        {
            Err(anyhow!(
                "Daemonization not supported on this platform. Use --foreground."
            ))
        }
    }
}

/// Run the agent in the foreground (Unix only)
#[cfg(unix)]
fn run_agent_foreground(
    socket: &PathBuf,
    pid_path: &PathBuf,
    env_path: &PathBuf,
    timeout: std::time::Duration,
) -> Result<()> {
    use auths_core::AgentHandle;
    use std::sync::Arc;

    // Write PID file
    let pid = std::process::id();
    write_sensitive_file(pid_path, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {:?}", pid_path))?;

    // Write environment file
    let socket_str = socket
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;
    let env_content = format!("export SSH_AUTH_SOCK=\"{}\"\n", socket_str);
    write_sensitive_file(env_path, &env_content)
        .with_context(|| format!("Failed to write env file: {:?}", env_path))?;

    eprintln!("Starting SSH agent (foreground)...");
    eprintln!("Socket: {}", socket_str);
    eprintln!("PID: {}", pid);
    if timeout.is_zero() {
        eprintln!("Idle timeout: disabled");
    } else {
        eprintln!("Idle timeout: {:?}", timeout);
    }
    eprintln!();
    eprintln!("To use this agent in your shell:");
    eprintln!("  eval $(cat {})", env_path.display());
    eprintln!("  # or");
    eprintln!("  export SSH_AUTH_SOCK=\"{}\"", socket_str);
    eprintln!();
    eprintln!("Press Ctrl+C to stop.");

    // Create agent handle with timeout
    let handle = Arc::new(AgentHandle::with_pid_file_and_timeout(
        socket.clone(),
        pid_path.clone(),
        timeout,
    ));

    // Run the listener
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    let result = rt.block_on(async {
        auths_core::api::start_agent_listener_with_handle(handle.clone()).await
    });

    // Cleanup on exit
    let _ = fs::remove_file(pid_path);
    let _ = fs::remove_file(env_path);
    let _ = fs::remove_file(socket);

    result.map_err(|e| anyhow!("Agent error: {}", e))
}

/// Run the agent in the foreground (non-Unix stub)
#[cfg(not(unix))]
fn run_agent_foreground(
    _socket: &PathBuf,
    _pid_path: &PathBuf,
    _env_path: &PathBuf,
    _timeout: std::time::Duration,
) -> Result<()> {
    Err(anyhow!(
        "SSH agent is not supported on this platform (requires Unix domain sockets)"
    ))
}

/// Daemonize the agent process (Unix only)
#[cfg(unix)]
fn daemonize_agent(
    socket: &std::path::Path,
    _pid_path: &std::path::Path,
    env_path: &std::path::Path,
    log_path: &std::path::Path,
    timeout_str: &str,
    quiet: bool,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let socket_str = socket
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;

    // Get the path to the current executable
    let exe = std::env::current_exe().context("Failed to get current executable path")?;

    // Fork by re-executing ourselves with --foreground
    // The child will detach and become the daemon
    let log_file = fs::File::create(log_path)
        .with_context(|| format!("Failed to create log file: {:?}", log_path))?;
    let log_file_err = log_file
        .try_clone()
        .context("Failed to clone log file handle")?;

    let mut cmd = Command::new(&exe);
    cmd.arg("agent")
        .arg("start")
        .arg("--foreground")
        .arg("--socket")
        .arg(socket_str)
        .arg("--timeout")
        .arg(timeout_str)
        .stdout(log_file)
        .stderr(log_file_err);

    // Use process_group(0) to create a new process group (detach from terminal)
    unsafe {
        cmd.pre_exec(|| {
            // Create new session (detach from controlling terminal)
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let child = cmd.spawn().context("Failed to spawn daemon process")?;

    if !quiet {
        eprintln!("Agent daemon started (PID {})", child.id());
        eprintln!("Socket: {}", socket_str);
        eprintln!("Log file: {}", log_path.display());
        eprintln!();
        eprintln!("To use this agent:");
        eprintln!("  eval $(auths agent env)");
        eprintln!("  # or");
        eprintln!("  export SSH_AUTH_SOCK=\"{}\"", socket_str);
    }

    // Write environment file for the parent to report
    let env_content = format!("export SSH_AUTH_SOCK=\"{}\"\n", socket_str);
    write_sensitive_file(env_path, &env_content)
        .with_context(|| format!("Failed to write env file: {:?}", env_path))?;

    Ok(())
}

/// Stop the agent
fn stop_agent() -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let socket_path = get_default_socket_path()?;
    let env_path = get_env_file_path()?;

    let pid = read_pid()?
        .ok_or_else(|| anyhow!("Agent not running (no PID file found at {:?})", pid_path))?;

    if !is_process_running(pid) {
        // Process not running, clean up stale files
        eprintln!("Agent process {} not found. Cleaning up stale files.", pid);
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&env_path);
        return Ok(());
    }

    eprintln!("Stopping agent (PID {})...", pid);

    // Send SIGTERM
    #[cfg(unix)]
    {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
            .with_context(|| format!("Failed to send SIGTERM to PID {}", pid))?;
    }

    #[cfg(not(unix))]
    {
        return Err(anyhow!("Stopping agent not supported on this platform"));
    }

    #[cfg(unix)]
    {
        // Wait for process to terminate (with timeout)
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);

        while start.elapsed() < timeout {
            if !is_process_running(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if is_process_running(pid) {
            eprintln!("Process did not terminate gracefully, sending SIGKILL...");
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }

        // Clean up files
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&env_path);

        eprintln!("Agent stopped.");
        Ok(())
    }
}

/// Show agent status
fn show_status() -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let socket_path = get_default_socket_path()?;

    let pid = read_pid()?;
    let running = pid.map(is_process_running).unwrap_or(false);
    let socket_exists = socket_path.exists();

    let status = AgentStatus {
        running,
        pid: if running { pid } else { None },
        socket_path: if socket_exists {
            Some(socket_path.to_string_lossy().to_string())
        } else {
            None
        },
        socket_exists,
        uptime_secs: None, // Would need to track start time to implement
    };

    if is_json_mode() {
        JsonResponse::success("agent status", status).print()?;
    } else if running {
        eprintln!("Agent Status: RUNNING");
        if let Some(p) = status.pid {
            eprintln!("  PID: {}", p);
        }
        if let Some(ref sock) = status.socket_path {
            eprintln!("  Socket: {}", sock);
        }
        eprintln!();
        eprintln!("To use this agent:");
        eprintln!("  eval $(auths agent env)");
    } else {
        eprintln!("Agent Status: STOPPED");
        if pid.is_some() && !running {
            eprintln!("  (Stale PID file found at {:?})", pid_path);
        }
        eprintln!();
        eprintln!("To start the agent:");
        eprintln!("  auths agent start");
    }

    Ok(())
}

/// Output environment variables for shell integration
fn output_env(shell: ShellFormat) -> Result<()> {
    let socket_path = get_default_socket_path()?;

    // Check if agent is running
    let pid = read_pid()?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        eprintln!("Error: Agent is not running.");
        eprintln!("Start the agent with: auths agent start");
        std::process::exit(1);
    }

    // Check if socket exists
    if !socket_path.exists() {
        eprintln!("Error: Socket file not found at {:?}", socket_path);
        eprintln!("The agent may have crashed. Try: auths agent start");
        std::process::exit(1);
    }

    // Get socket path as string
    let socket_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;

    // Output in appropriate shell format
    match shell {
        ShellFormat::Bash | ShellFormat::Zsh => {
            println!("export SSH_AUTH_SOCK=\"{}\"", socket_str);
        }
        ShellFormat::Fish => {
            println!("set -x SSH_AUTH_SOCK \"{}\"", socket_str);
        }
    }

    Ok(())
}

/// Lock the agent (clear keys from memory).
/// IMPORTANT: Uses auths_core::agent::remove_all_identities which relies on Unix
/// domain sockets. Do NOT remove this #[cfg(unix)] — it will break Windows CI.
#[cfg(unix)]
fn lock_agent() -> Result<()> {
    let pid = read_pid()?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_default_socket_path()?;
    auths_core::agent::remove_all_identities(&socket_path)
        .map_err(|e| anyhow!("Failed to lock agent: {}", e))?;

    eprintln!("Agent locked — all keys removed from memory.");
    eprintln!("Use `auths agent unlock <key-alias>` to reload a key.");

    Ok(())
}

#[cfg(not(unix))]
fn lock_agent() -> Result<()> {
    Err(anyhow!(
        "Agent lock is not supported on this platform (requires Unix domain sockets)"
    ))
}

/// Unlock the agent (re-load a key into memory).
/// IMPORTANT: Uses auths_core::agent::add_identity which relies on Unix domain
/// sockets. Do NOT remove this #[cfg(unix)] — it will break Windows CI.
#[cfg(unix)]
fn unlock_agent(key_alias: &str) -> Result<()> {
    let pid = read_pid()?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_default_socket_path()?;

    // Load encrypted key from platform keychain
    let keychain = auths_core::storage::keychain::get_platform_keychain()
        .map_err(|e| anyhow!("Failed to get platform keychain: {}", e))?;
    let (_identity_did, _role, encrypted_data) = keychain
        .load_key(&auths_core::storage::keychain::KeyAlias::new_unchecked(
            key_alias,
        ))
        .map_err(|e| anyhow!("Failed to load key '{}': {}", key_alias, e))?;

    // Prompt for passphrase
    let passphrase = rpassword::prompt_password(format!("Passphrase for '{}': ", key_alias))
        .context("Failed to read passphrase")?;

    // Decrypt the key
    let key_bytes = auths_core::crypto::signer::decrypt_keypair(&encrypted_data, &passphrase)
        .map_err(|e| anyhow!("Failed to decrypt key '{}': {}", key_alias, e))?;

    // Add to agent
    auths_core::agent::add_identity(&socket_path, &key_bytes)
        .map_err(|e| anyhow!("Failed to add key to agent: {}", e))?;

    eprintln!("Agent unlocked — key '{}' loaded.", key_alias);

    Ok(())
}

#[cfg(not(unix))]
fn unlock_agent(_key_alias: &str) -> Result<()> {
    Err(anyhow!(
        "Agent unlock is not supported on this platform (requires Unix domain sockets)"
    ))
}

// --- Service Installation ---

/// Detect the available service manager on the current platform
fn detect_service_manager() -> Option<ServiceManager> {
    #[cfg(target_os = "macos")]
    {
        Some(ServiceManager::Launchd)
    }
    #[cfg(target_os = "linux")]
    {
        // Check if systemd is running
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

/// Get the launchd plist path
fn get_launchd_plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("com.auths.agent.plist"))
}

/// Get the systemd unit file path
fn get_systemd_unit_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home
        .join(".config")
        .join("systemd")
        .join("user")
        .join("auths-agent.service"))
}

/// Generate launchd plist content
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

/// Generate systemd unit file content
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

/// Install the service
fn install_service(dry_run: bool, force: bool, manager: Option<ServiceManager>) -> Result<()> {
    let manager = manager
        .or_else(detect_service_manager)
        .ok_or_else(|| anyhow!("No supported service manager found on this platform"))?;

    match manager {
        ServiceManager::Launchd => install_launchd_service(dry_run, force),
        ServiceManager::Systemd => install_systemd_service(dry_run, force),
    }
}

/// Install launchd service (macOS)
fn install_launchd_service(dry_run: bool, force: bool) -> Result<()> {
    let plist_content = generate_launchd_plist()?;
    let plist_path = get_launchd_plist_path()?;

    if dry_run {
        eprintln!("Would install to: {}", plist_path.display());
        eprintln!();
        println!("{}", plist_content);
        return Ok(());
    }

    // Check if already exists
    if plist_path.exists() && !force {
        return Err(anyhow!(
            "Service already installed at {}. Use --force to overwrite.",
            plist_path.display()
        ));
    }

    // Create parent directory
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    // Write plist file
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

/// Install systemd service (Linux)
fn install_systemd_service(dry_run: bool, force: bool) -> Result<()> {
    let unit_content = generate_systemd_unit()?;
    let unit_path = get_systemd_unit_path()?;

    if dry_run {
        eprintln!("Would install to: {}", unit_path.display());
        eprintln!();
        println!("{}", unit_content);
        return Ok(());
    }

    // Check if already exists
    if unit_path.exists() && !force {
        return Err(anyhow!(
            "Service already installed at {}. Use --force to overwrite.",
            unit_path.display()
        ));
    }

    // Create parent directory
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    // Write unit file
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

/// Uninstall the service
fn uninstall_service() -> Result<()> {
    let manager = detect_service_manager()
        .ok_or_else(|| anyhow!("No supported service manager found on this platform"))?;

    match manager {
        ServiceManager::Launchd => uninstall_launchd_service(),
        ServiceManager::Systemd => uninstall_systemd_service(),
    }
}

/// Uninstall launchd service (macOS)
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

/// Uninstall systemd service (Linux)
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

impl crate::commands::executable::ExecutableCommand for AgentCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_agent(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_auths_dir() {
        let dir = get_auths_dir().unwrap();
        assert!(dir.ends_with(".auths"));
    }

    #[test]
    fn test_get_default_socket_path() {
        let path = get_default_socket_path().unwrap();
        assert!(path.ends_with("agent.sock"));
    }

    #[test]
    fn test_shell_format_default() {
        // Default should be Bash
        let format: ShellFormat = Default::default();
        assert!(matches!(format, ShellFormat::Bash));
    }

    #[test]
    fn test_parse_timeout() {
        use std::time::Duration;

        // Zero timeout
        assert_eq!(parse_timeout("0").unwrap(), Duration::ZERO);

        // Seconds
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));

        // Minutes
        assert_eq!(parse_timeout("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_timeout("30m").unwrap(), Duration::from_secs(1800));

        // Hours
        assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_timeout("2h").unwrap(), Duration::from_secs(7200));

        // No suffix defaults to minutes
        assert_eq!(parse_timeout("30").unwrap(), Duration::from_secs(1800));
    }
}
