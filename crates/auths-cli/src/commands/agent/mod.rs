//! SSH agent daemon commands (start, stop, status).

pub mod process;
pub mod service;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::core::fs::{create_restricted_dir, write_sensitive_file};
use crate::ux::format::{JsonResponse, is_json_mode};
use process::{
    cleanup_stale_files, is_process_running, read_pid_file, socket_is_connectable, write_pid_file,
};
use service::ServiceManager;

const DEFAULT_SOCKET_NAME: &str = "agent.sock";
const PID_FILE_NAME: &str = "agent.pid";
const ENV_FILE_NAME: &str = "agent.env";
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

/// Shell format for environment output.
#[derive(ValueEnum, Clone, Debug, Default)]
pub enum ShellFormat {
    #[default]
    Bash,
    Zsh,
    Fish,
}

/// Status information about the agent.
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
/// Returns `Ok(true)` if already running, `Ok(false)` if it was started.
///
/// Args:
/// * `quiet`: Suppress startup messages.
///
/// Usage:
/// ```ignore
/// let was_running = ensure_agent_running(true)?;
/// ```
#[allow(dead_code)] // Used by bin/sign.rs (cross-target usage not tracked by lint)
pub fn ensure_agent_running(quiet: bool) -> Result<bool> {
    let socket_path = get_default_socket_path()?;
    let pid_path = get_pid_file_path()?;

    if let Some(pid) = read_pid_file(&pid_path)?
        && is_process_running(pid)
        && socket_is_connectable(&socket_path)
    {
        return Ok(true);
    }

    if !quiet {
        eprintln!("Agent not running, starting...");
    }

    start_agent(None, false, "30m", quiet)?;

    let timeout = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(pid) = read_pid_file(&pid_path)?
            && is_process_running(pid)
            && socket_is_connectable(&socket_path)
        {
            if !quiet {
                eprintln!("Agent started (PID {})", pid);
            }
            return Ok(false);
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
        } => service::install_service(dry_run, force, manager),
        AgentSubcommand::UninstallService => service::uninstall_service(),
    }
}

fn parse_timeout(s: &str) -> Result<std::time::Duration> {
    use std::time::Duration;

    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }

    let (num_str, suffix) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, "h")
    } else {
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

fn get_auths_dir() -> Result<PathBuf> {
    auths_sdk::paths::auths_home().map_err(|e| anyhow!(e))
}

/// Get the default socket path.
pub fn get_default_socket_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(DEFAULT_SOCKET_NAME))
}

fn get_pid_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(PID_FILE_NAME))
}

fn get_env_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(ENV_FILE_NAME))
}

pub(crate) fn get_log_file_path() -> Result<PathBuf> {
    Ok(get_auths_dir()?.join(LOG_FILE_NAME))
}

fn start_agent(
    socket_path: Option<PathBuf>,
    foreground: bool,
    timeout_str: &str,
    quiet: bool,
) -> Result<()> {
    let auths_dir = get_auths_dir()?;
    create_restricted_dir(&auths_dir)
        .with_context(|| format!("Failed to create auths directory: {:?}", auths_dir))?;

    let socket = match socket_path {
        Some(s) => s,
        None => get_default_socket_path()?,
    };
    let pid_path = get_pid_file_path()?;
    let env_path = get_env_file_path()?;
    let timeout = parse_timeout(timeout_str)?;

    if let Some(pid) = read_pid_file(&pid_path)? {
        if is_process_running(pid) {
            return Err(anyhow!(
                "Agent already running (PID {}). Use 'auths agent stop' first.",
                pid
            ));
        }
        let _ = fs::remove_file(&pid_path);
    }

    match fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow!("Failed to remove stale socket {:?}: {}", socket, e));
        }
    }

    if foreground {
        run_agent_foreground(&socket, &pid_path, &env_path, timeout)
    } else {
        daemonize_agent(&socket, &env_path, timeout_str, quiet)
    }
}

#[cfg(unix)]
fn run_agent_foreground(
    socket: &std::path::Path,
    pid_path: &std::path::Path,
    env_path: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<()> {
    use auths_sdk::agent_core::AgentHandle;
    use std::sync::Arc;

    let pid = std::process::id();
    write_pid_file(pid_path, pid)?;

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

    let handle = Arc::new(AgentHandle::with_pid_file_and_timeout(
        socket.to_path_buf(),
        pid_path.to_path_buf(),
        timeout,
    ));

    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    let result = rt.block_on(async {
        auths_sdk::agent_core::start_agent_listener_with_handle(handle.clone()).await
    });

    cleanup_stale_files(&[pid_path, env_path, socket]);

    result.map_err(|e| anyhow!("Agent error: {}", e))
}

#[cfg(not(unix))]
fn run_agent_foreground(
    _socket: &std::path::Path,
    _pid_path: &std::path::Path,
    _env_path: &std::path::Path,
    _timeout: std::time::Duration,
) -> Result<()> {
    Err(anyhow!(
        "SSH agent is not supported on this platform (requires Unix domain sockets)"
    ))
}

#[cfg(unix)]
fn daemonize_agent(
    socket: &std::path::Path,
    env_path: &std::path::Path,
    timeout_str: &str,
    quiet: bool,
) -> Result<()> {
    let socket_str = socket
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;

    let log_path = get_log_file_path()?;
    let child_pid = process::spawn_detached(
        &[
            "agent",
            "start",
            "--foreground",
            "--socket",
            socket_str,
            "--timeout",
            timeout_str,
        ],
        &log_path,
    )?;

    if !quiet {
        eprintln!("Agent daemon started (PID {})", child_pid);
        eprintln!("Socket: {}", socket_str);
        eprintln!("Log file: {}", log_path.display());
        eprintln!();
        eprintln!("To use this agent:");
        eprintln!("  eval $(auths agent env)");
        eprintln!("  # or");
        eprintln!("  export SSH_AUTH_SOCK=\"{}\"", socket_str);
    }

    let env_content = format!("export SSH_AUTH_SOCK=\"{}\"\n", socket_str);
    write_sensitive_file(env_path, &env_content)
        .with_context(|| format!("Failed to write env file: {:?}", env_path))?;

    Ok(())
}

#[cfg(not(unix))]
fn daemonize_agent(
    _socket: &std::path::Path,
    _env_path: &std::path::Path,
    _timeout_str: &str,
    _quiet: bool,
) -> Result<()> {
    Err(anyhow!(
        "Daemonization not supported on this platform. Use --foreground."
    ))
}

fn stop_agent() -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let socket_path = get_default_socket_path()?;
    let env_path = get_env_file_path()?;

    let pid = read_pid_file(&pid_path)?
        .ok_or_else(|| anyhow!("Agent not running (no PID file found at {:?})", pid_path))?;

    if !is_process_running(pid) {
        eprintln!("Agent process {} not found. Cleaning up stale files.", pid);
        cleanup_stale_files(&[&pid_path, &socket_path, &env_path]);
        return Ok(());
    }

    eprintln!("Stopping agent (PID {})...", pid);
    process::terminate_process(pid, std::time::Duration::from_secs(5))?;
    cleanup_stale_files(&[&pid_path, &socket_path, &env_path]);
    eprintln!("Agent stopped.");
    Ok(())
}

fn show_status() -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let socket_path = get_default_socket_path()?;

    let pid = read_pid_file(&pid_path)?;
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
        uptime_secs: None,
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

fn output_env(shell: ShellFormat) -> Result<()> {
    let socket_path = get_default_socket_path()?;
    let pid_path = get_pid_file_path()?;

    let pid = read_pid_file(&pid_path)?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        eprintln!("Error: Agent is not running.");
        eprintln!("Start the agent with: auths agent start");
        std::process::exit(1);
    }

    if !socket_path.exists() {
        eprintln!("Error: Socket file not found at {:?}", socket_path);
        eprintln!("The agent may have crashed. Try: auths agent start");
        std::process::exit(1);
    }

    let socket_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow!("Socket path is not valid UTF-8"))?;

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

#[cfg(unix)]
fn lock_agent() -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let pid = read_pid_file(&pid_path)?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_default_socket_path()?;
    auths_sdk::agent_core::remove_all_identities(&socket_path)
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

#[cfg(unix)]
fn unlock_agent(key_alias: &str) -> Result<()> {
    let pid_path = get_pid_file_path()?;
    let pid = read_pid_file(&pid_path)?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_default_socket_path()?;

    let keychain = auths_sdk::keychain::get_platform_keychain()
        .map_err(|e| anyhow!("Failed to get platform keychain: {}", e))?;
    let (_identity_did, _role, encrypted_data) = keychain
        .load_key(&auths_sdk::keychain::KeyAlias::new_unchecked(key_alias))
        .map_err(|e| anyhow!("Failed to load key '{}': {}", key_alias, e))?;

    let passphrase = rpassword::prompt_password(format!("Passphrase for '{}': ", key_alias))
        .context("Failed to read passphrase")?;

    let key_bytes = auths_sdk::crypto::decrypt_keypair(&encrypted_data, &passphrase)
        .map_err(|e| anyhow!("Failed to decrypt key '{}': {}", key_alias, e))?;

    auths_sdk::agent_core::add_identity(&socket_path, &key_bytes)
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
        let format: ShellFormat = Default::default();
        assert!(matches!(format, ShellFormat::Bash));
    }

    #[test]
    fn test_parse_timeout() {
        use std::time::Duration;

        assert_eq!(parse_timeout("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_timeout("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_timeout("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_timeout("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_timeout("30").unwrap(), Duration::from_secs(1800));
    }
}
