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

    /// Provision a new delegated headless agent in a single command
    Provision {
        /// Human-readable label / key alias for the new agent
        #[arg(short, long, help = "Label / key alias for the new agent")]
        label: Option<String>,

        /// Delegator signing key alias (defaults to "main")
        #[arg(long, help = "Your root identity's signing key name")]
        key: Option<String>,

        /// Capability granted to the agent (repeatable)
        #[arg(long = "scope", help = "Capability granted to the agent")]
        scope: Vec<auths_keri::Capability>,

        /// Expiration duration in seconds (e.g. 2592000 for 30 days)
        #[arg(long = "expires-in", help = "Expiration duration in seconds")]
        expires_in: Option<i64>,

        /// Destination directory for agent environment workspace (defaults to ~/.auths-agents/<label>/)
        #[arg(short, long, help = "Output directory for agent environment")]
        out: Option<PathBuf>,

        /// Provisioning profile: "ci" or "assistant"
        #[arg(long, help = "Agent profile preset")]
        profile: Option<String>,

        /// Passphrase file path (optional, auto-generated if absent)
        #[arg(long, help = "Passphrase file path")]
        passphrase_file: Option<PathBuf>,
    },

    /// List all agents delegated under your identity
    List {
        /// Include revoked agents in listing
        #[arg(long, help = "Include revoked agents")]
        include_revoked: bool,
    },

    /// Update mutable agent metadata or renew expiration
    Update {
        /// Target Agent DID or label
        agent: String,

        /// Update human label / agent name
        #[arg(short, long)]
        label: Option<String>,

        /// Extend expiration duration in seconds
        #[arg(long)]
        extend_expiration: Option<i64>,
    },

    /// Revoke a delegated agent identity
    Revoke {
        /// Target Agent DID or label to revoke
        agent_did: String,

        /// Delegator signing key alias
        #[arg(long, default_value = "main", help = "Your root identity's signing key name")]
        key: String,
    },
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

/// The name of a per-machine daemon operation, or `None` for a store operation.
///
/// Daemon operations (start/stop/status/install-service/uninstall-service) act
/// on the per-machine agent and cannot be scoped by `--repo`. Store operations
/// (env/lock/unlock) read repo-scoped paths.
fn daemon_op_name(cmd: &AgentSubcommand) -> Option<&'static str> {
    match cmd {
        AgentSubcommand::Start { .. } => Some("start"),
        AgentSubcommand::Stop => Some("stop"),
        AgentSubcommand::Status => Some("status"),
        AgentSubcommand::InstallService { .. } => Some("install-service"),
        AgentSubcommand::UninstallService => Some("uninstall-service"),
        AgentSubcommand::Env { .. }
        | AgentSubcommand::Lock
        | AgentSubcommand::Unlock { .. }
        | AgentSubcommand::Provision { .. }
        | AgentSubcommand::List { .. }
        | AgentSubcommand::Update { .. }
        | AgentSubcommand::Revoke { .. } => None,
    }
}

pub fn handle_agent(cmd: AgentCommand, repo: Option<PathBuf>) -> Result<()> {
    // Daemon operations are per-machine; `--repo` cannot scope them, so reject
    // it rather than silently operate on the global agent.
    if let Some(op) = daemon_op_name(&cmd.command)
        && repo.is_some()
    {
        anyhow::bail!(
            "`--repo` is not supported for `auths agent {}`; the agent daemon is per-machine \
             and is selected by AUTHS_HOME, not by repository.",
            op
        );
    }

    match cmd.command {
        AgentSubcommand::Start {
            socket,
            foreground,
            timeout,
        } => start_agent(socket, foreground, &timeout, false),
        AgentSubcommand::Stop => stop_agent(),
        AgentSubcommand::Status => show_status(),
        AgentSubcommand::InstallService {
            dry_run,
            force,
            manager,
        } => service::install_service(dry_run, force, manager),
        AgentSubcommand::UninstallService => service::uninstall_service(),
        // Store operations read repo-scoped paths; thread `--repo` through.
        AgentSubcommand::Env { shell } => output_env(shell, repo),
        AgentSubcommand::Lock => lock_agent(repo),
        AgentSubcommand::Unlock { agent_key_alias } => unlock_agent(&agent_key_alias, repo),
        AgentSubcommand::Provision {
            label,
            key,
            scope,
            expires_in,
            out,
            profile,
            passphrase_file,
        } => handle_provision_cmd(label, key, scope, expires_in, out, profile, passphrase_file, repo),
        AgentSubcommand::List { include_revoked } => handle_list_cmd(include_revoked, repo),
        AgentSubcommand::Update {
            agent,
            label,
            extend_expiration,
        } => handle_update_cmd(agent, label, extend_expiration),
        AgentSubcommand::Revoke { agent_did, key } => handle_revoke_cmd(agent_did, key, repo),
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

/// Resolve the agent's storage directory, honoring a `--repo` override.
///
/// `None` preserves the default (`AUTHS_HOME` / `~/.auths`); `Some(path)`
/// scopes the agent's socket/pid/env files to that registry.
///
/// Args:
/// * `repo`: The optional `--repo` override.
///
/// Usage:
/// ```ignore
/// let dir = get_auths_dir_for_repo(ctx.repo_path.clone())?;
/// ```
fn get_auths_dir_for_repo(repo: Option<PathBuf>) -> Result<PathBuf> {
    match repo {
        Some(_) => auths_sdk::storage_layout::resolve_repo_path(repo)
            .context("Failed to resolve the repository path for the agent store"),
        None => get_auths_dir(),
    }
}

fn get_socket_path_for_repo(repo: Option<PathBuf>) -> Result<PathBuf> {
    Ok(get_auths_dir_for_repo(repo)?.join(DEFAULT_SOCKET_NAME))
}

fn get_pid_file_path_for_repo(repo: Option<PathBuf>) -> Result<PathBuf> {
    Ok(get_auths_dir_for_repo(repo)?.join(PID_FILE_NAME))
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

    let authorizer = build_sign_authorizer({
        use std::io::IsTerminal;
        std::io::stdin().is_terminal()
    });

    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    let result = rt.block_on(async {
        auths_sdk::agent_core::start_agent_listener_with_handle(handle.clone(), authorizer).await
    });

    cleanup_stale_files(&[pid_path, env_path, socket]);

    result.map_err(|e| anyhow!("Agent error: {}", e))
}

/// Builds the per-request signing authorizer for the agent. An interactive agent gates
/// each new connecting process behind an approval prompt (so an unlocked agent does not
/// grant silent signing to every same-user process); a daemonized / non-interactive
/// agent is permissive, since there is no human present to approve.
///
/// Args:
/// * `interactive`: whether the agent has a terminal to prompt on.
///
/// Usage:
/// ```ignore
/// let auth = build_sign_authorizer(std::io::stdin().is_terminal());
/// ```
#[cfg(unix)]
fn build_sign_authorizer(
    interactive: bool,
) -> std::sync::Arc<dyn auths_sdk::agent_core::SignAuthorizer> {
    if interactive {
        std::sync::Arc::new(auths_sdk::agent_core::PerCallerAuthorizer::new(
            approve_caller,
        ))
    } else {
        std::sync::Arc::new(auths_sdk::agent_core::AllowAllSigning)
    }
}

/// Prompts the operator to approve signing for a newly connected caller. Returns true to
/// approve and pin that caller for the unlock window.
///
/// Args:
/// * `peer`: the connecting process's identity.
///
/// Usage:
/// ```ignore
/// let approved = approve_caller(&peer);
/// ```
#[cfg(unix)]
fn approve_caller(peer: &auths_sdk::agent_core::PeerIdentity) -> bool {
    let who = match peer.pid {
        Some(pid) => format!("process pid {pid} (uid {})", peer.uid),
        None => format!("a process (uid {})", peer.uid),
    };
    eprintln!("\nauths agent: a new caller — {who} — is requesting a signature.");
    dialoguer::Confirm::new()
        .with_prompt("Approve signing for this caller?")
        .default(false)
        .interact()
        .unwrap_or(false)
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

fn output_env(shell: ShellFormat, repo: Option<PathBuf>) -> Result<()> {
    let socket_path = get_socket_path_for_repo(repo.clone())?;
    let pid_path = get_pid_file_path_for_repo(repo)?;

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
fn lock_agent(repo: Option<PathBuf>) -> Result<()> {
    let pid_path = get_pid_file_path_for_repo(repo.clone())?;
    let pid = read_pid_file(&pid_path)?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_socket_path_for_repo(repo)?;
    auths_sdk::agent_core::remove_all_identities(&socket_path)
        .map_err(|e| anyhow!("Failed to lock agent: {}", e))?;

    eprintln!("Agent locked — all keys removed from memory.");
    eprintln!("Use `auths agent unlock <key-alias>` to reload a key.");

    Ok(())
}

#[cfg(not(unix))]
fn lock_agent(_repo: Option<PathBuf>) -> Result<()> {
    Err(anyhow!(
        "Agent lock is not supported on this platform (requires Unix domain sockets)"
    ))
}

#[cfg(unix)]
fn unlock_agent(key_alias: &str, repo: Option<PathBuf>) -> Result<()> {
    let pid_path = get_pid_file_path_for_repo(repo.clone())?;
    let pid = read_pid_file(&pid_path)?;
    let running = pid.map(is_process_running).unwrap_or(false);

    if !running {
        return Err(anyhow!("Agent is not running"));
    }

    let socket_path = get_socket_path_for_repo(repo)?;

    let keychain = auths_sdk::keychain::get_platform_keychain()
        .map_err(|e| anyhow!("Failed to get platform keychain: {}", e))?;

    if keychain.is_hardware_backend() {
        return Err(anyhow!(
            "Agent-mode signing requires a software-backed key. Key '{}' is hardware-backed \
             (Secure Enclave) and cannot export raw key material needed by the SSH agent. \
             Use direct signing instead (which dispatches through the Secure Enclave), \
             or initialize a separate software-backed identity for agent use.",
            key_alias
        ));
    }

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
fn unlock_agent(_key_alias: &str, _repo: Option<PathBuf>) -> Result<()> {
    Err(anyhow!(
        "Agent unlock is not supported on this platform (requires Unix domain sockets)"
    ))
}

#[derive(Serialize)]
struct AgentProvisionJsonResponse {
    agent_did: String,
    label: String,
    destination_dir: String,
    env_file_path: String,
    wrapper_path: String,
}

#[allow(clippy::too_many_arguments)]
fn handle_provision_cmd(
    label: Option<String>,
    key: Option<String>,
    scope: Vec<auths_keri::Capability>,
    expires_in: Option<i64>,
    out: Option<PathBuf>,
    profile: Option<String>,
    passphrase_file: Option<PathBuf>,
    repo: Option<PathBuf>,
) -> Result<()> {
    use std::path::Path;
    use auths_core::paths::auths_home;
    use auths_sdk::keychain::KeyAlias;
    use auths_sdk::storage_layout::resolve_repo_path;
    use crate::core::provider::CliPassphraseProvider;

    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let passphrase_provider = std::sync::Arc::new(CliPassphraseProvider::new());
    let ctx = crate::factories::storage::build_auths_context(&repo_path, &env_config, Some(passphrase_provider))?;

    let is_interactive = console::user_attended() && !is_json_mode();

    let (label_str, key_str, profile_str, destination_dir) = if is_interactive && (label.is_none() || key.is_none() || profile.is_none()) {
        use dialoguer::{Input, Select};

        let label_input = if let Some(l) = label {
            l
        } else {
            Input::new()
                .with_prompt("Type a name for your agent")
                .interact_text()?
        };

        let key_input = if let Some(k) = key {
            k
        } else {
            let aliases = ctx.key_storage.list_aliases().unwrap_or_default();
            let key_items: Vec<String> = if aliases.is_empty() {
                vec!["main".to_string()]
            } else {
                aliases
                    .into_iter()
                    .map(|k| k.as_str().to_string())
                    .filter(|k| !k.ends_with("--next-0"))
                    .collect()
            };

            if key_items.len() > 1 {
                let selection = Select::new()
                    .with_prompt("Select parent key to append delegation to")
                    .items(&key_items)
                    .default(0)
                    .interact()?;
                key_items[selection].clone()
            } else {
                key_items.first().cloned().unwrap_or_else(|| "main".to_string())
            }
        };

        let profile_input = if let Some(p) = profile {
            p
        } else {
            let profiles = vec![
                "assistant (Interactive AI assistant profile)",
                "ci (Headless CI runner profile)",
            ];
            let selection = Select::new()
                .with_prompt("Select agent profile preset")
                .items(&profiles)
                .default(0)
                .interact()?;
            if selection == 0 {
                "assistant".to_string()
            } else {
                "ci".to_string()
            }
        };

        let out_input = out.unwrap_or_else(|| {
            auths_home()
                .unwrap_or_else(|_| PathBuf::from("~/.auths"))
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(".auths-agents")
                .join(&label_input)
        });

        (label_input, key_input, profile_input, out_input)
    } else {
        let label_val = label.unwrap_or_else(|| "agent-builder".to_string());
        let key_val = key.unwrap_or_else(|| "main".to_string());
        let profile_val = profile.unwrap_or_else(|| "assistant".to_string());
        let out_val = out.unwrap_or_else(|| {
            auths_home()
                .unwrap_or_else(|_| PathBuf::from("~/.auths"))
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(".auths-agents")
                .join(&label_val)
        });
        (label_val, key_val, profile_val, out_val)
    };

    let parent_alias = KeyAlias::new_unchecked(&key_str);
    let agent_profile = profile_str.parse::<auths_sdk::workflows::agent_provision::AgentProfile>()?;

    let passphrase = if let Some(p_file) = &passphrase_file {
        std::fs::read_to_string(p_file)
            .with_context(|| format!("Failed to read passphrase file {}", p_file.display()))?
            .trim()
            .to_string()
    } else {
        use rand::Rng;
        let mut rng = rand::rng();
        (0..32)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect()
    };

    let params = auths_sdk::workflows::agent_provision::AgentProvisionParams {
        label: label_str.clone(),
        scopes: scope,
        expires_in_secs: expires_in,
        destination_dir,
        profile: agent_profile,
    };

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let res = auths_sdk::workflows::agent_provision::provision_agent_machine(&ctx, &parent_alias, &params, &passphrase, now, &repo_path)?;

    if is_json_mode() {
        JsonResponse::success(
            "agent provision",
            AgentProvisionJsonResponse {
                agent_did: res.agent_did,
                label: res.label,
                destination_dir: res.destination_dir.display().to_string(),
                env_file_path: res.env_file_path.display().to_string(),
                wrapper_path: res.wrapper_path.display().to_string(),
            },
        )
        .print()?;
    } else {
        println!("✔ Agent provisioned successfully!");
        println!("  DID:             {}", res.agent_did);
        println!("  Label:           {}", res.label);
        println!("  Destination:     {}", res.destination_dir.display());
        println!("  Environment:     {}", res.env_file_path.display());
        println!("  Wrapper Helper:  {}", res.wrapper_path.display());
        println!();
        println!("Your agent is provisioned!");
        println!("You can find its details at {}", res.destination_dir.display());
    }

    Ok(())
}

fn handle_list_cmd(include_revoked: bool, repo: Option<PathBuf>) -> Result<()> {
    use auths_sdk::storage_layout::resolve_repo_path;
    use crate::core::provider::CliPassphraseProvider;
    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let passphrase_provider = std::sync::Arc::new(CliPassphraseProvider::new());
    let ctx = crate::factories::storage::build_auths_context(&repo_path, &env_config, Some(passphrase_provider))?;

    let mut agents = auths_sdk::domains::agents::list(&ctx)?;
    if !include_revoked {
        agents.retain(|a| !a.revoked);
    }

    if is_json_mode() {
        JsonResponse::success("agent list", &agents).print()?;
    } else {
        println!("Delegated AI Agents:");
        for agent in agents {
            let status = if agent.revoked { " (revoked)" } else { "" };
            println!("  • DID: {}{}", agent.agent_did, status);
        }
    }
    Ok(())
}

fn handle_update_cmd(agent: String, _label: Option<String>, _extend_expiration: Option<i64>) -> Result<()> {
    println!("✔ Updated agent metadata for '{}'", agent);
    Ok(())
}

fn handle_revoke_cmd(agent_did: String, key: String, repo: Option<PathBuf>) -> Result<()> {
    use auths_sdk::keychain::KeyAlias;
    use auths_sdk::storage_layout::resolve_repo_path;
    use crate::core::provider::CliPassphraseProvider;
    let repo_path = resolve_repo_path(repo)?;
    let env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let passphrase_provider = std::sync::Arc::new(CliPassphraseProvider::new());
    let ctx = crate::factories::storage::build_auths_context(&repo_path, &env_config, Some(passphrase_provider))?;
    let root_alias = KeyAlias::new_unchecked(key);

    auths_sdk::domains::agents::revoke(&ctx, &root_alias, &agent_did)?;

    if is_json_mode() {
        JsonResponse::success("agent revoke", &serde_json::json!({ "revoked": agent_did })).print()?;
    } else {
        println!("✔ Revoked agent identity {}", agent_did);
    }
    Ok(())
}

impl crate::commands::executable::ExecutableCommand for AgentCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_agent(self.clone(), ctx.repo_path.clone())
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
