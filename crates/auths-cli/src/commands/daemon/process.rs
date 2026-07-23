//! Standalone process lifecycle functions for the SSH agent daemon.
//!
//! Each function handles a single concern (PID files, signal checks, process
//! spawning, termination) and is independently testable without a running
//! Unix socket.

#[cfg(not(unix))]
use anyhow::anyhow;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

/// Write a process ID to a PID file with restricted permissions.
///
/// Args:
/// * `path`: Filesystem path for the PID file.
/// * `pid`: Process ID to write.
///
/// Usage:
/// ```ignore
/// write_pid_file(&pid_path, std::process::id())?;
/// ```
pub fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    crate::core::fs::write_sensitive_file(path, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {:?}", path))
}

/// Read a process ID from a PID file, returning `None` if the file does not exist.
///
/// Args:
/// * `path`: Filesystem path of the PID file.
///
/// Usage:
/// ```ignore
/// if let Some(pid) = read_pid_file(&pid_path)? {
///     println!("Agent running as PID {}", pid);
/// }
/// ```
pub fn read_pid_file(path: &Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read PID file: {:?}", path))?;

    let pid: u32 = content
        .trim()
        .parse()
        .with_context(|| format!("Invalid PID in file: {}", content.trim()))?;

    Ok(Some(pid))
}

/// Check whether a process with the given PID is running.
///
/// On Unix, sends signal 0 (a no-op signal that checks process existence).
/// On non-Unix platforms, always returns `false`.
///
/// Args:
/// * `pid`: Process ID to check.
///
/// Usage:
/// ```ignore
/// if is_process_running(pid) {
///     println!("Process {} is alive", pid);
/// }
/// ```
#[cfg(unix)]
pub fn is_process_running(pid: u32) -> bool {
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(not(unix))]
pub fn is_process_running(_pid: u32) -> bool {
    false
}

/// Test whether a Unix domain socket at `path` accepts connections.
///
/// Preferred over `path.exists()` because it avoids TOCTOU race conditions:
/// a socket file can exist but be stale (no listener).
///
/// Args:
/// * `path`: Filesystem path of the Unix domain socket.
///
/// Usage:
/// ```ignore
/// if socket_is_connectable(&socket_path) {
///     println!("Agent socket is live");
/// }
/// ```
#[cfg(unix)]
pub fn socket_is_connectable(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
pub fn socket_is_connectable(_path: &Path) -> bool {
    false
}

/// Spawn a detached daemon process by re-executing the current binary.
///
/// Creates a new session via `setsid()` so the child survives parent exit.
/// Stdout and stderr are redirected to `log_path`.
///
/// Args:
/// * `args`: Command-line arguments for the spawned process.
/// * `log_path`: Path for stdout/stderr redirection.
///
/// Usage:
/// ```ignore
/// let pid = spawn_detached(
///     &["agent", "start", "--foreground", "--socket", socket_str],
///     &log_path,
/// )?;
/// ```
#[cfg(unix)]
pub fn spawn_detached(args: &[&str], log_path: &Path) -> Result<u32> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let exe = std::env::current_exe().context("Failed to get current executable path")?;

    let log_file = fs::File::create(log_path)
        .with_context(|| format!("Failed to create log file: {:?}", log_path))?;
    let log_file_err = log_file
        .try_clone()
        .context("Failed to clone log file handle")?;

    let mut cmd = Command::new(&exe);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.stdout(log_file).stderr(log_file_err);

    // SAFETY: setsid() is async-signal-safe and called between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let child = cmd.spawn().context("Failed to spawn daemon process")?;
    Ok(child.id())
}

#[cfg(not(unix))]
pub fn spawn_detached(_args: &[&str], _log_path: &Path) -> Result<u32> {
    Err(anyhow!(
        "Daemonization not supported on this platform. Use --foreground."
    ))
}

/// Send SIGTERM to a process and wait for it to exit, escalating to SIGKILL
/// if it does not terminate within `timeout`.
///
/// Args:
/// * `pid`: Process ID to terminate.
/// * `timeout`: Maximum time to wait for graceful shutdown before SIGKILL.
///
/// Usage:
/// ```ignore
/// terminate_process(pid, Duration::from_secs(5))?;
/// ```
#[cfg(unix)]
pub fn terminate_process(pid: u32, timeout: Duration) -> Result<()> {
    signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .with_context(|| format!("Failed to send SIGTERM to PID {}", pid))?;

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !is_process_running(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if is_process_running(pid) {
        eprintln!("Process did not terminate gracefully, sending SIGKILL...");
        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn terminate_process(_pid: u32, _timeout: Duration) -> Result<()> {
    Err(anyhow!("Stopping agent not supported on this platform"))
}

/// Remove stale daemon files (PID file, socket, environment file).
///
/// Args:
/// * `paths`: Slice of file paths to clean up. Missing files are silently ignored.
///
/// Usage:
/// ```ignore
/// cleanup_stale_files(&[&pid_path, &socket_path, &env_path]);
/// ```
pub fn cleanup_stale_files(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_and_read_pid_file_round_trip() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("test.pid");

        write_pid_file(&pid_path, 42).unwrap();
        let read_back = read_pid_file(&pid_path).unwrap();
        assert_eq!(read_back, Some(42));
    }

    #[test]
    fn read_pid_file_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("nonexistent.pid");
        assert_eq!(read_pid_file(&pid_path).unwrap(), None);
    }

    #[test]
    fn read_pid_file_invalid_content_errors() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("bad.pid");
        fs::write(&pid_path, "not-a-number").unwrap();
        assert!(read_pid_file(&pid_path).is_err());
    }

    #[test]
    fn cleanup_stale_files_removes_existing() {
        let dir = TempDir::new().unwrap();
        let f1 = dir.path().join("a");
        let f2 = dir.path().join("b");
        fs::write(&f1, "x").unwrap();
        fs::write(&f2, "y").unwrap();

        cleanup_stale_files(&[&f1, &f2]);

        assert!(!f1.exists());
        assert!(!f2.exists());
    }

    #[test]
    fn cleanup_stale_files_ignores_missing() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("gone");
        cleanup_stale_files(&[&missing]);
    }

    #[cfg(unix)]
    #[test]
    fn is_process_running_detects_current_process() {
        assert!(is_process_running(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn is_process_running_false_for_nonexistent() {
        assert!(!is_process_running(999_999_999));
    }
}
