use anyhow::{Context, Result, bail};
use std::process::{Command, Stdio};

/// Run a command, return trimmed stdout. Fails with stderr in the error message.
pub fn run_capture(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{cmd} {}` failed (exit {}):\n{stderr}",
            args.join(" "),
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a command with extra env vars. Clears GH_TOKEN/GITHUB_TOKEN to avoid
/// stale tokens overriding the keyring account.
pub fn run_capture_env(cmd: &str, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN");

    for (k, v) in env {
        command.env(k, v);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{cmd} {}` failed (exit {}):\n{stderr}",
            args.join(" "),
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a command, piping `stdin_data` to its stdin. Returns trimmed stdout.
pub fn run_with_stdin(cmd: &str, args: &[&str], stdin_data: &[u8]) -> Result<String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .spawn()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data)?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{cmd} {}` failed (exit {}):\n{stderr}",
            args.join(" "),
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
