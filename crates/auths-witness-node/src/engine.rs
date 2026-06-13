//! Shipped adapters for the standup ports.
//!
//! These are the only place in the crate that knows about the host: the
//! `docker` binary and a TCP socket. The orchestration in
//! [`crate::standup`] talks to them through the [`ContainerEngine`] and
//! [`HealthCheck`] traits and never sees either detail.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::standup::{ContainerEngine, HealthCheck};

/// Drives Docker (Compose v2: `docker compose …`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DockerEngine;

impl DockerEngine {
    fn docker(args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new("docker").args(args).output()
    }

    /// Distil an engine error blob to one actionable line: the last non-empty
    /// line is the message Compose surfaces; operators never need the rest.
    fn one_line(stdout: &[u8], stderr: &[u8]) -> String {
        let blob = if stderr.is_empty() { stdout } else { stderr };
        String::from_utf8_lossy(blob)
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .unwrap_or("container engine reported an unspecified failure")
            .to_string()
    }
}

impl ContainerEngine for DockerEngine {
    fn unavailable_reason(&self) -> Option<String> {
        match Self::docker(&["info"]) {
            Ok(out) if out.status.success() => None,
            Ok(_) => Some(
                "the container engine is installed but not running — start it and retry"
                    .to_string(),
            ),
            Err(_) => Some(
                "no container engine found — install Docker (or a compatible engine) and retry"
                    .to_string(),
            ),
        }
    }

    fn compose_up(&self, project: &str, manifest_path: &Path) -> Result<(), String> {
        let manifest = manifest_path.to_string_lossy();
        let out = Self::docker(&[
            "compose",
            "-p",
            project,
            "-f",
            &manifest,
            "up",
            "-d",
            "--remove-orphans",
        ])
        .map_err(|e| format!("could not run the container engine: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            // Keep the engine's own line (operators paste it into issues) but
            // lead with what failed, so a terse engine message like "denied"
            // (image not pullable) or "port is already allocated" reads as one
            // actionable sentence on its own.
            Err(format!(
                "could not bring the node up: {}",
                Self::one_line(&out.stdout, &out.stderr)
            ))
        }
    }

    fn compose_down(&self, project: &str, manifest_path: &Path) -> Result<(), String> {
        let manifest = manifest_path.to_string_lossy();
        let out = Self::docker(&["compose", "-p", project, "-f", &manifest, "down", "-v"])
            .map_err(|e| format!("could not run the container engine: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Self::one_line(&out.stdout, &out.stderr))
        }
    }
}

/// Polls an `http://host:port/path` health endpoint over a raw socket — no HTTP
/// client dependency, because all this adapter needs to know is whether the
/// node answers `2xx` at its health path.
#[derive(Debug, Default, Clone, Copy)]
pub struct SocketHealthCheck;

impl HealthCheck for SocketHealthCheck {
    fn is_healthy(&self, url: &str) -> bool {
        let Some((host, port, path)) = parse_http_url(url) else {
            return false;
        };
        http_get_ok(&host, port, &path).unwrap_or(false)
    }
}

/// Parse `http://host:port/path` into its parts. Returns `None` for anything
/// that is not a plain-HTTP URL with an explicit port (which is all standup
/// ever produces).
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some((host.to_string(), port, path.to_string()))
}

/// One blocking HTTP/1.0 GET; `Ok(true)` iff the status line is `2xx`.
fn http_get_ok(host: &str, port: u16, path: &str) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::with_capacity(256);
    // The status line is the first line; reading the first chunk is enough.
    let mut chunk = [0u8; 256];
    let n = stream.read(&mut chunk)?;
    buf.extend_from_slice(&chunk[..n]);
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    // "HTTP/1.1 200 OK" → the code is the second token.
    Ok(status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .map(|c| (200..300).contains(&c))
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_standup_health_url() {
        let (h, p, path) = parse_http_url("http://127.0.0.1:3333/health").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 3333);
        assert_eq!(path, "/health");
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(parse_http_url("https://x/health").is_none());
        assert!(parse_http_url("ftp://x").is_none());
    }

    #[test]
    fn a_dead_port_is_not_healthy() {
        // Nothing listens on this ephemeral port.
        assert!(!SocketHealthCheck.is_healthy("http://127.0.0.1:1/health"));
    }

    #[test]
    fn one_line_takes_the_last_meaningful_line() {
        let msg = DockerEngine::one_line(b"", b"noise\n\nError: port is already allocated\n");
        assert_eq!(msg, "Error: port is already allocated");
    }
}
