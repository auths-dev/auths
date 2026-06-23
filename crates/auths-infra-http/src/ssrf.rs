//! Connection guard for user-supplied registry and pairing-relay URLs.
//!
//! `init --register`, `pair --registry`, and `artifact publish --registry` all
//! dial a URL the caller controls. Without a check, that URL can point at cloud
//! metadata endpoints (`http://169.254.169.254`), loopback, or other private
//! hosts the process can reach but the caller should not. This module enforces
//! HTTPS-only, public-host-only dialing, mirroring the OOBI client.
//!
//! The `AUTHS_ALLOW_PRIVATE_REGISTRY` environment variable disables the check so
//! intranet registries and local/CI servers (`http://127.0.0.1`) keep working.

use std::net::IpAddr;

use url::Url;

/// Environment variable that, when set to any value, allows plain `http` and
/// private/loopback registry hosts.
const ALLOW_PRIVATE_ENV: &str = "AUTHS_ALLOW_PRIVATE_REGISTRY";

/// Reason a registry URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SsrfBlocked {
    /// The URL could not be parsed.
    #[error("invalid registry URL: {0}")]
    InvalidUrl(String),

    /// The URL scheme is not `https`.
    #[error("registry URL scheme must be https, got '{0}'")]
    InsecureScheme(String),

    /// The URL has no host component.
    #[error("registry URL has no host")]
    MissingHost,

    /// The target host is loopback / private / link-local / unspecified.
    #[error("refusing to dial a private or loopback registry host: {0}")]
    BlockedHost(String),
}

/// Enforce the connection policy on a user-supplied registry URL.
///
/// Reads `AUTHS_ALLOW_PRIVATE_REGISTRY` to decide whether private hosts are
/// permitted, then delegates to [`evaluate`].
///
/// Args:
/// * `url`: The registry or pairing-relay base URL the caller asked to dial.
///
/// Usage:
/// ```ignore
/// guard_registry_url("https://registry.example.com")?;
/// ```
pub(crate) fn guard_registry_url(url: &str) -> Result<(), SsrfBlocked> {
    let allow_private = std::env::var_os(ALLOW_PRIVATE_ENV).is_some();
    evaluate(url, allow_private)
}

/// Decide whether `url` may be dialed.
///
/// When `allow_private` is true the URL is accepted as long as it parses and has
/// a host. Otherwise the scheme must be `https` and the host must not be
/// loopback, private, link-local, or unspecified.
///
/// Args:
/// * `url`: The registry or pairing-relay base URL to check.
/// * `allow_private`: When true, permit plain `http` and private/loopback hosts.
fn evaluate(url: &str, allow_private: bool) -> Result<(), SsrfBlocked> {
    let parsed = Url::parse(url).map_err(|e| SsrfBlocked::InvalidUrl(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or(SsrfBlocked::MissingHost)?
        .to_string();

    if allow_private {
        return Ok(());
    }

    if parsed.scheme() != "https" {
        return Err(SsrfBlocked::InsecureScheme(parsed.scheme().to_string()));
    }

    if is_blocked_host(&host) {
        return Err(SsrfBlocked::BlockedHost(host));
    }

    Ok(())
}

/// Whether a host should be refused. IP literals are classified directly; the
/// obvious loopback names are blocked. DNS names that resolve to private space
/// are mitigated by the HTTPS-only requirement.
pub(crate) fn is_blocked_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    matches!(host, "localhost" | "localhost.localdomain")
}

/// Whether an IP is loopback / private / link-local / unspecified.
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_blocks_metadata_and_loopback_allows_public() {
        assert_eq!(
            evaluate("http://169.254.169.254/x", false),
            Err(SsrfBlocked::InsecureScheme("http".to_string()))
        );
        assert_eq!(
            evaluate("https://169.254.169.254/x", false),
            Err(SsrfBlocked::BlockedHost("169.254.169.254".to_string()))
        );
        assert_eq!(
            evaluate("http://127.0.0.1:8080", false),
            Err(SsrfBlocked::InsecureScheme("http".to_string()))
        );
        assert_eq!(
            evaluate("https://127.0.0.1:8080", false),
            Err(SsrfBlocked::BlockedHost("127.0.0.1".to_string()))
        );
        assert_eq!(evaluate("https://registry.example.com", false), Ok(()));
    }

    #[test]
    fn evaluate_allow_private_permits_loopback() {
        assert_eq!(evaluate("http://127.0.0.1:8080", true), Ok(()));
        assert_eq!(evaluate("http://169.254.169.254/x", true), Ok(()));
    }
}
