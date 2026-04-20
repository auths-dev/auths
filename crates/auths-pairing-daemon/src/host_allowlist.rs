//! Host / Origin / Referer allowlist middleware.
//!
//! # Attack closed
//!
//! DNS rebinding: the victim's browser loads `evil.com`, whose TTL
//! expires and re-resolves to a LAN IP hosting this daemon. `fetch(…)`
//! from the evil page goes to the LAN IP with `Host: evil.com` and
//! `Origin: https://evil.com`. Before T3, the daemon served responses;
//! after T3, it returns 421 Misdirected Request with no body of
//! interest to the attacker.
//!
//! # What we check
//!
//! On every request:
//!
//! 1. `Host` header — required (RFC 9110 §7.2). Must parse and match an
//!    authority in the allowlist exactly (case-insensitive).
//! 2. `Origin` header — optional. If present, the authority portion
//!    must be in the allowlist.
//! 3. `Referer` header — optional. If present and parseable, the
//!    authority portion must be in the allowlist.
//!
//! Missing `Host` → 421. Any mismatch → 421.
//!
//! # Ordering
//!
//! This middleware sits OUTSIDE rate-limit and body-limit layers. A
//! rebinding-driven request gets rejected before it costs us any
//! token-bucket budget, JSON parse, or handler dispatch. Order:
//!
//! ```text
//! TraceLayer → host_allowlist → rate_limit → (body_limit) → handler
//! ```
//!
//! # Port handling
//!
//! The pairing daemon's port is chosen at bind time, not at build
//! time. The allowlist therefore distinguishes three construction
//! paths:
//!
//! - [`HostAllowlist::for_bound_addr`] — known `SocketAddr`, emits
//!   `<host>:<port>` authorities for every hostname + the explicit
//!   port. This is what the production path uses, after
//!   `TcpListener::bind` returns.
//! - [`HostAllowlist::pending`] — returns a fail-closed sentinel
//!   (matches nothing). Useful for routers built before their port is
//!   known; callers MUST replace the value before serving.
//! - [`HostAllowlist::allow_any_for_tests`] — wildcard, test-only.
//!   Integration tests that use `MockConnectInfo` want to keep focus
//!   on handler behavior, not host-header mechanics.

use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use std::sync::Arc;

use crate::error::DaemonError;

/// Allowlist of authorities the daemon accepts in `Host` / `Origin` /
/// `Referer` headers.
///
/// The authority match is case-insensitive and port-exact.
#[derive(Debug, Clone)]
pub struct HostAllowlist {
    /// Authority strings (`"<host>:<port>"` or `"[<ipv6>]:<port>"`),
    /// lowercased. An empty vec means fail-closed.
    authorities: Vec<String>,
    /// Test-only wildcard. NEVER set in production builds.
    allow_all_for_tests: bool,
}

impl HostAllowlist {
    /// Build the production allowlist for a daemon that has just bound
    /// to `addr`. Includes the loopback forms, the bound IP (if not
    /// already loopback), and an optional mDNS hostname (e.g.
    /// `"my-mac.local"`).
    ///
    /// The emitted authorities always include the port.
    pub fn for_bound_addr(addr: std::net::SocketAddr, mdns_hostname: Option<&str>) -> Self {
        let port = addr.port();
        let mut authorities = Vec::with_capacity(6);
        // Loopback forms
        authorities.push(format!("127.0.0.1:{port}"));
        authorities.push(format!("localhost:{port}"));
        authorities.push(format!("[::1]:{port}"));
        // Bound IP (if not already loopback)
        if !addr.ip().is_loopback() {
            match addr.ip() {
                std::net::IpAddr::V4(v4) => authorities.push(format!("{v4}:{port}")),
                std::net::IpAddr::V6(v6) => authorities.push(format!("[{v6}]:{port}")),
            }
        }
        if let Some(name) = mdns_hostname {
            authorities.push(format!("{}:{port}", name.to_ascii_lowercase()));
        }

        Self {
            authorities: authorities
                .into_iter()
                .map(|a| a.to_ascii_lowercase())
                .collect(),
            allow_all_for_tests: false,
        }
    }

    /// Returns an unsealed allowlist — matches nothing. Used as a
    /// placeholder at `Router` build time; the caller MUST replace
    /// before serving or every request will 421.
    pub fn pending() -> Self {
        Self {
            authorities: Vec::new(),
            allow_all_for_tests: false,
        }
    }

    /// Wildcard — accepts any `Host`. Test-only.
    ///
    /// Named with the `for_tests` suffix so a grep in production code
    /// makes the misuse obvious at code-review time.
    pub fn allow_any_for_tests() -> Self {
        Self {
            authorities: Vec::new(),
            allow_all_for_tests: true,
        }
    }

    /// Check whether the given authority string is in the allowlist.
    pub fn is_allowed(&self, authority: &str) -> bool {
        if self.allow_all_for_tests {
            return true;
        }
        let needle = authority.to_ascii_lowercase();
        self.authorities.iter().any(|a| *a == needle)
    }

    /// Raw authority list (for debugging / test assertions).
    pub fn authorities(&self) -> &[String] {
        &self.authorities
    }
}

/// Extract the authority `"<host>:<port>"` portion from an absolute URL.
///
/// Handles `http://…`, `https://…`, scheme-relative `//…`, and bare
/// authorities. Strips path/query/fragment. Returns `None` if the input
/// does not contain a recognizable authority.
fn authority_of(url_or_authority: &str) -> Option<&str> {
    let without_scheme = match url_or_authority.find("://") {
        Some(i) => &url_or_authority[i + 3..],
        None => {
            // Accept a bare authority (Host header itself) — strip
            // leading `//` if any, leave otherwise.
            url_or_authority
                .strip_prefix("//")
                .unwrap_or(url_or_authority)
        }
    };
    // Truncate at the first `/`, `?`, or `#`.
    let end = without_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(without_scheme.len());
    let authority = &without_scheme[..end];
    if authority.is_empty() {
        None
    } else {
        Some(authority)
    }
}

fn check_headers(headers: &HeaderMap, allowlist: &HostAllowlist) -> Result<(), DaemonError> {
    // Host — required.
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or(DaemonError::MisdirectedHost)?;
    if !allowlist.is_allowed(host) {
        return Err(DaemonError::MisdirectedHost);
    }
    // Origin — optional, but if present must match.
    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        // "null" is a valid Origin for some contexts but never a LAN-
        // daemon client — reject it.
        if origin.eq_ignore_ascii_case("null") {
            return Err(DaemonError::MisdirectedHost);
        }
        let auth = authority_of(origin).ok_or(DaemonError::MisdirectedHost)?;
        if !allowlist.is_allowed(auth) {
            return Err(DaemonError::MisdirectedHost);
        }
    }
    // Referer — optional, parsed the same way.
    if let Some(referer) = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
    {
        let auth = authority_of(referer).ok_or(DaemonError::MisdirectedHost)?;
        if !allowlist.is_allowed(auth) {
            return Err(DaemonError::MisdirectedHost);
        }
    }
    Ok(())
}

/// Middleware factory. Pass the produced closure to
/// `axum::middleware::from_fn_with_state`.
pub async fn host_allowlist_middleware(
    axum::extract::State(allowlist): axum::extract::State<Arc<HostAllowlist>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, DaemonError> {
    check_headers(request.headers(), &allowlist)?;
    Ok(next.run(request).await)
}

// Keep StatusCode import usable in Err paths elsewhere that don't go
// through DaemonError — not currently used, but retained for callers
// who want a bare handler.
#[allow(dead_code)]
const _STATUS_CODE_REFERENCE: StatusCode = StatusCode::MISDIRECTED_REQUEST;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn hdr(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn allowlist_for_port(port: u16) -> HostAllowlist {
        HostAllowlist::for_bound_addr(
            format!("192.168.1.42:{port}").parse().unwrap(),
            Some("my-mac.local"),
        )
    }

    #[test]
    fn missing_host_is_rejected() {
        let a = allowlist_for_port(8080);
        let h = HeaderMap::new();
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn evil_host_is_rejected() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "evil.com")]);
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn bound_lan_ip_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "192.168.1.42:8080")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn localhost_with_port_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "localhost:8080")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn ipv4_loopback_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "127.0.0.1:8080")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn ipv6_loopback_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "[::1]:8080")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn mdns_hostname_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[("host", "my-mac.local:8080")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn evil_origin_is_rejected() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[
            ("host", "localhost:8080"),
            (header::ORIGIN.as_str(), "https://evil.com"),
        ]);
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn matching_origin_is_accepted() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[
            ("host", "localhost:8080"),
            (header::ORIGIN.as_str(), "http://localhost:8080"),
        ]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn evil_referer_is_rejected() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[
            ("host", "localhost:8080"),
            (header::REFERER.as_str(), "https://evil.com/path/to/page"),
        ]);
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn pending_allowlist_rejects_all() {
        let a = HostAllowlist::pending();
        let h = hdr(&[("host", "localhost:8080")]);
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn test_wildcard_accepts_anything() {
        let a = HostAllowlist::allow_any_for_tests();
        let h = hdr(&[("host", "literally-anything.example")]);
        assert!(check_headers(&h, &a).is_ok());
    }

    #[test]
    fn null_origin_rejected() {
        let a = allowlist_for_port(8080);
        let h = hdr(&[
            ("host", "localhost:8080"),
            (header::ORIGIN.as_str(), "null"),
        ]);
        assert!(matches!(
            check_headers(&h, &a),
            Err(DaemonError::MisdirectedHost)
        ));
    }

    #[test]
    fn authority_of_parses_urls() {
        assert_eq!(authority_of("http://host:8080/path"), Some("host:8080"));
        assert_eq!(authority_of("https://host:8080"), Some("host:8080"));
        assert_eq!(authority_of("host:8080"), Some("host:8080"));
        assert_eq!(authority_of("//host:8080/x"), Some("host:8080"));
        assert_eq!(authority_of("http://host:8080?q=1"), Some("host:8080"));
        assert_eq!(authority_of(""), None);
    }
}
