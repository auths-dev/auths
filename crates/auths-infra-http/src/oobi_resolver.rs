//! HTTP OOBI client — fetch a `did:keri:` identity's KEL from the static
//! `.well-known/keri/oobi/<aid>/keri.cesr` layout (see
//! `docs/architecture/kel-distribution.md`).
//!
//! This adapter only *fetches* and parses; it returns raw `Vec<Event>`. The
//! prefix-binding guard + monotonicity live one layer up (the SDK chain / the
//! CLI composition root) so they are not reimplemented per transport. Because an
//! OOBI URL is attacker-influenceable, the client is SSRF-hardened: HTTPS-only,
//! redirects disabled, private/loopback hosts blocked, and a response-size cap.

use std::net::IpAddr;

use auths_keri::{Event, Prefix};
use url::Url;

use crate::default_client_builder;

/// Maximum OOBI response body size (DoS bound).
pub const MAX_OOBI_BYTES: usize = 4 * 1024 * 1024;

/// Errors fetching a KEL over HTTP from an OOBI endpoint.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpOobiError {
    /// The base URL or constructed OOBI URL is malformed.
    #[error("invalid OOBI URL: {0}")]
    InvalidUrl(String),

    /// The URL scheme is not `https` (SSRF guard; bypassed only when private
    /// hosts are explicitly allowed).
    #[error("OOBI URL scheme must be https, got '{0}'")]
    InsecureScheme(String),

    /// The target host is loopback / private / link-local (SSRF guard).
    #[error("refusing to fetch from a private or loopback host: {0}")]
    BlockedHost(String),

    /// The HTTP request itself failed (DNS, connect, TLS, timeout).
    #[error("OOBI request failed: {0}")]
    Request(String),

    /// 404 — the host serves no KEL for this identifier.
    #[error("identity not found at OOBI endpoint (404)")]
    NotFound,

    /// 410 — the identity is gone (revoked/abandoned at the host).
    #[error("identity gone at OOBI endpoint (410)")]
    Gone,

    /// 429 — rate limited.
    #[error("OOBI endpoint rate-limited the request (429)")]
    RateLimited,

    /// 422 — the server itself reported a prefix mismatch.
    #[error("OOBI endpoint reported a prefix mismatch (422)")]
    ServerPrefixMismatch,

    /// Any other non-success status.
    #[error("unexpected HTTP status {0} from OOBI endpoint")]
    UnexpectedStatus(u16),

    /// The response exceeded the size cap.
    #[error("OOBI response exceeds the {0}-byte size cap")]
    Oversized(usize),

    /// The body was not a parseable KEL.
    #[error("malformed KEL body from OOBI endpoint: {0}")]
    Malformed(String),
}

/// An SSRF-hardened HTTP client for the OOBI static KEL layout.
pub struct HttpOobiResolver {
    client: reqwest::Client,
    base_url: String,
    allow_private: bool,
}

impl HttpOobiResolver {
    /// Build a resolver for `base_url`. The client follows **no** redirects
    /// (so a 3xx to a private IP cannot exfiltrate) and inherits the hardened
    /// timeouts / TLS floor.
    ///
    /// Args:
    /// * `base_url`: The OOBI host base (e.g. `https://registry.example`).
    pub fn new(base_url: impl Into<String>) -> Result<Self, HttpOobiError> {
        let client = default_client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| HttpOobiError::Request(e.to_string()))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            allow_private: false,
        })
    }

    /// Allow plain `http` and private/loopback hosts — for intranet registries
    /// and tests against a local server. Off by default.
    pub fn allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    /// Fetch and parse the KEL for `prefix` from the OOBI layout.
    ///
    /// Applies the SSRF guard, maps HTTP status to the error taxonomy, enforces
    /// the size cap, and parses the `keri.cesr` body (a JSON array of events).
    /// Returns raw events — the caller applies the prefix-binding guard.
    ///
    /// Args:
    /// * `prefix`: The `did:keri:` prefix (AID) to resolve.
    pub async fn fetch_kel(&self, prefix: &Prefix) -> Result<Vec<Event>, HttpOobiError> {
        let url = self.oobi_url(prefix)?;
        self.guard_url(&url)?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| HttpOobiError::Request(e.to_string()))?;
        map_status(resp.status())?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| HttpOobiError::Request(e.to_string()))?;
        if bytes.len() > MAX_OOBI_BYTES {
            return Err(HttpOobiError::Oversized(MAX_OOBI_BYTES));
        }
        serde_json::from_slice::<Vec<Event>>(&bytes)
            .map_err(|e| HttpOobiError::Malformed(e.to_string()))
    }

    /// Build the OOBI URL for `prefix` under the base.
    fn oobi_url(&self, prefix: &Prefix) -> Result<Url, HttpOobiError> {
        let raw = format!(
            "{}/.well-known/keri/oobi/{}/keri.cesr",
            self.base_url.trim_end_matches('/'),
            prefix.as_str()
        );
        Url::parse(&raw).map_err(|e| HttpOobiError::InvalidUrl(e.to_string()))
    }

    /// Enforce the SSRF policy on a resolved URL (no-op when `allow_private`).
    fn guard_url(&self, url: &Url) -> Result<(), HttpOobiError> {
        if self.allow_private {
            return Ok(());
        }
        if url.scheme() != "https" {
            return Err(HttpOobiError::InsecureScheme(url.scheme().to_string()));
        }
        match url.host_str() {
            Some(host) if is_blocked_host(host) => {
                Err(HttpOobiError::BlockedHost(host.to_string()))
            }
            Some(_) => Ok(()),
            None => Err(HttpOobiError::InvalidUrl("URL has no host".to_string())),
        }
    }
}

/// Whether a host should be refused as an SSRF target. IP literals are classified
/// directly; the obvious loopback names are blocked. (DNS names that resolve to
/// private space are mitigated by redirects-disabled + HTTPS-only.)
fn is_blocked_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    matches!(host, "localhost" | "localhost.localdomain")
}

/// Whether an IP is loopback / private / link-local / unspecified.
fn is_blocked_ip(ip: IpAddr) -> bool {
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

/// Map a non-2xx HTTP status to the OOBI error taxonomy (`Ok` for any 2xx).
fn map_status(status: reqwest::StatusCode) -> Result<(), HttpOobiError> {
    use reqwest::StatusCode;
    if status.is_success() {
        return Ok(());
    }
    Err(match status {
        StatusCode::NOT_FOUND => HttpOobiError::NotFound,
        StatusCode::GONE => HttpOobiError::Gone,
        StatusCode::TOO_MANY_REQUESTS => HttpOobiError::RateLimited,
        StatusCode::UNPROCESSABLE_ENTITY => HttpOobiError::ServerPrefixMismatch,
        other => HttpOobiError::UnexpectedStatus(other.as_u16()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_keri::{
        CesrKey, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold, VersionString,
        finalize_icp_event,
    };

    fn icp_and_prefix() -> (Event, Prefix) {
        let key = KeriPublicKey::ed25519(&[11u8; 32]).unwrap();
        // A valid next-commitment digest (the SAID of any key works structurally).
        let next = KeriPublicKey::ed25519(&[12u8; 32]).unwrap();
        let n = auths_core::crypto::said::compute_next_commitment(&next);
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
            nt: Threshold::Simple(1),
            n: vec![n],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let prefix = finalized.i.clone();
        (Event::Icp(finalized), prefix)
    }

    #[test]
    fn blocks_loopback_and_private_and_insecure() {
        assert!(is_blocked_host("127.0.0.1"));
        assert!(is_blocked_host("10.0.0.5"));
        assert!(is_blocked_host("192.168.1.1"));
        assert!(is_blocked_host("169.254.1.1"));
        assert!(is_blocked_host("localhost"));
        assert!(is_blocked_host("::1"));
        assert!(!is_blocked_host("93.184.216.34")); // example.com
        assert!(!is_blocked_host("registry.example.com"));

        let resolver = HttpOobiResolver::new("https://127.0.0.1").unwrap();
        let (_e, prefix) = icp_and_prefix();
        let err = resolver.guard_url(&resolver.oobi_url(&prefix).unwrap()).unwrap_err();
        assert!(matches!(err, HttpOobiError::BlockedHost(_)));

        let insecure = HttpOobiResolver::new("http://registry.example.com").unwrap();
        let err = insecure
            .guard_url(&insecure.oobi_url(&prefix).unwrap())
            .unwrap_err();
        assert!(matches!(err, HttpOobiError::InsecureScheme(_)));
    }

    #[test]
    fn maps_http_status_to_taxonomy() {
        use reqwest::StatusCode;
        assert!(map_status(StatusCode::OK).is_ok());
        assert!(matches!(
            map_status(StatusCode::NOT_FOUND),
            Err(HttpOobiError::NotFound)
        ));
        assert!(matches!(
            map_status(StatusCode::GONE),
            Err(HttpOobiError::Gone)
        ));
        assert!(matches!(
            map_status(StatusCode::TOO_MANY_REQUESTS),
            Err(HttpOobiError::RateLimited)
        ));
        assert!(matches!(
            map_status(StatusCode::UNPROCESSABLE_ENTITY),
            Err(HttpOobiError::ServerPrefixMismatch)
        ));
        assert!(matches!(
            map_status(StatusCode::INTERNAL_SERVER_ERROR),
            Err(HttpOobiError::UnexpectedStatus(500))
        ));
    }

    #[test]
    fn builds_well_known_oobi_url() {
        let resolver = HttpOobiResolver::new("https://registry.example/").unwrap();
        let prefix = Prefix::new_unchecked("EabcDEF123".to_string());
        let url = resolver.oobi_url(&prefix).unwrap();
        assert_eq!(
            url.as_str(),
            "https://registry.example/.well-known/keri/oobi/EabcDEF123/keri.cesr"
        );
    }

    #[tokio::test]
    async fn fetches_kel_from_static_layout() {
        use axum::Router;
        use axum::routing::get;

        let (event, prefix) = icp_and_prefix();
        let events = vec![event];
        let body = serde_json::to_vec(&events).unwrap();

        let app = Router::new().route(
            "/.well-known/keri/oobi/{aid}/keri.cesr",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resolver = HttpOobiResolver::new(format!("http://{addr}"))
            .unwrap()
            .allow_private(true);
        let fetched = resolver.fetch_kel(&prefix).await.unwrap();
        assert_eq!(fetched, events);
    }
}
