//! Typed errors for the pairing daemon + the HTTP status-code mapping.
//!
//! Every handler returns `Result<Json<T>, DaemonError>` and every
//! status code in the daemon is emitted from a single `IntoResponse`
//! impl. Centralizing this mapping is what lets new middleware (421
//! from the Host allowlist, 413 from the body-limit, 503 from the
//! CPU-budget semaphore, etc.) share one error path instead of
//! hand-rolling its own status-code translation.
//!
//! # Error body shape
//!
//! `{ "error": "<kebab-case-code>", "message": "<safe>" }` — the `error`
//! code is the authoritative discriminant. The `message` string is a
//! fixed safe template per variant and NEVER echoes request data (URLs,
//! header values, JSON body fragments). This is the error-oracle defense:
//! a caller can probe for presence/shape but cannot exfiltrate data
//! through our error surface.
//!
//! # Logging
//!
//! The server-side `tracing::error!` call (installed in each handler
//! where the `DaemonError` originates, or via a tower-http trace layer)
//! sees the full typed error, including any inner `Pairing(PairingError)`
//! source. Only the HTTP response is redacted.

use std::time::Duration;

use thiserror::Error;

/// Errors from the pairing daemon.
///
/// Each variant has a fixed HTTP status-code mapping via the
/// [`IntoResponse`][axum::response::IntoResponse] impl (server feature
/// only). Variants added here MUST also be added to the `IntoResponse`
/// impl's `match` — a missed variant is caught at compile time because
/// the enum is `#[non_exhaustive]`-free internally.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Cryptographic token generation failed.
    #[error("failed to generate pairing token")]
    TokenGenerationFailed,

    /// TCP listener could not bind to the requested address.
    #[error("failed to bind TCP listener: {0}")]
    BindFailed(#[source] std::io::Error),

    /// mDNS advertisement or discovery failed.
    #[error("mDNS error: {0}")]
    MdnsError(String),

    /// Network interface detection failed.
    #[error("failed to detect network interfaces: {0}")]
    NetworkDetectionFailed(#[source] std::io::Error),

    /// A pairing protocol error.
    #[error(transparent)]
    Pairing(#[from] auths_core::pairing::PairingError),

    /// RNG health check at startup failed. The daemon refuses to
    /// bind a listener if the OS CSPRNG appears unhealthy — this
    /// catches the early-boot entropy-starvation window that has
    /// produced real-world key-collision incidents.
    #[error("RNG health check failed: {0}")]
    EntropyCheckFailed(String),

    // --- HTTP-boundary variants ----------------------------------------------
    /// Resource not found (404). Emitted for unknown session_id /
    /// short_code lookups. Carries no detail to avoid enumeration.
    #[error("not found")]
    NotFound,

    /// Conflict (409). Session is in a state that does not accept the
    /// requested transition — e.g. submitting a response to a session
    /// that has already received one. Also used for nonce replay detection
    /// prior to session-scoped auth (see `NonceReplay`).
    #[error("conflict")]
    Conflict,

    /// Missing / invalid `X-Pairing-Token` (401). Legacy bootstrap
    /// path — will be replaced by `UnauthorizedHmac` /
    /// `UnauthorizedSig` once the hybrid-auth middleware lands.
    #[error("unauthorized")]
    Unauthorized,

    /// Request's `Host` / `Origin` / `Referer` did not match the LAN
    /// allowlist (421). The session's pairing token is bound to a
    /// specific address; requests routed through another Host header are
    /// evidence of DNS rebinding or proxy abuse.
    #[error("misdirected request (421)")]
    MisdirectedHost,

    /// Body exceeded the configured size cap (413). Prevents memory
    /// exhaustion via oversized POSTs.
    #[error("payload too large (413)")]
    PayloadTooLarge,

    /// Rate limiter rejected the request (429). `retry_after` hints at
    /// token-bucket refill; emitted as a `Retry-After` header in the
    /// response. Absent hint → responder omits the header.
    #[error("rate limited (429)")]
    RateLimited { retry_after: Option<Duration> },

    /// CPU-budget semaphore exhausted (503) — we intentionally decline
    /// NEW sessions rather than admit them into degraded service. Always
    /// carries a `Retry-After` so the client does not hot-loop.
    #[error("capacity exhausted (503)")]
    CapacityExhausted { retry_after: Duration },

    /// HMAC validation on the pre-key bootstrap path failed (401).
    /// Distinguished from `UnauthorizedSig` so observability can separate
    /// bootstrap-auth failures (which are expected under brute-force
    /// probing of short codes) from session-auth failures (which indicate
    /// a paired device acting outside its key's scope).
    #[error("unauthorized (bootstrap HMAC)")]
    UnauthorizedHmac,

    /// Device-signature validation on a session-scoped endpoint failed
    /// (401). See [`UnauthorizedHmac`] for why the two are split.
    #[error("unauthorized (session signature)")]
    UnauthorizedSig,

    /// A signed request re-used a nonce the daemon already saw (409).
    /// Emitted by the per-session nonce-replay cache once session-scoped
    /// signed requests are introduced.
    #[error("nonce replay (409)")]
    NonceReplay,

    /// JSON body nested beyond the configured depth cap (400). Protects
    /// serde_json / the domain layer from pathological inputs that
    /// trigger deep recursion or pathological hashing.
    #[error("json depth exceeded (400)")]
    JsonDepthExceeded,

    /// Request's monotonic timestamp was too far from the server clock
    /// (400). Prevents long-lived signed-request replay across reboots.
    #[error("clock skew out of bounds (400)")]
    ClockSkew,

    /// Session expired per the monotonic-clock deadline (410). Separate
    /// from the pairing-token's `expires_at` (which is wall-clock) —
    /// monotonic enforcement is resilient to clock adjustments.
    #[error("session expired (410)")]
    SessionExpired,

    /// A request's `device_signing_pubkey` bytes did not match the byte
    /// length expected for the declared `curve` (400). Distinguished from
    /// [`UnauthorizedSig`] so a curve/length-mismatch surfaces as a routing
    /// error — not as `InvalidSignature` — per the wire-format-curve-tagging
    /// rule in CLAUDE.md §4. The variant carries `{curve, expected, actual}`
    /// for server logs; the wire body does not interpolate these.
    #[error("pubkey length {actual} does not match curve {curve} (expected {expected})")]
    InvalidPubkeyLength {
        curve: &'static str,
        expected: usize,
        actual: usize,
    },

    /// Request carried a `subkey_chain` extension that this daemon build
    /// cannot verify (400). Emitted when the daemon is compiled without
    /// the `subkey-chain-v1` feature but receives a chain. Silent ignore
    /// would be a security regression — the controller would record the
    /// session-only subkey as the stable phone identifier without the
    /// chain-of-custody proof the chain was meant to provide.
    #[error("subkey chain extension not supported by this daemon build")]
    UnsupportedSubkeyChain,

    /// A supplied `subkey_chain` failed cryptographic verification (400):
    /// wrong-length pubkey, wrong-length signature, signature does not
    /// verify, or a self-referential chain (bootstrap == subkey).
    #[error("subkey chain verification failed: {reason}")]
    InvalidSubkeyChain { reason: &'static str },
}

// ---------------------------------------------------------------------------
// HTTP mapping — only compiled when the server feature is active.
// Keeping the error enum itself available on no-server builds (e.g. for
// callers that embed the daemon as a library and drive it without axum)
// is intentional.
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
mod http_response {
    use super::DaemonError;
    use axum::Json;
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use serde::Serialize;

    /// Minimal, request-data-free error body.
    ///
    /// `error` is a machine-readable kebab-case code. `message` is a
    /// fixed per-variant template; callers should branch on `error`, not
    /// `message`.
    #[derive(Serialize)]
    struct ErrorBody {
        error: &'static str,
        message: &'static str,
    }

    impl DaemonError {
        /// Stable machine-readable discriminant (kebab-case). Exposed as
        /// a `pub fn` so integration tests can assert on the exact wire
        /// string without re-deriving it from the enum.
        pub fn code(&self) -> &'static str {
            match self {
                DaemonError::TokenGenerationFailed => "token-generation-failed",
                DaemonError::BindFailed(_) => "bind-failed",
                DaemonError::MdnsError(_) => "mdns-error",
                DaemonError::NetworkDetectionFailed(_) => "network-detection-failed",
                DaemonError::Pairing(_) => "pairing-error",
                DaemonError::EntropyCheckFailed(_) => "entropy-check-failed",
                DaemonError::NotFound => "not-found",
                DaemonError::Conflict => "conflict",
                DaemonError::Unauthorized => "unauthorized",
                DaemonError::MisdirectedHost => "misdirected-host",
                DaemonError::PayloadTooLarge => "payload-too-large",
                DaemonError::RateLimited { .. } => "rate-limited",
                DaemonError::CapacityExhausted { .. } => "capacity-exhausted",
                DaemonError::UnauthorizedHmac => "unauthorized-hmac",
                DaemonError::UnauthorizedSig => "unauthorized-sig",
                DaemonError::NonceReplay => "nonce-replay",
                DaemonError::JsonDepthExceeded => "json-depth-exceeded",
                DaemonError::ClockSkew => "clock-skew",
                DaemonError::SessionExpired => "session-expired",
                DaemonError::InvalidPubkeyLength { .. } => "invalid-pubkey-length",
                DaemonError::UnsupportedSubkeyChain => "unsupported-subkey-chain",
                DaemonError::InvalidSubkeyChain { .. } => "invalid-subkey-chain",
            }
        }

        fn status_code(&self) -> StatusCode {
            match self {
                DaemonError::TokenGenerationFailed
                | DaemonError::BindFailed(_)
                | DaemonError::MdnsError(_)
                | DaemonError::NetworkDetectionFailed(_)
                | DaemonError::EntropyCheckFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                DaemonError::Pairing(_) => StatusCode::BAD_REQUEST,
                DaemonError::NotFound => StatusCode::NOT_FOUND,
                DaemonError::Conflict | DaemonError::NonceReplay => StatusCode::CONFLICT,
                DaemonError::Unauthorized
                | DaemonError::UnauthorizedHmac
                | DaemonError::UnauthorizedSig => StatusCode::UNAUTHORIZED,
                DaemonError::MisdirectedHost => StatusCode::MISDIRECTED_REQUEST,
                DaemonError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                DaemonError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
                DaemonError::CapacityExhausted { .. } => StatusCode::SERVICE_UNAVAILABLE,
                DaemonError::JsonDepthExceeded
                | DaemonError::ClockSkew
                | DaemonError::InvalidPubkeyLength { .. }
                | DaemonError::UnsupportedSubkeyChain
                | DaemonError::InvalidSubkeyChain { .. } => StatusCode::BAD_REQUEST,
                DaemonError::SessionExpired => StatusCode::GONE,
            }
        }

        fn safe_message(&self) -> &'static str {
            // Fixed per-variant strings. Never interpolate request data,
            // internal path names, or inner-error detail into these —
            // those go to `tracing::error!`, not to the wire.
            match self {
                DaemonError::TokenGenerationFailed => "token generation failed",
                DaemonError::BindFailed(_) => "internal error",
                DaemonError::MdnsError(_) => "internal error",
                DaemonError::NetworkDetectionFailed(_) => "internal error",
                DaemonError::EntropyCheckFailed(_) => "internal error",
                DaemonError::Pairing(_) => "pairing request invalid",
                DaemonError::NotFound => "not found",
                DaemonError::Conflict => "conflict",
                DaemonError::Unauthorized => "unauthorized",
                DaemonError::MisdirectedHost => "misdirected request",
                DaemonError::PayloadTooLarge => "payload too large",
                DaemonError::RateLimited { .. } => "too many requests",
                DaemonError::CapacityExhausted { .. } => "service at capacity",
                DaemonError::UnauthorizedHmac => "unauthorized",
                DaemonError::UnauthorizedSig => "unauthorized",
                DaemonError::NonceReplay => "nonce already used",
                DaemonError::JsonDepthExceeded => "request malformed",
                DaemonError::ClockSkew => "request malformed",
                DaemonError::SessionExpired => "session expired",
                DaemonError::InvalidPubkeyLength { .. } => "request malformed",
                DaemonError::UnsupportedSubkeyChain => "unsupported extension",
                DaemonError::InvalidSubkeyChain { .. } => "request malformed",
            }
        }

        fn retry_after(&self) -> Option<std::time::Duration> {
            match self {
                DaemonError::RateLimited { retry_after } => *retry_after,
                DaemonError::CapacityExhausted { retry_after } => Some(*retry_after),
                _ => None,
            }
        }
    }

    impl IntoResponse for DaemonError {
        fn into_response(self) -> Response {
            let status = self.status_code();
            let code = self.code();
            let message = self.safe_message();
            let retry_after = self.retry_after();

            // Structured server-side log. The full source chain (inner
            // io::Error, PairingError detail, etc.) lands here — never in
            // the response body.
            match status.as_u16() {
                500..=599 => tracing::error!(error = %self, code, "daemon error"),
                400..=499 => tracing::warn!(error = %self, code, "daemon error"),
                _ => tracing::debug!(error = %self, code, "daemon response"),
            }

            let body = Json(ErrorBody {
                error: code,
                message,
            });
            let mut response = (status, body).into_response();

            if let Some(dur) = retry_after {
                let secs = dur.as_secs().max(1);
                if let Ok(hv) = HeaderValue::from_str(&secs.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, hv);
                }
            }

            response
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn status_of(e: DaemonError) -> StatusCode {
        e.into_response().status()
    }

    #[test]
    fn http_status_mapping_is_stable() {
        assert_eq!(status_of(DaemonError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(status_of(DaemonError::Conflict), StatusCode::CONFLICT);
        assert_eq!(
            status_of(DaemonError::Unauthorized),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(DaemonError::MisdirectedHost),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            status_of(DaemonError::PayloadTooLarge),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status_of(DaemonError::RateLimited { retry_after: None }),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_of(DaemonError::CapacityExhausted {
                retry_after: Duration::from_secs(3)
            }),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_of(DaemonError::UnauthorizedHmac),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(DaemonError::UnauthorizedSig),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status_of(DaemonError::NonceReplay), StatusCode::CONFLICT);
        assert_eq!(
            status_of(DaemonError::JsonDepthExceeded),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status_of(DaemonError::ClockSkew), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(DaemonError::SessionExpired), StatusCode::GONE);
    }

    #[test]
    fn retry_after_header_emitted_for_429_and_503() {
        let r = DaemonError::RateLimited {
            retry_after: Some(Duration::from_secs(7)),
        }
        .into_response();
        assert_eq!(
            r.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("7")
        );

        let r = DaemonError::CapacityExhausted {
            retry_after: Duration::from_secs(30),
        }
        .into_response();
        assert_eq!(
            r.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("30")
        );
    }

    #[test]
    fn retry_after_absent_when_not_configured() {
        let r = DaemonError::RateLimited { retry_after: None }.into_response();
        assert!(r.headers().get("retry-after").is_none());

        let r = DaemonError::NotFound.into_response();
        assert!(r.headers().get("retry-after").is_none());
    }

    #[test]
    fn code_strings_are_stable_kebab_case() {
        // These strings are part of the wire contract — tests pin them
        // here so a rename of a variant cannot silently change the API.
        assert_eq!(DaemonError::NotFound.code(), "not-found");
        assert_eq!(DaemonError::Conflict.code(), "conflict");
        assert_eq!(DaemonError::MisdirectedHost.code(), "misdirected-host");
        assert_eq!(DaemonError::PayloadTooLarge.code(), "payload-too-large");
        assert_eq!(
            DaemonError::RateLimited { retry_after: None }.code(),
            "rate-limited"
        );
        assert_eq!(
            DaemonError::CapacityExhausted {
                retry_after: Duration::from_secs(1)
            }
            .code(),
            "capacity-exhausted"
        );
        assert_eq!(DaemonError::UnauthorizedHmac.code(), "unauthorized-hmac");
        assert_eq!(DaemonError::UnauthorizedSig.code(), "unauthorized-sig");
        assert_eq!(DaemonError::NonceReplay.code(), "nonce-replay");
        assert_eq!(DaemonError::JsonDepthExceeded.code(), "json-depth-exceeded");
        assert_eq!(DaemonError::ClockSkew.code(), "clock-skew");
        assert_eq!(DaemonError::SessionExpired.code(), "session-expired");
    }
}
