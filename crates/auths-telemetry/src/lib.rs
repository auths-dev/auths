//! Auths Telemetry
//!
//! Centralized security event API for SIEM ingestion. Provides a unified,
//! deterministic telemetry standard consumed by auths-auth-server,
//! auths-registry-server, and auths-chat-server.

pub mod emitter;
pub mod event;
pub mod logging;
pub mod metrics;
pub mod ports;
pub mod sinks;

pub use emitter::{
    DROPPED_AUDIT_EVENTS, TelemetryShutdown, emit_telemetry, init_telemetry_with_sink,
};
pub use event::{AuditEvent, build_audit_event};
pub use logging::{init_json_tracing, init_tracing};
pub use metrics::{PrometheusHandle, init_prometheus};
pub use ports::EventSink;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

/// Initialises JSON tracing and the Prometheus metrics recorder.
///
/// Call once at process startup before any metrics or tracing macros are invoked.
/// Returns the Prometheus render handle used by the `/metrics` HTTP handler.
///
/// Args:
/// * `log_level`: Fallback log level (e.g. `"info"`). Overridden by `RUST_LOG`.
///
/// Usage:
/// ```ignore
/// let handle = std::sync::Arc::new(auths_telemetry::init_observability("info"));
/// ```
pub fn init_observability(log_level: &str) -> PrometheusHandle {
    init_json_tracing(log_level);
    init_prometheus()
}
