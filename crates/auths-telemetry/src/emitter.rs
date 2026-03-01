use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;

use crate::event::AuditEvent;
use crate::ports::EventSink;

/// Counts events silently dropped because the telemetry channel was full.
///
/// Consumers of `WriterSink` do not drop events; this counter is retained for
/// compatibility with code paths that may use a custom buffering sink that
/// increments this counter on back-pressure.
/// Monitor this counter in alerting rules for SOC2 / FedRAMP compliance.
pub static DROPPED_AUDIT_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Global sink set once at `init_telemetry_with_sink` time.
static TELEMETRY_SINK: OnceLock<Arc<dyn EventSink>> = OnceLock::new();

/// Handle returned by `init_telemetry_with_sink`.
///
/// Call `shutdown()` before the process exits to flush any buffered events.
pub struct TelemetryShutdown {
    sink: Arc<dyn EventSink>,
}

impl TelemetryShutdown {
    /// Flush all buffered events.
    ///
    /// Usage:
    /// ```ignore
    /// let telemetry = auths_telemetry::init_telemetry_with_sink(sink);
    /// run_server(state).await?;
    /// telemetry.shutdown();
    /// ```
    pub fn shutdown(self) {
        self.sink.flush();
    }
}

/// Initialises the telemetry pipeline with an injectable sink.
///
/// Allows servers, CLIs, and tests to provide their own sink implementation.
/// A second call is a silent no-op; the first initialisation wins.
///
/// Args:
/// * `sink` - The sink implementation to install globally.
///
/// Usage:
/// ```ignore
/// use auths_telemetry::{init_telemetry_with_sink, sinks::stdout::new_stdout_sink};
/// use std::sync::Arc;
/// let _handle = init_telemetry_with_sink(Arc::new(new_stdout_sink()));
/// ```
pub fn init_telemetry_with_sink(sink: Arc<dyn EventSink>) -> TelemetryShutdown {
    let _ = TELEMETRY_SINK.set(Arc::clone(&sink));
    TelemetryShutdown { sink }
}

/// Emits a structured telemetry event to the active sink.
///
/// Serialises `event` to JSON and forwards to the active sink. Returns
/// immediately. If `init_telemetry_with_sink` was never called, this is a no-op.
///
/// Args:
/// * `event` - The structured audit event to emit.
///
/// Usage:
/// ```rust
/// use auths_telemetry::{build_audit_event, emit_telemetry};
/// let event = build_audit_event("did:keri:abc...", "session_verification", "Success", 0);
/// emit_telemetry(&event);
/// ```
pub fn emit_telemetry(event: &AuditEvent<'_>) {
    let Some(sink) = TELEMETRY_SINK.get() else {
        return;
    };
    let payload = serde_json::to_string(event).unwrap_or_default();
    sink.emit(&payload);
}
