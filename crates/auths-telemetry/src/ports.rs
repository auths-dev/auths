//! Telemetry sink port definition.

/// Synchronous, fire-and-forget sink for structured telemetry payloads.
///
/// Implementations are responsible for persistence, buffering, and flushing.
/// `emit()` must never block the caller; defer I/O to a background thread or
/// accumulate in memory. `flush()` blocks until all previously-emitted payloads
/// have been persisted.
///
/// Usage:
/// ```ignore
/// use auths_telemetry::ports::EventSink;
///
/// struct NullSink;
/// impl EventSink for NullSink {
///     fn emit(&self, _payload: &str) {}
///     fn flush(&self) {}
/// }
/// ```
pub trait EventSink: Send + Sync + 'static {
    /// Emit a JSON-serialized event payload. Must not block.
    fn emit(&self, payload: &str);

    /// Block until all previously-emitted payloads have been written.
    fn flush(&self);
}
