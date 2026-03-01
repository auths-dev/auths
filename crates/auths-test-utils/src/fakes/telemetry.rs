//! In-memory telemetry sink for testing.

use std::sync::{Arc, Mutex};

use auths_telemetry::EventSink;

/// A sink that accumulates emitted payloads in memory.
///
/// Intended exclusively for testing — replaces the stdout sink so that tests can
/// inspect emitted events without writing to stdout or spawning background tasks.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::fakes::telemetry::MemoryEventSink;
///
/// let sink = MemoryEventSink::new();
/// let captured = sink.events_handle();
/// auths_telemetry::init_telemetry_with_sink(Box::new(sink));
/// // ... emit events ...
/// let events = captured.lock().unwrap();
/// assert_eq!(events.len(), 1);
/// ```
pub struct MemoryEventSink {
    events: Arc<Mutex<Vec<String>>>,
}

impl MemoryEventSink {
    /// Create a new `MemoryEventSink`.
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a clone of the shared event buffer for inspection.
    ///
    /// Args:
    /// * None.
    pub fn events_handle(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.events)
    }

    /// Drain and return all captured events, leaving the buffer empty.
    ///
    /// Args:
    /// * None.
    pub fn drain(&self) -> Vec<String> {
        self.events.lock().unwrap().drain(..).collect()
    }
}

impl Default for MemoryEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for MemoryEventSink {
    fn emit(&self, payload: &str) {
        self.events.lock().unwrap().push(payload.to_string());
    }

    /// No-op — all events are already in memory.
    fn flush(&self) {}
}

#[cfg(test)]
mod contract_tests {
    use super::MemoryEventSink;

    crate::event_sink_contract_tests!(memory, MemoryEventSink::new());
}
