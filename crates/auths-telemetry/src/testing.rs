use std::sync::{Arc, Mutex};

use crate::EventSink;

/// A sink that accumulates emitted payloads in memory.
///
/// Intended exclusively for testing — replaces the stdout sink so that tests can
/// inspect emitted events without writing to stdout or spawning background tasks.
///
/// Usage:
/// ```ignore
/// use auths_telemetry::testing::MemoryEventSink;
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

    fn flush(&self) {}
}

/// Contract test suite for [`EventSink`] implementations.
///
/// Generates a module with `#[test]` cases that verify behavioural correctness.
/// The setup expression must return a type that implements `EventSink` and has
/// a `drain() -> Vec<String>` method for inspection.
///
/// Args:
/// * `$name` — identifier for the generated module (e.g. `memory`).
/// * `$setup` — expression returning an owned sink instance.
///
/// Usage:
/// ```ignore
/// auths_telemetry::event_sink_contract_tests!(memory, MemoryEventSink::new());
/// ```
#[macro_export]
macro_rules! event_sink_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use $crate::EventSink as _;

            use super::*;

            #[test]
            fn contract_emit_captures_payload() {
                let sink = $setup;
                sink.emit("hello");
                let events = sink.drain();
                assert_eq!(events, vec!["hello".to_string()]);
            }

            #[test]
            fn contract_flush_is_noop() {
                let sink = $setup;
                sink.emit("a");
                sink.flush();
                let events = sink.drain();
                assert_eq!(events.len(), 1);
            }

            #[test]
            fn contract_emit_preserves_order() {
                let sink = $setup;
                sink.emit("first");
                sink.emit("second");
                sink.emit("third");
                let events = sink.drain();
                assert_eq!(events, vec!["first", "second", "third"]);
            }

            #[test]
            fn contract_drain_clears_buffer() {
                let sink = $setup;
                sink.emit("x");
                let first = sink.drain();
                let second = sink.drain();
                assert_eq!(first.len(), 1);
                assert!(second.is_empty(), "drain should clear the buffer");
            }

            #[test]
            fn contract_emit_empty_payload_is_stored() {
                let sink = $setup;
                sink.emit("");
                let events = sink.drain();
                assert_eq!(events, vec!["".to_string()]);
            }
        }
    };
}

#[cfg(test)]
mod contract_tests {
    use super::MemoryEventSink;

    crate::event_sink_contract_tests!(memory, MemoryEventSink::new());
}
