//! Composite sink that fans out events to multiple child sinks.

use std::sync::Arc;

use crate::ports::EventSink;

/// Routes events to multiple [`EventSink`] children simultaneously.
///
/// Each child receives every emitted payload independently. A panic or failure
/// in one child does not prevent delivery to the remaining children.
///
/// Args:
/// * `sinks`: The child sinks to fan out to.
///
/// Usage:
/// ```ignore
/// let composite = CompositeSink::new(vec![sink_a, sink_b]);
/// composite.emit(r#"{"action":"sign"}"#);
/// ```
pub struct CompositeSink {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl CompositeSink {
    /// Create a sink that fans out to the given children.
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }

    /// Create a sink with no children (noop).
    pub fn empty() -> Self {
        Self { sinks: Vec::new() }
    }
}

impl EventSink for CompositeSink {
    fn emit(&self, payload: &str) {
        for sink in &self.sinks {
            // Isolate panics so one broken child cannot kill siblings
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink.emit(payload);
            }));
        }
    }

    fn flush(&self) {
        for sink in &self.sinks {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink.flush();
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MemoryEventSink;

    /// Harness that wraps a CompositeSink with a single MemoryEventSink child,
    /// exposing `drain()` so the `event_sink_contract_tests!` macro works.
    struct ContractHarness {
        composite: CompositeSink,
        inner: Arc<MemoryEventSink>,
    }

    impl ContractHarness {
        fn new() -> Self {
            let inner = Arc::new(MemoryEventSink::new());
            let composite = CompositeSink::new(vec![inner.clone()]);
            Self { composite, inner }
        }

        fn drain(&self) -> Vec<String> {
            self.inner.drain()
        }
    }

    impl EventSink for ContractHarness {
        fn emit(&self, payload: &str) {
            self.composite.emit(payload);
        }

        fn flush(&self) {
            self.composite.flush();
        }
    }

    crate::event_sink_contract_tests!(composite_contract, ContractHarness::new());
}
