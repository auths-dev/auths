/// Contract test suite for [`MemoryEventSink`].
///
/// Generates a module with `#[test]` cases that verify behavioural correctness
/// of the `MemoryEventSink` implementation. Because `EventSink` has no
/// read-back method, the macro requires the setup expression to return a
/// `MemoryEventSink` directly (not a dyn-typed sink) so that `drain()` is
/// available for inspection.
///
/// Args:
/// * `$name` — identifier for the generated module (e.g. `memory`).
/// * `$setup` — expression returning an owned `MemoryEventSink`.
///
/// Usage:
/// ```ignore
/// event_sink_contract_tests!(memory, MemoryEventSink::new());
/// ```
#[macro_export]
macro_rules! event_sink_contract_tests {
    ($name:ident, $setup:expr $(,)?) => {
        mod $name {
            use auths_telemetry::EventSink as _;

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
                // Flush must not clear events (only drain does)
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
