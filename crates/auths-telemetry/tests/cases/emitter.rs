use std::io::Cursor;
use std::sync::{Arc, Mutex};

use auths_telemetry::EventSink;
use auths_telemetry::sinks::stdout::WriterSink;

/// Verifies that `WriterSink` records emitted events.
#[test]
fn writer_sink_records_emitted_events() {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let writer = SharedBufWriter(Arc::clone(&buf));
    let sink = WriterSink::new(writer);

    sink.emit(r#"{"event_type":"test_event"}"#);

    let bytes = buf.lock().unwrap().clone();
    let output = String::from_utf8(bytes).unwrap();
    assert!(
        output.contains("test_event"),
        "expected event in output, got: {output:?}"
    );
}

/// Verifies `WriterSink::flush` completes without error.
#[test]
fn writer_sink_flush_completes() {
    let sink = WriterSink::new(Cursor::new(Vec::<u8>::new()));
    sink.flush(); // must not panic
}

/// Verifies `TelemetryShutdown::shutdown` completes synchronously.
#[test]
fn telemetry_shutdown_completes_synchronously() {
    use auths_telemetry::init_telemetry_with_sink;
    use std::sync::Arc;

    let sink = WriterSink::new(Cursor::new(Vec::<u8>::new()));
    let handle = init_telemetry_with_sink(Arc::new(sink));
    // Should return immediately — WriterSink has no background worker.
    handle.shutdown();
}

/// Shared buffer implementing `Write` for testing.
struct SharedBufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
