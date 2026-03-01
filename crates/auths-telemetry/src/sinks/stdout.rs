//! Synchronous stdout telemetry sink.
//!
//! Writes newline-delimited JSON directly to a `Write` impl under a mutex.
//! Blocking I/O here is intentional — telemetry writes are rare relative to
//! application throughput. Callers that need non-blocking MPSC buffering
//! should build a `TokioMpscSink` in their binary crate and pass it to
//! `init_telemetry_with_sink`.

use std::io::{BufWriter, Write};
use std::sync::Mutex;

use crate::ports::EventSink;

/// Telemetry sink that writes newline-delimited JSON to any `Write` impl.
///
/// Thread-safe via `Mutex`. Suitable for stdout, files, or in-memory buffers.
pub struct WriterSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
}

impl<W: Write + Send> WriterSink<W> {
    /// Create a sink wrapping `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
        }
    }
}

/// Construct a `WriterSink` that writes to stdout.
pub fn new_stdout_sink() -> WriterSink<std::io::Stdout> {
    WriterSink::new(std::io::stdout())
}

impl<W: Write + Send + Sync + 'static> EventSink for WriterSink<W> {
    fn emit(&self, payload: &str) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{payload}");
            let _ = w.flush();
        }
    }

    fn flush(&self) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.flush();
        }
    }
}
