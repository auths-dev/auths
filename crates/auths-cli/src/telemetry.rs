//! CLI-owned telemetry infrastructure.
//!
//! Provides `TokioMpscSink` — an async, non-blocking telemetry sink backed by
//! a `tokio::sync::mpsc` channel. The CLI binary owns the background worker
//! task so the library crate (`auths-telemetry`) remains tokio-free.
//!
//! # Usage (async CLI entry point)
//!
//! ```ignore
//! use auths_cli::telemetry::TokioMpscSink;
//! use auths_telemetry::init_telemetry_with_sink;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let sink = TokioMpscSink::new(256);
//!     init_telemetry_with_sink(Arc::new(sink.clone()));
//!
//!     let result = run_command().await;
//!
//!     sink.flush().await;
//!     result
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;

use auths_telemetry::EventSink;
use tokio::sync::mpsc;

static DROPPED: AtomicU64 = AtomicU64::new(0);

enum WorkerMsg {
    Event(String),
    Flush(std_mpsc::SyncSender<()>),
}

/// Non-blocking telemetry sink backed by a Tokio MPSC channel.
///
/// `emit()` is non-blocking — events are queued to the channel. `flush()` is
/// synchronous and blocks until the background worker acknowledges all prior
/// events. Call `flush().await` before the process exits.
#[derive(Clone)]
pub struct TokioMpscSink {
    tx: mpsc::WeakSender<WorkerMsg>,
    /// Kept alive so the channel stays open until `flush()` drops it.
    _strong: std::sync::Arc<mpsc::Sender<WorkerMsg>>,
}

impl TokioMpscSink {
    /// Spawn the background writer and return the sink.
    ///
    /// Args:
    /// * `capacity`: MPSC channel buffer depth in events.
    ///
    /// Usage:
    /// ```ignore
    /// let sink = TokioMpscSink::new(256);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<WorkerMsg>(capacity);
        let weak = tx.downgrade();
        let strong = std::sync::Arc::new(tx);

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut writer = tokio::io::BufWriter::new(tokio::io::stdout());

            while let Some(msg) = rx.recv().await {
                match msg {
                    WorkerMsg::Event(line) => {
                        let _ = writer.write_all(line.as_bytes()).await;
                        let _ = writer.write_all(b"\n").await;
                        let _ = writer.flush().await;

                        let dropped = DROPPED.swap(0, Ordering::AcqRel);
                        if dropped > 0 {
                            let meta = serde_json::json!({
                                "event_type": "TelemetryDegradation",
                                "dropped_count": dropped,
                            });
                            let s = serde_json::to_string(&meta).unwrap_or_default();
                            let _ = writer.write_all(s.as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                            let _ = writer.flush().await;
                        }
                    }
                    WorkerMsg::Flush(ack) => {
                        let _ = writer.flush().await;
                        let _ = ack.send(());
                    }
                }
            }
            let _ = writer.flush().await;
        });

        Self {
            tx: weak,
            _strong: strong,
        }
    }

    /// Flush all buffered events and wait for the worker to drain.
    ///
    /// Call this before the process exits to prevent losing events.
    pub async fn flush(self) {
        // Drop the strong sender so the channel closes after the flush message.
        let strong = self._strong;
        let tx = self.tx.upgrade();
        drop(strong);
        if let Some(tx) = tx {
            let (ack_tx, ack_rx) = std_mpsc::sync_channel(0);
            let _ = tx.send(WorkerMsg::Flush(ack_tx)).await;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(5));
            })
            .await;
        }
    }
}

impl EventSink for TokioMpscSink {
    fn emit(&self, payload: &str) {
        let Some(tx) = self.tx.upgrade() else { return };
        if tx.try_send(WorkerMsg::Event(payload.to_string())).is_err() {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) {
        let Some(tx) = self.tx.upgrade() else { return };
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(0);
        if tx.try_send(WorkerMsg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(5));
        }
    }
}
