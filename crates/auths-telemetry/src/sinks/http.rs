//! Generic HTTP event sink for enterprise SIEM integration.
//!
//! Sends batched audit events to customer-configured HTTP endpoints.
//! Supports Splunk HEC, Datadog Logs, and generic NDJSON formats.
//! Non-blocking: `emit()` pushes to a bounded channel; a background thread
//! batches and POSTs.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use crate::emitter::DROPPED_AUDIT_EVENTS;
use crate::ports::EventSink;

/// Payload serialization format for the HTTP endpoint.
#[derive(Debug, Clone)]
pub enum PayloadFormat {
    /// Splunk HTTP Event Collector: concatenated JSON objects.
    /// `{"event":"..."}{"event":"..."}`
    SplunkHec,
    /// Datadog Logs API: JSON array.
    /// `[{"message":"..."}, {"message":"..."}]`
    DatadogLogs,
    /// Newline-delimited JSON (generic).
    /// `{"event":"..."}\n{"event":"..."}\n`
    NdJson,
}

/// Configuration for an [`HttpSink`].
#[derive(Debug, Clone)]
pub struct HttpSinkConfig {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub timeout_ms: u64,
    pub payload_format: PayloadFormat,
}

impl Default for HttpSinkConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            headers: HashMap::new(),
            batch_size: 10,
            flush_interval_ms: 5000,
            timeout_ms: 2000,
            payload_format: PayloadFormat::NdJson,
        }
    }
}

enum WorkerMsg {
    Event(String),
    Flush(std_mpsc::SyncSender<()>),
    Shutdown,
}

/// Generic HTTP POST event sink.
///
/// Events are queued via a bounded channel and delivered by a background thread.
/// Best-effort delivery — HTTP failures are silently dropped.
///
/// Args:
/// * `config`: Sink configuration (URL, headers, format, batching).
///
/// Usage:
/// ```ignore
/// let config = HttpSinkConfig { url: "https://splunk.corp:8088/services/collector/event".into(), ..Default::default() };
/// let sink = HttpSink::new(config);
/// sink.emit(r#"{"action":"sign"}"#);
/// sink.flush();
/// ```
pub struct HttpSink {
    tx: tokio::sync::mpsc::Sender<WorkerMsg>,
    worker_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl HttpSink {
    /// Create a new HTTP sink with the given config. Spawns a background worker thread.
    pub fn new(config: HttpSinkConfig) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<WorkerMsg>(256);

        let worker_handle = std::thread::Builder::new()
            .name("auths-http-sink".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    rt.block_on(worker_loop(config, rx));
                }
            });

        Self {
            tx,
            worker_handle: std::sync::Mutex::new(worker_handle.ok()),
        }
    }
}

impl EventSink for HttpSink {
    fn emit(&self, payload: &str) {
        if self
            .tx
            .try_send(WorkerMsg::Event(payload.to_string()))
            .is_err()
        {
            DROPPED_AUDIT_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(0);
        if self.tx.try_send(WorkerMsg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(Duration::from_secs(2));
        }
    }
}

impl Drop for HttpSink {
    fn drop(&mut self) {
        let _ = self.tx.try_send(WorkerMsg::Shutdown);
        if let Ok(mut guard) = self.worker_handle.lock()
            && let Some(handle) = guard.take()
        {
            let _ = handle.join();
        }
    }
}

async fn worker_loop(config: HttpSinkConfig, mut rx: tokio::sync::mpsc::Receiver<WorkerMsg>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("auths-telemetry/0.1")
        .build();

    let Ok(client) = client else { return };

    let mut buffer: Vec<String> = Vec::with_capacity(config.batch_size);
    let flush_interval = Duration::from_millis(config.flush_interval_ms);
    let mut timer = tokio::time::interval(flush_interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick
    timer.tick().await;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(WorkerMsg::Event(payload)) => {
                        buffer.push(payload);
                        if buffer.len() >= config.batch_size {
                            send_batch(&client, &config, &mut buffer).await;
                        }
                    }
                    Some(WorkerMsg::Flush(ack)) => {
                        if !buffer.is_empty() {
                            send_batch(&client, &config, &mut buffer).await;
                        }
                        let _ = ack.send(());
                    }
                    Some(WorkerMsg::Shutdown) | None => {
                        if !buffer.is_empty() {
                            send_batch(&client, &config, &mut buffer).await;
                        }
                        break;
                    }
                }
            }
            _ = timer.tick() => {
                if !buffer.is_empty() {
                    send_batch(&client, &config, &mut buffer).await;
                }
            }
        }
    }
}

async fn send_batch(client: &reqwest::Client, config: &HttpSinkConfig, buffer: &mut Vec<String>) {
    let body = format_batch(&config.payload_format, buffer);
    buffer.clear();

    let content_type = match config.payload_format {
        PayloadFormat::NdJson => "application/x-ndjson",
        PayloadFormat::SplunkHec | PayloadFormat::DatadogLogs => "application/json",
    };

    let mut req = client
        .post(&config.url)
        .header("Content-Type", content_type)
        .body(body);

    for (key, value) in &config.headers {
        req = req.header(key.as_str(), value.as_str());
    }

    // Best-effort: silently drop HTTP errors
    let _ = req.send().await;
}

/// Serialize a batch of JSON payloads into the format-specific HTTP body.
///
/// Args:
/// * `format`: The target payload format.
/// * `events`: Raw JSON payload strings from `emit()`.
pub fn format_batch(format: &PayloadFormat, events: &[String]) -> String {
    match format {
        PayloadFormat::SplunkHec => {
            let mut body = String::new();
            for event in events {
                body.push_str(r#"{"event":"#);
                body.push_str(event);
                body.push_str(r#","source":"auths","sourcetype":"auths:audit"}"#);
            }
            body
        }
        PayloadFormat::DatadogLogs => {
            let entries: Vec<String> = events
                .iter()
                .map(|e| format!(r#"{{"message":{e},"ddsource":"auths","service":"auths"}}"#))
                .collect();
            format!("[{}]", entries.join(","))
        }
        PayloadFormat::NdJson => {
            let mut body = String::new();
            for event in events {
                body.push_str(event);
                body.push('\n');
            }
            body
        }
    }
}
