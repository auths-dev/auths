//! Opt-in Prometheus `/metrics` surface for the gateway (#7).
//!
//! The gateway is a stdio MCP server, so it exposes no HTTP by default. When
//! `AUTHS_MCP_METRICS_ADDR` is set (e.g. `127.0.0.1:9090`), [`crate::proxy::serve`] installs
//! the global Prometheus recorder and spawns this minimal HTTP/1.1 listener, which renders
//! the current registry at `GET /metrics`. Off by default — stdio mode is unaffected, and
//! the `metrics::` macros on the hot path are cheap no-ops when no recorder is installed.

use auths_telemetry::PrometheusHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Counter: total metered calls, labeled by verdict (`granted` | `refused` | `error`).
pub const CALLS_TOTAL: &str = "auths_mcp_calls_total";
/// Histogram: per-call wall-clock latency, in seconds.
pub const CALL_LATENCY: &str = "auths_mcp_call_latency_seconds";
/// Counter: per-call agent signatures, labeled by path (`inproc` | `subprocess`).
pub const SIGN_TOTAL: &str = "auths_mcp_sign_total";
/// Counter: settlements recorded to the signed spend log.
pub const SETTLE_TOTAL: &str = "auths_mcp_settle_total";

/// Serve `handle.render()` at `GET /metrics` on `addr` until the process exits.
///
/// Minimal HTTP/1.1: drains the request head, then returns the Prometheus exposition with
/// `Connection: close`. Any bind/accept error is logged and swallowed — metrics are
/// best-effort observability, never a reason to fail the gateway.
///
/// Args:
/// * `addr`: `host:port` to listen on (from `AUTHS_MCP_METRICS_ADDR`).
/// * `handle`: the Prometheus render handle from `auths_telemetry::init_prometheus`.
///
/// Usage:
/// ```ignore
/// tokio::spawn(serve_metrics(addr, handle));
/// ```
pub async fn serve_metrics(addr: String, handle: PrometheusHandle) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: metrics /metrics bind {addr} failed ({e}) — metrics disabled"
            );
            return;
        }
    };
    eprintln!("auths-mcp-gateway: metrics exposed at http://{addr}/metrics");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // drain the request head (best-effort)
            let body = handle.render();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
