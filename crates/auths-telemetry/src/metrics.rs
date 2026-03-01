pub use metrics_exporter_prometheus::PrometheusHandle;

/// Installs the global Prometheus metrics recorder and returns a render handle.
///
/// Call once at process startup, before any `metrics::counter!` / `metrics::gauge!`
/// / `metrics::histogram!` macro is invoked. The returned handle is used by the
/// `/metrics` HTTP handler to serialise the current registry state.
///
/// Args:
/// * (none)
///
/// Usage:
/// ```ignore
/// let handle = auths_telemetry::init_prometheus();
/// ```
pub fn init_prometheus() -> PrometheusHandle {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}
