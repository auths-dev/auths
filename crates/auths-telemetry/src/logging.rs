use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialises the global tracing subscriber.
///
/// Reads `RUST_LOG` if set; falls back to `log_level`. Uses `.try_init()` so
/// a second call (e.g. in tests) is a silent no-op rather than a panic.
///
/// Args:
/// * `log_level`: Fallback log level string (e.g. `"info"`).
/// * `json`: When `true`, emits structured JSON (machine-readable).
///   When `false`, emits plain text (human-readable).
///
/// Usage:
/// ```ignore
/// auths_telemetry::init_tracing(&config.log_level, false);
/// ```
pub fn init_tracing(log_level: &str, json: bool) {
    if json {
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)))
            .with(tracing_subscriber::fmt::layer().json())
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)))
            .with(tracing_subscriber::fmt::layer())
            .try_init();
    }
}

/// Initialises the global tracing subscriber with structured JSON output.
///
/// Thin wrapper around `init_tracing(log_level, true)` for backward compatibility.
///
/// Args:
/// * `log_level`: Fallback log level string (e.g. `"info"`).
///
/// Usage:
/// ```ignore
/// auths_telemetry::init_json_tracing(&config.log_level);
/// ```
pub fn init_json_tracing(log_level: &str) {
    init_tracing(log_level, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests verify idempotency: calling init_tracing or init_json_tracing
    // multiple times must never panic (the global subscriber is set only once).

    #[test]
    fn init_tracing_plain_is_idempotent() {
        // First call installs the subscriber; subsequent calls are silent no-ops.
        init_tracing("info", false);
        init_tracing("debug", false); // must not panic
        init_tracing("warn", false); // must not panic
    }

    #[test]
    fn init_tracing_json_is_idempotent() {
        init_tracing("info", true);
        init_tracing("debug", true); // must not panic
    }

    #[test]
    fn init_json_tracing_is_idempotent() {
        init_json_tracing("info");
        init_json_tracing("info"); // must not panic
    }

    #[test]
    fn init_json_tracing_delegates_to_init_tracing() {
        // Both should complete without error; the global subscriber is idempotent.
        init_json_tracing("warn");
        init_tracing("warn", true);
    }
}
