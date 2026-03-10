//! Audit sink configuration.
//!
//! Customers define audit sinks in a TOML file (typically `~/.auths/audit.toml`).
//! Each sink entry specifies a type, destination, and optional credentials
//! (resolved from environment variables at runtime).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tracing::warn;

use crate::ports::EventSink;
use crate::sinks::stdout::WriterSink;

/// Top-level audit configuration.
///
/// Usage:
/// ```ignore
/// let config = load_audit_config(Path::new("/home/user/.auths/audit.toml"));
/// let sinks = build_sinks_from_config(&config, |name| std::env::var(name).ok());
/// ```
#[derive(Debug, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
}

/// Authentication scheme for HTTP sinks.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// `Authorization: Splunk <token>`
    Splunk,
    /// `Authorization: Bearer <token>`
    #[default]
    Bearer,
    /// Custom header name (e.g. `DD-API-KEY`)
    ApiKeyHeader { header: String },
}

/// Payload format for HTTP sinks (matches `sinks::http::PayloadFormat`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ConfigPayloadFormat {
    SplunkHec,
    DatadogLogs,
    NdJson,
}

/// Individual sink configuration entry.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum SinkConfig {
    #[serde(rename = "http")]
    Http {
        url: String,
        token_env: String,
        #[serde(default)]
        auth_scheme: AuthScheme,
        payload_format: ConfigPayloadFormat,
        #[serde(default = "default_batch_size")]
        batch_size: usize,
        #[serde(default = "default_flush_interval")]
        flush_interval_ms: u64,
    },
    #[serde(rename = "file")]
    File { path: PathBuf },
    #[serde(rename = "stdout")]
    Stdout,
}

fn default_batch_size() -> usize {
    10
}

fn default_flush_interval() -> u64 {
    5000
}

/// Load audit config from a TOML file.
///
/// Returns an empty config if the file does not exist. Logs a warning and
/// returns empty config if the file is malformed.
///
/// Args:
/// * `path`: Path to the audit TOML config file.
///
/// Usage:
/// ```ignore
/// let config = load_audit_config(Path::new("/home/user/.auths/audit.toml"));
/// ```
pub fn load_audit_config(path: &Path) -> AuditConfig {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return AuditConfig::default(),
        Err(e) => {
            warn!("could not read audit config {}: {e}", path.display());
            return AuditConfig::default();
        }
    };

    match toml::from_str(&content) {
        Ok(config) => config,
        Err(e) => {
            warn!("invalid audit config {}: {e}", path.display());
            AuditConfig::default()
        }
    }
}

/// Build concrete [`EventSink`] instances from parsed config.
///
/// The `resolve_env` closure resolves environment variable names to values.
/// Skips sinks whose env vars are missing (with a warning). Returns sinks
/// ready for [`CompositeSink`](crate::sinks::composite::CompositeSink).
///
/// Args:
/// * `config`: Parsed audit configuration.
/// * `resolve_env`: Closure that resolves env var names to values.
///
/// Usage:
/// ```ignore
/// let sinks = build_sinks_from_config(&config, |name| std::env::var(name).ok());
/// let composite = CompositeSink::new(sinks);
/// ```
pub fn build_sinks_from_config(
    config: &AuditConfig,
    resolve_env: impl Fn(&str) -> Option<String>,
) -> Vec<Arc<dyn EventSink>> {
    let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();

    for sink_config in &config.sinks {
        match sink_config {
            SinkConfig::Http { .. } => {
                build_http_sink(&mut sinks, sink_config, &resolve_env);
            }
            SinkConfig::File { path } => {
                build_file_sink(&mut sinks, path);
            }
            SinkConfig::Stdout => {
                sinks.push(Arc::new(crate::sinks::stdout::new_stdout_sink()));
            }
        }
    }

    sinks
}

#[cfg(feature = "sink-http")]
fn build_http_sink(
    sinks: &mut Vec<Arc<dyn EventSink>>,
    sink_config: &SinkConfig,
    resolve_env: &dyn Fn(&str) -> Option<String>,
) {
    use std::collections::HashMap;

    use crate::sinks::http::{HttpSink, HttpSinkConfig, PayloadFormat};

    let SinkConfig::Http {
        url,
        token_env,
        auth_scheme,
        payload_format,
        batch_size,
        flush_interval_ms,
    } = sink_config
    else {
        return;
    };

    let Some(token) = resolve_env(token_env) else {
        warn!("skipping audit sink: env var '{token_env}' not set");
        return;
    };

    let mut headers = HashMap::new();
    match auth_scheme {
        AuthScheme::Splunk => {
            headers.insert("Authorization".to_string(), format!("Splunk {token}"));
        }
        AuthScheme::Bearer => {
            headers.insert("Authorization".to_string(), format!("Bearer {token}"));
        }
        AuthScheme::ApiKeyHeader { header } => {
            headers.insert(header.clone(), token);
        }
    }

    let format = match payload_format {
        ConfigPayloadFormat::SplunkHec => PayloadFormat::SplunkHec,
        ConfigPayloadFormat::DatadogLogs => PayloadFormat::DatadogLogs,
        ConfigPayloadFormat::NdJson => PayloadFormat::NdJson,
    };

    let config = HttpSinkConfig {
        url: url.to_string(),
        headers,
        batch_size: *batch_size,
        flush_interval_ms: *flush_interval_ms,
        timeout_ms: 2000,
        payload_format: format,
    };

    sinks.push(Arc::new(HttpSink::new(config)));
}

#[cfg(not(feature = "sink-http"))]
fn build_http_sink(
    _sinks: &mut Vec<Arc<dyn EventSink>>,
    _sink_config: &SinkConfig,
    _resolve_env: &dyn Fn(&str) -> Option<String>,
) {
    warn!("HTTP audit sinks require the 'sink-http' feature; skipping");
}

fn build_file_sink(sinks: &mut Vec<Arc<dyn EventSink>>, path: &Path) {
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        warn!("could not create directory {}: {e}", parent.display());
        return;
    }

    match fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => {
            sinks.push(Arc::new(WriterSink::new(file)));
        }
        Err(e) => {
            warn!("could not open audit log {}: {e}", path.display());
        }
    }
}
