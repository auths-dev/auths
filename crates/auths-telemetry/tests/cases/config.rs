use std::path::Path;

use auths_telemetry::config::{AuditConfig, load_audit_config};

#[test]
fn missing_file_returns_empty_config() {
    let config = load_audit_config(Path::new("/nonexistent/audit.toml"));
    assert!(config.sinks.is_empty());
}

#[test]
fn empty_file_returns_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(&path, "").unwrap();

    let config = load_audit_config(&path);
    assert!(config.sinks.is_empty());
}

#[test]
fn malformed_toml_returns_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(&path, "this is not valid toml [[[").unwrap();

    let config = load_audit_config(&path);
    assert!(config.sinks.is_empty());
}

#[test]
fn parses_stdout_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(
        &path,
        r#"
[[sinks]]
type = "stdout"
"#,
    )
    .unwrap();

    let config = load_audit_config(&path);
    assert_eq!(config.sinks.len(), 1);
}

#[test]
fn parses_file_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(
        &path,
        r#"
[[sinks]]
type = "file"
path = "/tmp/auths-audit.jsonl"
"#,
    )
    .unwrap();

    let config = load_audit_config(&path);
    assert_eq!(config.sinks.len(), 1);
}

#[test]
fn parses_http_sink_with_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(
        &path,
        r#"
[[sinks]]
type = "http"
url = "https://splunk.corp:8088/services/collector/event"
token_env = "SPLUNK_HEC_TOKEN"
payload_format = "splunk_hec"
auth_scheme = "splunk"
"#,
    )
    .unwrap();

    let config = load_audit_config(&path);
    assert_eq!(config.sinks.len(), 1);
}

#[test]
fn parses_multiple_sinks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(
        &path,
        r#"
[[sinks]]
type = "http"
url = "https://splunk.corp:8088/services/collector/event"
token_env = "SPLUNK_HEC_TOKEN"
payload_format = "splunk_hec"

[[sinks]]
type = "file"
path = "/var/log/auths/audit.jsonl"

[[sinks]]
type = "stdout"
"#,
    )
    .unwrap();

    let config = load_audit_config(&path);
    assert_eq!(config.sinks.len(), 3);
}

#[test]
fn empty_sinks_array_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(&path, "sinks = []").unwrap();

    let config = load_audit_config(&path);
    assert!(config.sinks.is_empty());
}

#[test]
fn build_stdout_sink() {
    let config = AuditConfig {
        sinks: vec![auths_telemetry::config::SinkConfig::Stdout],
    };
    let sinks = auths_telemetry::config::build_sinks_from_config(&config, |_| None);
    assert_eq!(sinks.len(), 1);
}

#[test]
fn build_file_sink_creates_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("subdir").join("audit.jsonl");

    let config = AuditConfig {
        sinks: vec![auths_telemetry::config::SinkConfig::File {
            path: log_path.clone(),
        }],
    };
    let sinks = auths_telemetry::config::build_sinks_from_config(&config, |_| None);
    assert_eq!(sinks.len(), 1);
    assert!(log_path.parent().unwrap().exists());
}

#[test]
fn build_skips_http_sink_when_env_var_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.toml");
    std::fs::write(
        &path,
        r#"
[[sinks]]
type = "http"
url = "https://example.com/events"
token_env = "SPLUNK_TOKEN"
payload_format = "ndjson"
"#,
    )
    .unwrap();

    let config = load_audit_config(&path);
    // Resolver always returns None — simulates missing env var
    let sinks = auths_telemetry::config::build_sinks_from_config(&config, |_| None);
    assert!(sinks.is_empty(), "should skip sink when env var is missing");
}
