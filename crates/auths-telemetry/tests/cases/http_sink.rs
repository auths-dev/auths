use std::collections::HashMap;
use std::time::Duration;

use auths_telemetry::EventSink;
use auths_telemetry::sinks::http::{HttpSink, HttpSinkConfig, PayloadFormat, format_batch};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(server: &MockServer, format: PayloadFormat) -> HttpSinkConfig {
    HttpSinkConfig {
        url: format!("{}/events", server.uri()),
        headers: HashMap::new(),
        batch_size: 10,
        flush_interval_ms: 60000,
        timeout_ms: 2000,
        payload_format: format,
    }
}

#[tokio::test]
async fn ndjson_format_delivers_events() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = config_for(&server, PayloadFormat::NdJson);
    config.batch_size = 2;

    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    sink.emit(r#"{"action":"verify"}"#);

    // Give the worker time to flush the batch
    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.flush();
    drop(sink);

    // wiremock verifies expect(1) on drop
}

#[tokio::test]
async fn splunk_hec_format_sends_concatenated_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = config_for(&server, PayloadFormat::SplunkHec);
    config.batch_size = 2;
    config
        .headers
        .insert("Authorization".to_string(), "Splunk test-token".to_string());

    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    sink.emit(r#"{"action":"verify"}"#);

    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.flush();
    drop(sink);
}

#[tokio::test]
async fn datadog_format_sends_json_array() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = config_for(&server, PayloadFormat::DatadogLogs);
    config.batch_size = 2;
    config
        .headers
        .insert("DD-API-KEY".to_string(), "test-key".to_string());

    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    sink.emit(r#"{"action":"verify"}"#);

    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.flush();
    drop(sink);
}

#[tokio::test]
async fn flush_delivers_partial_batch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = config_for(&server, PayloadFormat::NdJson);
    // batch_size is 10, but we only emit 1 event — flush should still deliver
    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    sink.flush();
    drop(sink);
}

#[tokio::test]
async fn http_error_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut config = config_for(&server, PayloadFormat::NdJson);
    config.batch_size = 1;

    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.emit(r#"{"action":"verify"}"#);
    sink.flush();
    drop(sink);
    // No panic = success
}

#[tokio::test]
async fn drop_shuts_down_cleanly() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = config_for(&server, PayloadFormat::NdJson);
    let sink = HttpSink::new(config);
    sink.emit(r#"{"action":"sign"}"#);
    drop(sink);
    // Clean shutdown = no hang, no panic
}

#[test]
fn format_batch_splunk_hec_concatenates_objects() {
    let events = vec![
        r#"{"action":"sign"}"#.to_string(),
        r#"{"action":"verify"}"#.to_string(),
    ];
    let body = format_batch(&PayloadFormat::SplunkHec, &events);
    assert!(
        !body.starts_with('['),
        "Splunk HEC must NOT be a JSON array"
    );
    assert!(
        body.contains(r#"{"event":{"action":"sign"}"#),
        "body: {body}"
    );
    assert!(
        body.contains(r#"{"event":{"action":"verify"}"#),
        "body: {body}"
    );
}

#[test]
fn format_batch_datadog_produces_json_array() {
    let events = vec![
        r#"{"action":"sign"}"#.to_string(),
        r#"{"action":"verify"}"#.to_string(),
    ];
    let body = format_batch(&PayloadFormat::DatadogLogs, &events);
    assert!(body.starts_with('['), "Datadog must be a JSON array");
    assert!(body.ends_with(']'), "Datadog must end with ]");
    assert!(body.contains(r#""ddsource":"auths""#), "body: {body}");
}

#[test]
fn format_batch_ndjson_uses_newlines() {
    let events = vec![
        r#"{"action":"sign"}"#.to_string(),
        r#"{"action":"verify"}"#.to_string(),
    ];
    let body = format_batch(&PayloadFormat::NdJson, &events);
    let lines: Vec<&str> = body.trim_end().split('\n').collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], r#"{"action":"sign"}"#);
    assert_eq!(lines[1], r#"{"action":"verify"}"#);
}

#[test]
fn format_batch_empty_events_produces_empty_output() {
    let events: Vec<String> = vec![];
    assert_eq!(format_batch(&PayloadFormat::NdJson, &events), "");
    assert_eq!(format_batch(&PayloadFormat::SplunkHec, &events), "");
    assert_eq!(format_batch(&PayloadFormat::DatadogLogs, &events), "[]");
}
