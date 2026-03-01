use auths_telemetry::AuditEvent;
use schemars::schema_for;

/// Verifies that the four stable fields documented in telemetry-schema.md
/// are present and required in the schemars-generated JSON schema.
#[test]
fn audit_event_schema_has_required_fields() {
    let schema = schema_for!(AuditEvent<'static>);
    let value = serde_json::to_value(&schema).expect("schema serialization failed");

    let props = value["properties"]
        .as_object()
        .expect("AuditEvent schema must have properties");

    for field in ["timestamp", "actor_did", "action", "status"] {
        assert!(
            props.contains_key(field),
            "AuditEvent schema is missing required field: {field}"
        );
    }
}

/// Verifies that the committed docs/cloud-ci/telemetry/schema.json matches the
/// schema generated from the AuditEvent Rust struct. Fails if a developer adds
/// or renames a field without re-running `cargo xtask gen-schema`.
#[test]
fn schema_json_is_up_to_date() {
    let schema = schema_for!(AuditEvent<'static>);
    let generated = serde_json::to_string_pretty(&schema).expect("schema serialization failed");

    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/cloud-ci/telemetry/schema.json"
    ))
    .expect(
        "docs/cloud-ci/telemetry/schema.json not found. \
         Run `cargo xtask gen-schema` to generate it.",
    );

    assert_eq!(
        committed.trim(),
        generated.trim(),
        "schema.json is out of date. Run `cargo xtask gen-schema` to regenerate it."
    );
}
