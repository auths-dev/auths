# AuditEvent Telemetry Schema

> **Auto-generated.** Do not edit by hand.
> Run `cargo xtask gen-schema` to regenerate from the `AuditEvent` Rust struct.
> CI will fail the `schema_json_is_up_to_date` integration test if this file
> drifts from the compiled struct definition.

## JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AuditEvent",
  "description": "Represents a standardized security event for SIEM ingestion.\n\nArgs:\n* `timestamp` - Unix epoch seconds when the event was recorded.\n* `actor_did` - The KERI decentralized identifier initiating the action.\n* `action` - The specific capability or operation attempted.\n* `status` - The resolution of the event (e.g., \"Success\", \"Denied\").\n* `trace_id` - Optional W3C traceparent-compatible trace identifier.\n\nUsage:\n```rust\nuse auths_telemetry::build_audit_event;\nlet event = build_audit_event(\"did:keri:abc...\", \"assume_role\", \"Denied\", 0);\n```",
  "type": "object",
  "properties": {
    "action": {
      "type": "string"
    },
    "actor_did": {
      "type": "string"
    },
    "status": {
      "type": "string"
    },
    "timestamp": {
      "type": "integer",
      "format": "int64"
    },
    "trace_id": {
      "type": [
        "string",
        "null"
      ]
    }
  },
  "required": [
    "timestamp",
    "actor_did",
    "action",
    "status"
  ]
}
```

## Stable Fields

| Field        | Type    | Required | Description                                          |
|--------------|---------|----------|------------------------------------------------------|
| `timestamp`  | integer | yes      | Unix epoch seconds (UTC) at event emission.          |
| `actor_did`  | string  | yes      | `did:keri:<prefix>` of the principal.                |
| `action`     | string  | yes      | Capability or operation attempted.                   |
| `status`     | string  | yes      | Policy evaluation outcome (Success / Denied / etc.). |

See `index.md` for the full action catalogue and status value semantics.
