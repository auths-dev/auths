# AuditEvent Telemetry Schema

> **Auto-generated.** Do not edit by hand.
> Run `cargo xtask gen-schema` to regenerate from the `AuditEvent` Rust struct.
> CI will fail the `schema_json_is_up_to_date` integration test if this file
> drifts from the compiled struct definition.

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AuditEvent",
  "description": "Represents a standardized security event for SIEM ingestion.\n\nArgs: * `timestamp` - Unix epoch seconds when the event was recorded. * `actor_did` - The KERI decentralized identifier initiating the action. * `action` - The specific capability or operation attempted. * `status` - The resolution of the event (e.g., \"Success\", \"Denied\").\n\nUsage: ```rust use auths_telemetry::build_audit_event; let event = build_audit_event(\"did:keri:abc...\", \"assume_role\", \"Denied\"); ```",
  "type": "object",
  "required": [
    "action",
    "actor_did",
    "status",
    "timestamp"
  ],
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
    }
  }
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
