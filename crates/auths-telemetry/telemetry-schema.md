# Auths Telemetry Schema

This document is the authoritative contract for enterprise integration teams,
M&A due-diligence reviewers, and CISO tooling that ingests security observables
from the Auths platform. Every field produced by `emit_telemetry` is described
here with its type, cardinality, and semantics.

---

## JSON Output Format

Each security event is emitted as a single-line JSON object to stdout.
Consumers should treat each newline-delimited record as one complete event.

### Schema

| Field        | Type    | Required | Description                                                                                       |
|--------------|---------|----------|---------------------------------------------------------------------------------------------------|
| `timestamp`  | integer | yes      | Unix epoch seconds (UTC) when the event was recorded on the emitting node.                        |
| `actor_did`  | string  | yes      | The KERI decentralized identifier (`did:keri:<prefix>`) of the principal initiating the action.   |
| `action`     | string  | yes      | The capability or operation attempted. See [Action Catalogue](#action-catalogue) below.            |
| `status`     | string  | yes      | Policy evaluation outcome. See [Status Values](#status-values) below.                             |

### Example Record

```json
{"timestamp":1708531200,"actor_did":"did:keri:EBfxc4RiVY8cr29TCl9mM0RlxS3fNPWwKJEVZeq-YKD","action":"session_verification","status":"Success"}
```

---

## Action Catalogue

| `action` value          | Emitted by              | Description                                                        |
|-------------------------|-------------------------|--------------------------------------------------------------------|
| `session_verification`  | auths-auth-server       | Mobile client submitted a signed challenge for verification.       |
| `assume_role`           | auths-auth-server       | Client requested a capability scoped to a specific role.           |
| `registry_lookup`       | auths-registry-server   | Resolver queried the identity registry for a DID's public key.     |
| `chat_message_send`     | auths-chat-server       | Authenticated principal sent an encrypted chat message.            |
| `mcp:auth`              | auths-mcp-server        | JWT authentication attempt at the MCP server middleware layer.     |
| `mcp:read_file`         | auths-mcp-server        | Agent invoked the MCP `read_file` tool.                            |
| `mcp:write_file`        | auths-mcp-server        | Agent invoked the MCP `write_file` tool.                           |
| `mcp:deploy`            | auths-mcp-server        | Agent invoked the MCP `deploy` tool.                               |
| `mcp:*`                 | auths-mcp-server        | Wildcard pattern for any MCP tool invocation (`mcp:{tool_name}`).  |

---

## Status Values

| `status` value   | Meaning                                                                              |
|------------------|--------------------------------------------------------------------------------------|
| `Success`        | The action completed normally and all policy checks passed.                          |
| `Denied`         | The action was rejected by policy (e.g. capability not granted).                     |
| `Conflict`       | A compare-and-swap race was detected (e.g. session already verified by another req). |
| `Expired`        | The session or token had passed its `expires_at` deadline.                           |
| `Invalid`        | The request payload failed structural or cryptographic validation.                   |

---

## CEF (Common Event Format) Mapping

For SIEM products that ingest CEF (ArcSight, IBM QRadar), map fields as follows:

```
CEF:0|Auths|AuthServer|1.0|<action>|<action>|<severity>|
  src=<actor_did>
  outcome=<status>
  rt=<timestamp * 1000>
```

Severity mapping:

| `status`   | CEF Severity |
|------------|--------------|
| `Success`  | 2 (Low)      |
| `Denied`   | 6 (Medium)   |
| `Conflict` | 5 (Medium)   |
| `Expired`  | 4 (Low)      |
| `Invalid`  | 7 (High)     |

---

## Parsing Guarantee

The JSON schema above is **stable**. New fields will only be added; existing
fields will never be removed or renamed within a major version. Automated log
parsers may rely on `timestamp`, `actor_did`, `action`, and `status` being
present on every record.
