use std::path::Path;

use anyhow::Context;
use auths_telemetry::AuditEvent;

/// Generates `docs/cloud-ci/telemetry/schema.json` and
/// `docs/cloud-ci/telemetry/schema.md` from the `AuditEvent` Rust struct.
///
/// Run this whenever `AuditEvent` fields change so the committed artifacts
/// stay in sync. CI will fail the `schema_json_is_up_to_date` integration
/// test if you forget.
pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let schema = schemars::schema_for!(AuditEvent<'static>);
    let json = serde_json::to_string_pretty(&schema).context("failed to serialise schema")?;

    let out_dir = workspace_root.join("docs/cloud-ci/telemetry");
    std::fs::create_dir_all(&out_dir).context("failed to create docs/cloud-ci/telemetry/")?;

    // schema.json — machine-readable artifact consumed by the sync test.
    let json_path = out_dir.join("schema.json");
    std::fs::write(&json_path, format!("{json}\n")).context("failed to write schema.json")?;
    println!("Wrote {}", json_path.display());

    // schema.md — human-readable wrapper with CI provenance note.
    let md_path = out_dir.join("schema.md");
    let md = format!(
        r#"# AuditEvent Telemetry Schema

> **Auto-generated.** Do not edit by hand.
> Run `cargo xtask gen-schema` to regenerate from the `AuditEvent` Rust struct.
> CI will fail the `schema_json_is_up_to_date` integration test if this file
> drifts from the compiled struct definition.

## JSON Schema

```json
{json}
```

## Stable Fields

| Field        | Type    | Required | Description                                          |
|--------------|---------|----------|------------------------------------------------------|
| `timestamp`  | integer | yes      | Unix epoch seconds (UTC) at event emission.          |
| `actor_did`  | string  | yes      | `did:keri:<prefix>` of the principal.                |
| `action`     | string  | yes      | Capability or operation attempted.                   |
| `status`     | string  | yes      | Policy evaluation outcome (Success / Denied / etc.). |

See `index.md` for the full action catalogue and status value semantics.
"#
    );
    std::fs::write(&md_path, md).context("failed to write schema.md")?;
    println!("Wrote {}", md_path.display());

    Ok(())
}
