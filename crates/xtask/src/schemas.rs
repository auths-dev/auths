use std::path::Path;

use anyhow::Context;
use auths_keri::IcpEvent;
use auths_verifier::core::{Attestation, IdentityBundle};

struct SchemaSpec {
    name: &'static str,
    filename: &'static str,
    generate: fn() -> schemars::schema::RootSchema,
}

const SCHEMAS: &[SchemaSpec] = &[
    SchemaSpec {
        name: "Attestation",
        filename: "attestation-v1.json",
        generate: || schemars::schema_for!(Attestation),
    },
    SchemaSpec {
        name: "IdentityBundle",
        filename: "identity-bundle-v1.json",
        generate: || schemars::schema_for!(IdentityBundle),
    },
    SchemaSpec {
        name: "IcpEvent",
        filename: "keri-icp-v1.json",
        generate: || schemars::schema_for!(IcpEvent),
    },
];

/// Generates JSON Schema files from Rust types into `schemas/`.
pub fn generate(workspace_root: &Path) -> anyhow::Result<()> {
    let out_dir = workspace_root.join("schemas");
    std::fs::create_dir_all(&out_dir).context("failed to create schemas/")?;

    for spec in SCHEMAS {
        let schema = (spec.generate)();
        let json = serde_json::to_string_pretty(&schema).context("failed to serialize schema")?;
        let path = out_dir.join(spec.filename);
        std::fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("Wrote {} ({})", path.display(), spec.name);
    }

    Ok(())
}

/// Validates test fixture JSON files against committed schemas.
pub fn validate(workspace_root: &Path) -> anyhow::Result<()> {
    let schema_dir = workspace_root.join("schemas");
    let fixture_dir = schema_dir.join("fixtures");

    if !fixture_dir.exists() {
        println!(
            "No fixtures directory at {}. Nothing to validate.",
            fixture_dir.display()
        );
        return Ok(());
    }

    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;

    for spec in SCHEMAS {
        let schema_path = schema_dir.join(spec.filename);
        if !schema_path.exists() {
            anyhow::bail!(
                "Schema {} not found. Run `cargo xtask generate-schemas` first.",
                schema_path.display()
            );
        }

        let schema_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&schema_path)
                .with_context(|| format!("failed to read {}", schema_path.display()))?,
        )
        .context("schema is not valid JSON")?;

        let validator = jsonschema::validator_for(&schema_json)
            .with_context(|| format!("failed to compile schema {}", spec.filename))?;

        let type_fixture_dir = fixture_dir.join(spec.filename.trim_end_matches(".json"));
        if !type_fixture_dir.exists() {
            continue;
        }

        for entry in std::fs::read_dir(&type_fixture_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            total += 1;
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("{} is not valid JSON", path.display()))?;

            let result = validator.validate(&value);
            if result.is_ok() {
                passed += 1;
                println!("  PASS: {}", path.display());
            } else {
                failed += 1;
                println!("  FAIL: {}", path.display());
                for error in validator.iter_errors(&value) {
                    println!("    - {error}");
                }
            }
        }
    }

    if total == 0 {
        println!("No fixture files found in {}.", fixture_dir.display());
    } else {
        println!("\n{total} fixtures checked: {passed} passed, {failed} failed.");
    }

    if failed > 0 {
        anyhow::bail!("{failed} fixture(s) failed schema validation");
    }

    Ok(())
}
