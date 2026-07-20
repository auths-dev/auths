//! Binding-boundary lint: the Node bindings are a presentation layer.
//!
//! `packages/auths-node` exists to marshal — it calls `auths_sdk` workflows
//! (and the contract/wire crates `auths_verifier`, `auths_keri`, `auths_rp`,
//! `auths_crypto`), it does not reach into `auths_id` / `auths_core` /
//! `auths_storage` primitives. Every such reach is a place where the binding
//! can drift from the SDK's orchestration — the `delegateAgent` incident
//! (bindings kept minting attestation-linked agents long after the SDK went
//! KERI-native) is the class this lint prevents.
//!
//! Existing reaches are grandfathered with a trailing
//! `// binding-boundary-allow: <reason>` and shrink over time; a NEW deep
//! import without the annotation fails CI.

use std::path::PathBuf;

use anyhow::{Context, bail};

const BINDINGS_SRC: &str = "packages/auths-node/src";
const DEEP_PREFIXES: &[&str] = &["use auths_id::", "use auths_core::", "use auths_storage::"];
const ALLOW_MARKER: &str = "binding-boundary-allow:";

/// Run the lint over the Node bindings source.
///
/// Args:
/// * `workspace_root`: The repository root.
///
/// Usage:
/// ```ignore
/// check_binding_boundary::run(workspace_root())?;
/// ```
pub fn run(workspace_root: PathBuf) -> anyhow::Result<()> {
    let src = workspace_root.join(BINDINGS_SRC);
    let mut violations = Vec::new();
    let mut scanned = 0usize;

    for entry in std::fs::read_dir(&src).with_context(|| format!("read {}", src.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        scanned += 1;
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            let is_deep = DEEP_PREFIXES.iter().any(|p| trimmed.starts_with(p));
            // rustfmt may float a trailing annotation to the next line (inside a
            // brace group) — accept the marker on the line, the one above, or below.
            let annotated = line.contains(ALLOW_MARKER)
                || idx
                    .checked_sub(1)
                    .is_some_and(|i| lines[i].contains(ALLOW_MARKER))
                || lines.get(idx + 1).is_some_and(|l| l.contains(ALLOW_MARKER));
            if is_deep && !annotated {
                violations.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(&workspace_root)
                        .unwrap_or(&path)
                        .display(),
                    idx + 1,
                    trimmed
                ));
            }
        }
    }

    if !violations.is_empty() {
        for v in &violations {
            eprintln!("BINDING-BOUNDARY  {v}");
        }
        bail!(
            "{} deep import(s) in the Node bindings without a `{ALLOW_MARKER}` annotation. \
             Bindings are a presentation layer: call an auths_sdk workflow instead, or \
             annotate the line with the reason and a migration note.",
            violations.len()
        );
    }

    println!("binding-boundary check: {scanned} binding files scanned, 0 violations");
    Ok(())
}
