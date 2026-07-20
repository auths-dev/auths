//! Generate the verdict-code contract manifest from the verifiers' `code()`
//! methods.
//!
//! Every verdict string a relying party can receive is defined once, in an
//! inherent `code()` on the emitting enum. Downstream consumers — the docs
//! verdict allowlist, the `@auths-dev/mcp` release gate, the marketing site —
//! hardcode copies today, so a rename in one place silently breaks them (a
//! `consistent → self-consistent` rename did exactly that). This scans each
//! `code()` for the literals it can emit and writes them, namespaced by
//! emitter, to `schemas/contracts-v1.json` — the one artifact those consumers
//! assert against, gated by the same generate-then-`git diff` idiom the JSON
//! schemas use.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// A verdict family — the emitting enum and the source file its `code()` lives
/// in. The `key` namespaces vocabulary that overlaps across layers (e.g.
/// `revoked` is emitted by both `gate` and `commit`).
struct Family {
    key: &'static str,
    enum_name: &'static str,
    file: &'static str,
}

const FAMILIES: &[Family] = &[
    Family {
        key: "audit",
        enum_name: "AuditVerdict",
        file: "crates/auths-mcp-core/src/audit.rs",
    },
    Family {
        key: "call",
        enum_name: "CallVerdict",
        file: "crates/auths-evidence/src/types.rs",
    },
    Family {
        key: "commit",
        enum_name: "CommitVerdict",
        file: "crates/auths-verifier/src/commit_kel.rs",
    },
    Family {
        key: "gate",
        enum_name: "Verdict",
        file: "crates/auths-mcp-core/src/gate.rs",
    },
    Family {
        key: "log",
        enum_name: "LogVerdict",
        file: "crates/auths-evidence/src/types.rs",
    },
    Family {
        key: "paymode",
        enum_name: "BudgetRequired",
        file: "crates/auths-mcp-core/src/paymode.rs",
    },
];

const MANIFEST_PATH: &str = "schemas/contracts-v1.json";

#[derive(serde::Serialize)]
struct Manifest {
    version: &'static str,
    verdicts: BTreeMap<String, Vec<String>>,
}

/// Regenerate the verdict manifest from source, or (in check mode) fail if the
/// committed manifest is stale.
///
/// Args:
/// * `workspace_root`: the repo root the family paths resolve against.
/// * `check`: when true, do not write — exit non-zero if the committed manifest
///   drifted from source (the CI gate).
///
/// Usage:
/// ```ignore
/// gen_contracts::run(workspace_root(), false)?; // regenerate the manifest
/// ```
pub fn run(workspace_root: &Path, check: bool) -> Result<()> {
    let manifest = build_manifest(workspace_root)?;
    let json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
    let content = format!("{json}\n");
    let path = workspace_root.join(MANIFEST_PATH);
    if check {
        let committed =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if committed != content {
            bail!("{MANIFEST_PATH} is out of date — run `cargo xtask gen-contracts` to regenerate");
        }
        println!("gen-contracts: {MANIFEST_PATH} is up to date");
    } else {
        std::fs::write(&path, &content).with_context(|| format!("write {}", path.display()))?;
        println!("gen-contracts: wrote {MANIFEST_PATH}");
    }
    Ok(())
}

/// Read every family's source and collect its verdict codes into the manifest.
fn build_manifest(workspace_root: &Path) -> Result<Manifest> {
    let mut verdicts = BTreeMap::new();
    for family in FAMILIES {
        let text = std::fs::read_to_string(workspace_root.join(family.file))
            .with_context(|| format!("read {}", family.file))?;
        let codes = family_codes(&text, family.enum_name);
        if codes.is_empty() {
            bail!(
                "no verdict codes parsed for {} in {} — did the code() shape change?",
                family.enum_name,
                family.file
            );
        }
        verdicts.insert(family.key.to_string(), codes);
    }
    Ok(Manifest {
        version: "contracts/v1",
        verdicts,
    })
}

/// The inherent-impl type a line opens (`impl Foo {` → `Some("Foo")`); `None`
/// for trait impls (`impl Bar for Foo`) and non-impl lines.
fn inherent_impl_target(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("impl ")?;
    if rest.contains(" for ") {
        return None;
    }
    rest.split(|c: char| c.is_whitespace() || c == '{' || c == '<')
        .next()
        .filter(|name| !name.is_empty())
}

/// The kebab-case verdict code a line carries (`… => "chain-break"` or a bare
/// `"budget-required"`), if any. Only lowercase kebab tokens qualify, so message
/// strings and doc text inside a `code()` body never leak in.
fn kebab_code(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    let lit = &rest[..end];
    let is_kebab = !lit.is_empty()
        && lit.starts_with(|c: char| c.is_ascii_lowercase())
        && lit
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    is_kebab.then_some(lit)
}

/// Collect, in source order, the codes the named enum's inherent `code()` can
/// emit. Tracks the current inherent impl so a file with two verdict enums
/// (e.g. `CallVerdict` and `LogVerdict`) resolves each independently.
fn family_codes(text: &str, enum_name: &str) -> Vec<String> {
    let mut current_impl: Option<&str> = None;
    let mut collecting = false;
    let mut depth = 0i32;
    let mut codes = Vec::new();
    for line in text.lines() {
        if !collecting {
            if let Some(target) = inherent_impl_target(line) {
                current_impl = Some(target);
            }
            if current_impl != Some(enum_name) || !line.contains("fn code(&self)") {
                continue;
            }
            collecting = true;
            depth = 0;
        }
        // A comment line inside the body carries no code and no real brace
        // scope — skip it, so a `// "self-consistent" …` note above an arm can't
        // leak a phantom literal (nor its prose braces skew the depth count).
        if line.trim_start().starts_with("//") {
            continue;
        }
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if let Some(code) = kebab_code(line) {
            codes.push(code.to_string());
        }
        if depth <= 0 {
            collecting = false;
            current_impl = None;
        }
    }
    codes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn every_family_parses_to_a_non_empty_kebab_set() {
        let manifest = build_manifest(&workspace_root()).expect("build manifest");
        assert_eq!(manifest.verdicts.len(), FAMILIES.len());
        for (key, codes) in &manifest.verdicts {
            assert!(!codes.is_empty(), "no codes for family {key}");
            let unique: std::collections::BTreeSet<_> = codes.iter().collect();
            assert_eq!(
                unique.len(),
                codes.len(),
                "duplicate code in family {key} — a comment leak or a repeated arm? {codes:?}"
            );
            for code in codes {
                assert!(
                    code.starts_with(|c: char| c.is_ascii_lowercase())
                        && code
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "non-kebab code {code:?} in {key}"
                );
            }
        }
    }

    #[test]
    fn the_renames_that_bit_us_are_reflected() {
        let manifest = build_manifest(&workspace_root()).expect("build manifest");
        let audit = &manifest.verdicts["audit"];
        assert!(audit.contains(&"self-consistent".to_string()));
        assert!(audit.contains(&"chain-break".to_string()));
        // The offline audit is `self-consistent`, never a bare `consistent`.
        assert!(!audit.contains(&"consistent".to_string()));
        // The whole-log evidence judge, however, IS `consistent`.
        assert!(manifest.verdicts["log"].contains(&"consistent".to_string()));
        assert_eq!(
            manifest.verdicts["paymode"],
            vec!["budget-required".to_string()]
        );
        assert!(manifest.verdicts["gate"].contains(&"allowed".to_string()));
    }
}
