//! Error-docs coverage lint: every registered `AUTHS-E` code must have a
//! generated page on disk, and every generated page must name a registered code.
//!
//! This is a page-existence/drift guard, distinct from `check_error_codes`
//! (which locks registration and suggestion coverage). It reuses the same
//! registry-enumeration path — the `code = crate::Type::Variant` bindings in
//! `docs/errors/registry.lock` — and pairs each code with its published
//! `docs/errors/AUTHS-E<code>.md` page:
//!
//! 1. A registered code with no page on disk fails the build — the generated
//!    docs went stale against the registry.
//! 2. A page on disk with no registered code fails the build — an orphan left
//!    behind after a code was reassigned or removed.
//!
//! Both directions are fixed the same way: re-run `cargo xtask gen-error-docs`.

use std::collections::BTreeSet;
use std::path::Path;

/// Verify the generated error-docs pages are in sync with the registered codes.
///
/// Enumerates the registered codes from `docs/errors/registry.lock`, then
/// asserts a `docs/errors/AUTHS-E<code>.md` page exists for each and that no
/// `AUTHS-E*.md` page exists without a registered code. Prints one
/// `path — reason` line per violation and fails on any.
///
/// Args:
/// * `workspace_root`: the repository root.
///
/// Usage:
/// ```ignore
/// check_error_docs_published::run(workspace_root)?;
/// ```
pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let registered = parse_registered_codes(workspace_root)?;
    if registered.is_empty() {
        anyhow::bail!(
            "docs/errors/registry.lock has no codes — run `cargo xtask gen-error-docs` first"
        );
    }

    let published = scan_published_codes(workspace_root)?;
    let violations = find_drift(&registered, &published);

    if violations.is_empty() {
        println!(
            "  ok       {} registered error codes each have a generated docs/errors page; no orphans",
            registered.len()
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("{v}");
        }
        anyhow::bail!(
            "{} error-docs coverage violation(s): a registered code has no generated page, \
             or a page names no registered code — run `cargo xtask gen-error-docs`",
            violations.len()
        )
    }
}

/// Parse the registered codes from `docs/errors/registry.lock`, ignoring the
/// comment header and blank lines. Each entry is a `CODE = binding` line; only
/// the code is needed here.
fn parse_registered_codes(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let path = root.join("docs/errors/registry.lock");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let mut codes = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((code, _binding)) = line.split_once('=') {
            codes.insert(code.trim().to_string());
        }
    }
    Ok(codes)
}

/// Collect the codes that have a published page: every `AUTHS-E*.md` file under
/// `docs/errors/`, mapped back to its bare code. Non-code pages (`index.md`) and
/// non-markdown files are ignored.
fn scan_published_codes(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let dir = root.join("docs/errors");
    let mut codes = BTreeSet::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(code) = name.strip_suffix(".md")
            && code.starts_with("AUTHS-E")
        {
            codes.insert(code.to_string());
        }
    }
    Ok(codes)
}

/// Compare the registered and published code sets, returning one
/// `docs/errors/<file> — reason` message per drift. Both sets are ordered, so
/// the messages come out sorted and stable.
fn find_drift(registered: &BTreeSet<String>, published: &BTreeSet<String>) -> Vec<String> {
    let mut violations = Vec::new();
    for code in registered.difference(published) {
        violations.push(format!(
            "docs/errors/{code}.md — registered code {code} has no generated docs page"
        ));
    }
    for code in published.difference(registered) {
        violations.push(format!(
            "docs/errors/{code}.md — orphan page: {code} is not in docs/errors/registry.lock"
        ));
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn code_set(codes: &[&str]) -> BTreeSet<String> {
        codes.iter().map(|c| c.to_string()).collect()
    }

    fn write_fixture(root: &Path, codes: &[&str], pages: &[&str]) {
        let errors = root.join("docs/errors");
        std::fs::create_dir_all(&errors).unwrap();
        let mut lock = String::from("# AUTHS error-code registry lock.\n");
        for code in codes {
            lock.push_str(&format!("{code} = auths-core::Example::Variant\n"));
        }
        std::fs::write(errors.join("registry.lock"), lock).unwrap();
        for page in pages {
            std::fs::write(errors.join(format!("{page}.md")), "# page\n").unwrap();
        }
    }

    #[test]
    fn complete_set_passes() {
        let registered = code_set(&["AUTHS-E1001", "AUTHS-E1002"]);
        let published = code_set(&["AUTHS-E1001", "AUTHS-E1002"]);
        assert!(find_drift(&registered, &published).is_empty());
    }

    #[test]
    fn registered_code_without_a_page_is_flagged() {
        let registered = code_set(&["AUTHS-E1001", "AUTHS-E1002"]);
        let published = code_set(&["AUTHS-E1001"]);
        let violations = find_drift(&registered, &published);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("AUTHS-E1002"),
            "the code missing a page must be named: {}",
            violations[0]
        );
    }

    #[test]
    fn orphan_page_without_a_registered_code_is_flagged() {
        let registered = code_set(&["AUTHS-E1001"]);
        let published = code_set(&["AUTHS-E1001", "AUTHS-E9999"]);
        let violations = find_drift(&registered, &published);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("AUTHS-E9999"),
            "the orphan page's code must be named: {}",
            violations[0]
        );
    }

    #[test]
    fn run_passes_when_every_code_has_a_page() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(
            tmp.path(),
            &["AUTHS-E1001", "AUTHS-E1002"],
            &["AUTHS-E1001", "AUTHS-E1002"],
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn run_fails_when_a_registered_code_has_no_page() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(
            tmp.path(),
            &["AUTHS-E1001", "AUTHS-E1002"],
            &["AUTHS-E1001"],
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn non_code_pages_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), &["AUTHS-E1001"], &["AUTHS-E1001"]);
        std::fs::write(tmp.path().join("docs/errors/index.md"), "# index\n").unwrap();
        assert!(
            run(tmp.path()).is_ok(),
            "index.md is not a per-code page and must not read as an orphan"
        );
    }
}
