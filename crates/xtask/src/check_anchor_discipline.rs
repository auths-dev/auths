//! Anchor discipline enforcement via tree-sitter.
//!
//! Scans production .rs files in SDK domains and CLI commands for direct
//! `store_attestation`, `store_org_member`, and `load_all_attestations` calls
//! that bypass the atomic write / enriched read infrastructure.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const BANNED_WRITE_METHODS: &[&str] = &["store_attestation", "store_org_member"];

const BANNED_WRITE_PATHS: &[&str] = &[
    "crates/auths-sdk/src/domains/",
    "crates/auths-cli/src/commands/",
];

const BANNED_READ_METHODS: &[&str] = &["load_all_attestations"];

const BANNED_READ_PATHS: &[&str] = &["crates/auths-cli/src/commands/"];

const EXEMPT_PATHS: &[&str] = &[
    "crates/auths-storage/src/",
    "crates/auths-id/src/storage/",
    "crates/auths-id/src/testing/",
    "crates/auths-id/src/attestation/enriched.rs",
    "/tests/",
    "/testing/",
    "/fakes/",
];

struct Violation {
    file: PathBuf,
    line: usize,
    col: usize,
    name: String,
}

pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser
        .set_language(&language.into())
        .expect("failed to set tree-sitter-rust language");

    let mut violations = Vec::new();
    let mut files_checked = 0u32;

    for entry in WalkDir::new(workspace_root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                return name != "target" && name != ".git" && name != "node_modules";
            }
            name.ends_with(".rs")
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }

        let rel = path.strip_prefix(workspace_root).unwrap_or(path);
        let rel_str = rel.to_string_lossy();

        if EXEMPT_PATHS.iter().any(|e| rel_str.contains(e)) {
            continue;
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };

        files_checked += 1;

        let is_write_path = BANNED_WRITE_PATHS.iter().any(|p| rel_str.starts_with(p));
        let is_read_path = BANNED_READ_PATHS.iter().any(|p| rel_str.starts_with(p));

        if is_write_path {
            check_for_banned(
                tree.root_node(),
                &source,
                path,
                BANNED_WRITE_METHODS,
                &mut violations,
                false,
            );
        }

        if is_read_path {
            check_for_banned(
                tree.root_node(),
                &source,
                path,
                BANNED_READ_METHODS,
                &mut violations,
                false,
            );
        }
    }

    if violations.is_empty() {
        println!(
            "anchor-discipline check: {} files scanned, 0 violations",
            files_checked
        );
        Ok(())
    } else {
        println!(
            "anchor-discipline check: {} violations found in {} files",
            violations.len(),
            files_checked
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{}:{} — VIOLATION: '{}' bypasses anchor discipline",
                rel.display(),
                v.line,
                v.col,
                v.name
            );
        }
        anyhow::bail!(
            "{} anchor-discipline violations found. \
             Use AtomicWriteBatch for writes or load_all_enriched for reads.",
            violations.len()
        )
    }
}

fn check_for_banned(
    node: tree_sitter::Node,
    source: &str,
    file: &Path,
    banned: &[&str],
    violations: &mut Vec<Violation>,
    in_test: bool,
) {
    let kind = node.kind();

    if in_test || is_test_attributed(&node, source) {
        return;
    }

    if kind == "identifier" || kind == "field_identifier" {
        let text = &source[node.byte_range()];
        if banned.contains(&text) {
            // Check if it's in a method call / function call context (not a definition)
            if let Some(parent) = node.parent() {
                let pk = parent.kind();
                if pk == "call_expression" || pk == "field_expression" || pk == "scoped_identifier"
                {
                    let start = node.start_position();
                    violations.push(Violation {
                        file: file.to_path_buf(),
                        line: start.row + 1,
                        col: start.column + 1,
                        name: text.to_string(),
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_for_banned(child, source, file, banned, violations, in_test);
    }
}

fn is_test_attributed(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute_item" {
            let text = &source[child.byte_range()];
            if text.contains("#[test]") || text.contains("#[cfg(test)]") {
                return true;
            }
        }
    }
    false
}
