//! Constant-time comparison enforcement via tree-sitter.
//!
//! Scans production .rs files for `==` comparisons where either side calls
//! `.as_bytes()` — a pattern that indicates non-constant-time comparison of
//! cryptographic material. Use `subtle::ConstantTimeEq::ct_eq()` instead.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const EXEMPT_PATHS: &[&str] = &[
    "crates/auths-crypto/src/",
    "/tests/",
    "/testing/",
    "/fakes/",
    "/benches/",
    "/examples/",
];

struct Violation {
    file: PathBuf,
    line: usize,
    col: usize,
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
        check_node(tree.root_node(), &source, path, &mut violations, false);
    }

    if violations.is_empty() {
        println!(
            "constant-time check: {} files scanned, 0 violations",
            files_checked
        );
        Ok(())
    } else {
        println!(
            "constant-time check: {} violations found in {} files",
            violations.len(),
            files_checked
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{}:{} — VIOLATION: non-constant-time == on .as_bytes()",
                rel.display(),
                v.line,
                v.col,
            );
        }
        anyhow::bail!(
            "{} non-constant-time byte comparisons found. \
             Use subtle::ConstantTimeEq::ct_eq() instead of ==.",
            violations.len()
        )
    }
}

fn check_node(
    node: tree_sitter::Node,
    source: &str,
    file: &Path,
    violations: &mut Vec<Violation>,
    in_test: bool,
) {
    let kind = node.kind();
    let is_test_context = in_test || is_test_attributed(&node, source);

    if is_test_context {
        return;
    }

    if kind == "binary_expression" {
        let op_text = node
            .child_by_field_name("operator")
            .map(|n| &source[n.byte_range()]);

        if op_text == Some("==") || op_text == Some("!=") {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");

            let left_has_as_bytes = left.is_some_and(|n| subtree_contains_as_bytes(n, source));
            let right_has_as_bytes = right.is_some_and(|n| subtree_contains_as_bytes(n, source));

            if left_has_as_bytes || right_has_as_bytes {
                let start = node.start_position();
                violations.push(Violation {
                    file: file.to_path_buf(),
                    line: start.row + 1,
                    col: start.column + 1,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_node(child, source, file, violations, is_test_context);
    }
}

fn subtree_contains_as_bytes(node: tree_sitter::Node, source: &str) -> bool {
    let kind = node.kind();

    if kind == "identifier" || kind == "field_identifier" {
        let text = &source[node.byte_range()];
        if text == "as_bytes" {
            return true;
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if subtree_contains_as_bytes(child, source) {
            return true;
        }
    }
    false
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
