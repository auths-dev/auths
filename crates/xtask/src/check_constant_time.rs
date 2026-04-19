//! Constant-time comparison enforcement via tree-sitter.
//!
//! Two invariants enforced here:
//! 1. **Byte-equality:** `==` / `!=` where either side calls `.as_bytes()` —
//!    indicates non-constant-time comparison of cryptographic material. Use
//!    `subtle::ConstantTimeEq::ct_eq()` instead.
//! 2. **Secret-marker discipline (fn-128.T5):** any type that implements the
//!    sealed `Secret` marker trait from `auths-crypto::secret` MUST NOT
//!    derive `PartialEq` or `Eq`. Equality on secret material must go
//!    through `subtle::ConstantTimeEq`. The scanner collects every
//!    `impl Secret for T` it sees, then re-scans for `struct T` / `enum T`
//!    declarations with forbidden derives.
//!
//! The `Secret` trait's super-trait bound on `ZeroizeOnDrop` catches the
//! second invariant (no zeroize → no `impl Secret`) at compile time. The
//! PartialEq/Eq prohibition is enforced here because Rust's trait system
//! cannot prohibit a derive on a type.

use std::collections::HashSet;
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
    kind: ViolationKind,
}

#[derive(Debug, Clone, Copy)]
enum ViolationKind {
    /// `==` / `!=` on a byte slice (`.as_bytes()` in scope).
    ByteEq,
    /// `#[derive(PartialEq)]` / `#[derive(Eq)]` on a Secret-implementing type.
    SecretPartialEq(&'static str),
}

pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser
        .set_language(&language.into())
        .expect("failed to set tree-sitter-rust language");

    let mut violations = Vec::new();
    let mut files_checked = 0u32;

    // First pass: collect every type T with `impl Secret for T {}` in the
    // workspace. Used by the second pass to flag PartialEq/Eq derives.
    let secret_types = collect_secret_types(workspace_root)?;

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
        check_secret_partialeq(
            tree.root_node(),
            &source,
            path,
            &secret_types,
            &mut violations,
        );
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
            let msg = match v.kind {
                ViolationKind::ByteEq => {
                    "non-constant-time == on .as_bytes(); use subtle::ConstantTimeEq::ct_eq()"
                        .to_string()
                }
                ViolationKind::SecretPartialEq(ty) => format!(
                    "derive(PartialEq/Eq) on Secret type `{ty}`; equality must go through subtle::ConstantTimeEq"
                ),
            };
            println!(
                "  {}:{}:{} — VIOLATION: {}",
                rel.display(),
                v.line,
                v.col,
                msg
            );
        }
        anyhow::bail!(
            "{} constant-time violations found. See messages above.",
            violations.len()
        )
    }
}

/// First pass: walk every source file and record every type T that has an
/// `impl Secret for T {}` (or `impl auths_crypto::Secret for T`) declaration.
fn collect_secret_types(workspace_root: &Path) -> anyhow::Result<HashSet<String>> {
    let mut set = HashSet::new();
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
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Cheap regex-free scan: find lines starting with `impl Secret for ` or
        // `impl auths_crypto::Secret for `. Capture the first identifier after.
        for line in source.lines() {
            let trimmed = line.trim_start();
            let after_impl = trimmed
                .strip_prefix("impl Secret for ")
                .or_else(|| trimmed.strip_prefix("impl auths_crypto::Secret for "))
                .or_else(|| trimmed.strip_prefix("impl crate::secret::Secret for "));
            if let Some(rest) = after_impl {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                // Strip any path prefix (e.g. `crate::provider::SecureSeed` → `SecureSeed`).
                let bare = name.rsplit("::").next().unwrap_or(&name).to_string();
                if !bare.is_empty() {
                    set.insert(bare);
                }
            }
        }
    }
    Ok(set)
}

/// Second pass: for every `struct T` / `enum T` declaration whose name is in
/// `secret_types`, flag any `#[derive(...)]` attribute that mentions
/// `PartialEq` or `Eq`.
fn check_secret_partialeq(
    node: tree_sitter::Node,
    source: &str,
    file: &Path,
    secret_types: &HashSet<String>,
    violations: &mut Vec<Violation>,
) {
    let kind = node.kind();
    if kind == "struct_item" || kind == "enum_item" {
        // Grab the type name.
        let name = node
            .child_by_field_name("name")
            .map(|n| source[n.byte_range()].to_string());
        if let Some(name) = name {
            if secret_types.contains(&name) {
                // Walk the attribute_items that precede the type declaration
                // (tree-sitter-rust places them as children of struct_item/enum_item).
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "attribute_item" {
                        let text = &source[child.byte_range()];
                        if text.contains("derive")
                            && (text.contains("PartialEq") || text.contains("Eq"))
                        {
                            let start = child.start_position();
                            // SAFETY: the trait name is captured by value into the Violation;
                            // we store a &'static str via intern by leaking a Box — simple
                            // and fine for the limited set of Secret types in the workspace.
                            let ty: &'static str = Box::leak(name.clone().into_boxed_str());
                            violations.push(Violation {
                                file: file.to_path_buf(),
                                line: start.row + 1,
                                col: start.column + 1,
                                kind: ViolationKind::SecretPartialEq(ty),
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_secret_partialeq(child, source, file, secret_types, violations);
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
                    kind: ViolationKind::ByteEq,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn parse_for_test(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("tree-sitter-rust language");
        parser.parse(source, None).expect("parse")
    }

    #[test]
    fn secret_partialeq_scanner_flags_violation() {
        // Simulated source with a Secret-implementing type that also derives PartialEq.
        let source = r#"
            #[derive(PartialEq, Eq)]
            pub struct BadSeed([u8; 32]);

            impl Secret for BadSeed {}
        "#;

        let tree = parse_for_test(source);
        let secrets: HashSet<String> = ["BadSeed".to_string()].into_iter().collect();
        let mut violations = Vec::new();
        let path = std::path::Path::new("bad.rs");
        check_secret_partialeq(tree.root_node(), source, path, &secrets, &mut violations);
        assert_eq!(violations.len(), 1, "expected exactly one violation");
        assert!(matches!(
            violations[0].kind,
            ViolationKind::SecretPartialEq("BadSeed")
        ));
    }

    #[test]
    fn secret_partialeq_scanner_ignores_non_secret_types() {
        let source = r#"
            #[derive(PartialEq, Eq)]
            pub struct SomeOtherType;
        "#;
        let tree = parse_for_test(source);
        let secrets: HashSet<String> = HashSet::new();
        let mut violations = Vec::new();
        check_secret_partialeq(
            tree.root_node(),
            source,
            std::path::Path::new("ok.rs"),
            &secrets,
            &mut violations,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn secret_partialeq_scanner_allows_secret_without_derive() {
        // A Secret type without PartialEq is legal.
        let source = r#"
            pub struct GoodSeed([u8; 32]);

            impl Secret for GoodSeed {}
        "#;
        let tree = parse_for_test(source);
        let secrets: HashSet<String> = ["GoodSeed".to_string()].into_iter().collect();
        let mut violations = Vec::new();
        check_secret_partialeq(
            tree.root_node(),
            source,
            std::path::Path::new("good.rs"),
            &secrets,
            &mut violations,
        );
        assert!(violations.is_empty());
    }
}
