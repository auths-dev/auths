//! RFC 6979 deterministic-ECDSA enforcement via tree-sitter.
//!
//! Bans any call to a randomized-ECDSA API in production code. The workspace
//! is RFC 6979 deterministic today (scout audit confirmed zero violations
//! at the time of writing); this scanner freezes that invariant.
//!
//! # What gets flagged
//!
//! Any method call on an identifier whose name matches one of these (case-
//! sensitive, exact method-name match):
//!
//! | Method                         | Why banned                                     |
//! |--------------------------------|------------------------------------------------|
//! | `sign_with_rng`                | ECDSA with caller-supplied RNG — non-RFC 6979. |
//! | `sign_prehash_with_rng`        | Same for pre-hashed messages.                  |
//! | `sign_digest_with_rng`         | Same for digest-typed messages.                |
//! | `try_sign_with_rng`            | Fallible variant; same hazard.                 |
//! | `sign_digest`                  | Pre-hash digest-sign — caller controls hash; easy to misuse. |
//! | `sign_prehash_raw`             | Raw prehash signer — skips RFC 6979 derivation.|
//!
//! # Exemptions
//!
//! - `crates/auths-crypto/src/` — sanctioned provider boundary (like the
//!   constant-time scanner's exemption).
//! - `/tests/`, `/testing/`, `/fakes/`, `/benches/`, `/examples/` — test scope.
//!
//! # Rationale
//!
//! RFC 6979 non-compliance is a class-breaking bug (Sony PS3; early Bitcoin
//! wallet bugs; ANSSI 2012 advisory). The sign-with-RNG APIs on
//! `p256::ecdsa::SigningKey` exist for cases where the caller has a better
//! entropy source (fault-injection defence) — out of scope for this
//! workspace. Ban them preventatively; lift the ban with an explicit
//! `#[allow(clippy::disallowed_methods)]` + `INVARIANT:` comment if ever
//! needed.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const BANNED_METHODS: &[&str] = &[
    "sign_with_rng",
    "sign_prehash_with_rng",
    "sign_digest_with_rng",
    "try_sign_with_rng",
    "sign_digest",
    "sign_prehash_raw",
];

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
    method: String,
}

pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
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
        check_node(tree.root_node(), &source, path, &mut violations);
    }

    if violations.is_empty() {
        println!(
            "rfc6979 check: {} files scanned, 0 violations",
            files_checked
        );
        Ok(())
    } else {
        println!(
            "rfc6979 check: {} violations found in {} files",
            violations.len(),
            files_checked,
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{}:{} — BANNED: {}() — ECDSA must be RFC 6979 deterministic",
                rel.display(),
                v.line,
                v.col,
                v.method,
            );
        }
        anyhow::bail!(
            "{} banned randomized-ECDSA call(s) found. See messages above.",
            violations.len()
        )
    }
}

fn check_node(node: tree_sitter::Node, source: &str, file: &Path, violations: &mut Vec<Violation>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "field_expression" {
                if let Some(name_node) = func.child_by_field_name("field") {
                    let name = &source[name_node.byte_range()];
                    if BANNED_METHODS.contains(&name) {
                        let start = node.start_position();
                        violations.push(Violation {
                            file: file.to_path_buf(),
                            line: start.row + 1,
                            col: start.column + 1,
                            method: name.to_string(),
                        });
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_node(child, source, file, violations);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_for_test(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("tree-sitter-rust");
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn flags_sign_with_rng() {
        let source = r#"
            fn bad_sign() {
                let sig = signing_key.sign_with_rng(&mut rng, message);
            }
        "#;
        let tree = parse_for_test(source);
        let mut violations = Vec::new();
        check_node(
            tree.root_node(),
            source,
            Path::new("bad.rs"),
            &mut violations,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].method, "sign_with_rng");
    }

    #[test]
    fn ignores_deterministic_sign() {
        let source = r#"
            fn good_sign() {
                let sig: Signature = signing_key.sign(message);
            }
        "#;
        let tree = parse_for_test(source);
        let mut violations = Vec::new();
        check_node(
            tree.root_node(),
            source,
            Path::new("good.rs"),
            &mut violations,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn flags_all_banned_methods() {
        for method in BANNED_METHODS {
            let source = format!("fn f() {{ x.{}(a, b); }}", method);
            let tree = parse_for_test(&source);
            let mut violations = Vec::new();
            check_node(
                tree.root_node(),
                &source,
                Path::new("f.rs"),
                &mut violations,
            );
            assert_eq!(violations.len(), 1, "method `{}` should be flagged", method);
        }
    }
}
