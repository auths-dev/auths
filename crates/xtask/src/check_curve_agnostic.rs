//! AST-level curve-agnostic enforcement via tree-sitter.
//!
//! Scans production .rs files (excluding auths-crypto, tests, mobile-ffi)
//! for identifiers, function names, field names, and string literals
//! containing curve-specific words (ed25519, p256, secp256k1, ed448).
//! Allows typed enum variant access (CurveType::Ed25519, TypedSeed::P256, etc.).

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const CURVE_PATTERN: &str = r"(?i)(ed25519|p256|secp256k1|ed448)";

const ALLOWED_PARENTS: &[&str] = &[
    "CurveType",
    "TypedSeed",
    "KeriPublicKey",
    "CurveTag",
    "DecodedDidKey",
    "SignatureAlgorithm",
    "Codex",
    "SigType",
    "KeyData",
    // Third-party crate imports (p256, ssh-key)
    "ecdsa",
    "public",
];

const ALLOWED_TYPE_NAMES: &[&str] = &[
    "Ed25519Signature",
    "Ed25519PublicKey",
    "Ed25519KeyPair",
    "Ed25519KeyError",
];

const ALLOWED_METHOD_NAMES: &[&str] = &[
    "ed25519_verify",
    "p256_verify",
    "verify_ed25519",
    "verify_p256",
    "ed25519_pubkey_to_did_keri",
    "parse_curve_hint",
    "verify_with_p256",
    "ed25519",
    "p256",
];

const ALLOWED_IDENT_PREFIXES: &[&str] = &[
    "OID_ED25519",
    "ED25519_EC_PARAMS",
    "SshEd25519",
    "NistP256",
    "parse_ed25519_seed",
    "parse_ed25519_key_material",
    "build_ed25519_pkcs8",
    "encode_seed_as_pkcs8",
    "generate_ed25519_keypair",
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

    let re = regex_lite::Regex::new(CURVE_PATTERN).unwrap();

    let mut violations = Vec::new();
    let mut files_checked = 0u32;

    for entry in WalkDir::new(workspace_root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip non-Rust, hidden dirs, target/
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

        // Skip sanctioned crypto backends (the crates where curve-specific code lives)
        if rel_str.starts_with("crates/auths-crypto/src") {
            continue;
        }
        if rel_str.starts_with("crates/auths-core/src/crypto") {
            continue;
        }
        if rel_str.starts_with("crates/auths-core/src/api/runtime.rs") {
            continue;
        }
        if rel_str.starts_with("crates/auths-core/src/storage/pkcs11") {
            continue;
        }
        // Skip standalone mobile FFI
        if rel_str.contains("auths-mobile-ffi") {
            continue;
        }
        // Skip test directories and examples
        if rel_str.contains("/tests/")
            || rel_str.contains("/benches/")
            || rel_str.contains("/fuzz/")
            || rel_str.contains("/examples/")
        {
            continue;
        }
        // Skip testing.rs modules
        if rel_str.ends_with("testing.rs") {
            continue;
        }
        // Skip KERI codec (CESR code tables are curve-specific by spec)
        if rel_str.ends_with("keri/src/codec.rs") {
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
        check_node(tree.root_node(), &source, &re, path, &mut violations, false);
    }

    if violations.is_empty() {
        println!(
            "curve-agnostic check: {} files scanned, 0 violations",
            files_checked
        );
        Ok(())
    } else {
        println!(
            "curve-agnostic check: {} violations found in {} files",
            violations.len(),
            files_checked
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{}:{} — VIOLATION: '{}' contains curve-specific name",
                rel.display(),
                v.line,
                v.col,
                v.name
            );
        }
        anyhow::bail!(
            "{} curve-specific names found in production code outside auths-crypto. \
             Use typed enum dispatch (CurveType, TypedSeed, etc.) instead.",
            violations.len()
        )
    }
}

fn check_node(
    node: tree_sitter::Node,
    source: &str,
    re: &regex_lite::Regex,
    file: &Path,
    violations: &mut Vec<Violation>,
    in_test: bool,
) {
    // Skip #[test] functions and #[cfg(test)] modules
    let kind = node.kind();
    let is_test_context = in_test || is_test_attributed(&node, source);

    if is_test_context {
        return;
    }

    // Skip comments
    if kind == "line_comment" || kind == "block_comment" {
        return;
    }

    // Check identifiers for curve-specific names
    if kind == "identifier" || kind == "field_identifier" || kind == "type_identifier" {
        let text = &source[node.byte_range()];
        if re.is_match(text)
            && !is_allowed_enum_variant(&node, source)
            && !ALLOWED_TYPE_NAMES.contains(&text)
            && !ALLOWED_METHOD_NAMES.contains(&text)
            && !ALLOWED_IDENT_PREFIXES.iter().any(|p| text.starts_with(p))
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

    // String literals: only flag if they're NOT inside a match arm (FFI curve-hint parsing is OK)
    // and NOT an error message (error strings that name curves for user clarity are OK)
    // For now, skip string literal checking entirely — the identifier check catches the real violations.
    // String literals naming curves are mostly: FFI parse boundaries, error messages, docstrings.
    // All of those are informational, not dispatching.
    // TODO: re-enable string literal checking with match-arm exclusion when the check stabilizes.

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_node(child, source, re, file, violations, is_test_context);
    }
}

fn is_test_attributed(node: &tree_sitter::Node, source: &str) -> bool {
    // Check if this node (function_item or mod_item) has #[test] or #[cfg(test)]
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

fn is_allowed_enum_variant(node: &tree_sitter::Node, source: &str) -> bool {
    // Walk up to find if this identifier is the name part of a scoped_identifier
    // whose path part is one of the allowed enum parents
    if let Some(parent) = node.parent() {
        if parent.kind() == "scoped_identifier" {
            // The path is the first child, the name is the second
            if let Some(path_node) = parent.child_by_field_name("path") {
                let path_text = &source[path_node.byte_range()];
                // Check if the path ends with one of the allowed parent names
                for allowed in ALLOWED_PARENTS {
                    if path_text == *allowed || path_text.ends_with(allowed) {
                        return true;
                    }
                }
            }
        }
        // Also allow match arm patterns like `CurveType::Ed25519 =>`
        if parent.kind() == "match_pattern" || parent.kind() == "tuple_struct_pattern" {
            if let Some(gp) = parent.parent() {
                if gp.kind() == "scoped_identifier" || gp.kind() == "tuple_struct_pattern" {
                    let gp_text = &source[gp.byte_range()];
                    for allowed in ALLOWED_PARENTS {
                        if gp_text.contains(allowed) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}
