//! RT-002 verify-path completeness enforcement via tree-sitter.
//!
//! The stateless/embedded verify path must AUTHENTICATE a KEL — verify each
//! event's signature against the controlling key-state via `validate_signed_kel`
//! — not merely replay it structurally (`validate_kel*` / `replay_kel`, which
//! check SAID + sequence + chain + commitment but never the signatures). A
//! structural-only replay on an untrusted-input verify path is exactly the
//! RT-002 forge: a hand-crafted, unsigned KEL replays to an attacker-chosen
//! key-state and verifies.
//!
//! This lint bans the structural-only replays in the verifier + CLI-verify
//! surfaces so a NEW untrusted-input entrypoint cannot silently reintroduce the
//! class. A site that legitimately replays an already-authenticated or
//! trusted-local KEL must carry an explicit `// rt-002-allow: <reason>`
//! annotation (on the call line or a preceding comment line) documenting why
//! structural replay is sound there — turning every exception into a reviewed,
//! grep-able decision.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Structural-only KEL replays (and the trust assertion that unlocks them) — must
/// not be reached from an untrusted-input verify path without an `rt-002-allow:`
/// justification.
///
/// Post-#263, the bare `validate_kel*` replays are `pub(crate)` in auths-keri, so a
/// verify-path crate can only structurally replay by minting a
/// `TrustedKel::from_trusted_source(..)` — that explicit trust assertion is now the
/// primary thing to gate here. The old `validate_kel*` names are kept for defence in
/// depth (they can no longer be called cross-crate, but banning them is harmless).
const BANNED_METHODS: &[&str] = &[
    "from_trusted_source",
    "validate_kel",
    "validate_kel_with_lookup",
    "validate_kel_with_receipts",
    "replay_kel",
];

/// Verify-path surfaces where an untrusted KEL could be replayed.
const BANNED_PATHS: &[&str] = &[
    "crates/auths-verifier/src/",
    "crates/auths-cli/src/commands/verify_commit.rs",
];

const EXEMPT_PATHS: &[&str] = &["/tests/", "/testing/", "/fakes/"];

/// The inline marker that grandfathers a reviewed structural-replay site.
const ALLOW_MARKER: &str = "rt-002-allow";

struct Violation {
    file: PathBuf,
    line: usize,
    col: usize,
    name: String,
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

        if !BANNED_PATHS.iter().any(|p| rel_str.starts_with(p)) {
            continue;
        }
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
        let lines: Vec<&str> = source.lines().collect();
        check(tree.root_node(), &source, &lines, path, &mut violations);
    }

    if violations.is_empty() {
        println!("verify-path-completeness check: {files_checked} files scanned, 0 violations");
        Ok(())
    } else {
        println!(
            "verify-path-completeness check: {} violation(s) in {} files",
            violations.len(),
            files_checked
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{}:{} — '{}' is a STRUCTURAL-only KEL replay on a verify path (RT-002). \
                 Use `validate_signed_kel`, or add `// rt-002-allow: <why structural is sound here>`.",
                rel.display(),
                v.line,
                v.col,
                v.name
            );
        }
        anyhow::bail!(
            "{} verify-path-completeness violation(s): structural KEL replay reachable from an \
             untrusted-input verify path. Authenticate via validate_signed_kel or annotate with \
             rt-002-allow.",
            violations.len()
        )
    }
}

fn check(
    node: tree_sitter::Node,
    source: &str,
    lines: &[&str],
    file: &Path,
    violations: &mut Vec<Violation>,
) {
    let kind = node.kind();
    if kind == "identifier" || kind == "field_identifier" {
        let text = &source[node.byte_range()];
        if BANNED_METHODS.contains(&text) {
            if let Some(parent) = node.parent() {
                let pk = parent.kind();
                if pk == "call_expression" || pk == "field_expression" || pk == "scoped_identifier"
                {
                    let start = node.start_position();
                    if !line_allowed(lines, start.row) {
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
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check(child, source, lines, file, violations);
    }
}

/// True if the call's line or one of the two preceding lines carries the
/// `rt-002-allow` justification marker (`row` is 0-based).
fn line_allowed(lines: &[&str], row: usize) -> bool {
    let lo = row.saturating_sub(2);
    (lo..=row).any(|i| lines.get(i).is_some_and(|l| l.contains(ALLOW_MARKER)))
}
