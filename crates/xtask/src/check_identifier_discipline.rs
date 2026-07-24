//! Identifier discipline enforcement: ban raw `strip_prefix` string manipulation
//! on domain identifiers (e.g. `strip_prefix("did:keri:")`, `strip_prefix("sha256:")`).
//!
//! Production code MUST use strongly-typed domain primitives (`auths_verifier::IdentityDID`
//! and `auths_crypto::Hash256`) rather than ad-hoc string slicing.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Maximum allowed legacy violations while PRD-strong-typing-identifiers refactor is underway.
/// This ratchet threshold MUST only decrease as legacy occurrences are refactored into IdentityDID.
const MAX_ALLOWED_VIOLATIONS: usize = 62;

/// Inline comment marker allowing explicit waivers (e.g. `// raw-strip-allow:`).
const ALLOW_MARKER: &str = "raw-strip-allow";

const BANNED_PATTERNS: &[(&str, &str)] = &[
    (
        "strip_prefix(\"did:keri:\")",
        "Use auths_verifier::IdentityDID instead of raw string stripping",
    ),
    (
        "strip_prefix(\"sha256:\")",
        "Use auths_crypto::Hash256::from_hex_prefixed instead of raw string stripping",
    ),
    (
        "strip_prefix(\"did:key:\")",
        "Use auths_verifier::CanonicalDid instead of raw string stripping",
    ),
];

const EXEMPT_PATHS: &[&str] = &[
    "crates/auths-verifier/src/types.rs",
    "crates/auths-crypto/src/hash256.rs",
    "crates/xtask/src/check_identifier_discipline.rs",
    "/tests/",
    "/testing/",
    "/fakes/",
    "/benches/",
    "/examples/",
];

struct Violation {
    file: PathBuf,
    line: usize,
    pattern: &'static str,
    suggestion: &'static str,
}

pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let mut violations = Vec::new();
    let mut files_checked = 0u32;

    for entry in WalkDir::new(workspace_root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                return !name.starts_with('.') && name != "target" && name != "node_modules";
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

        files_checked += 1;

        for (line_idx, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || line.contains(ALLOW_MARKER) {
                continue;
            }
            for (pattern, suggestion) in BANNED_PATTERNS {
                if line.contains(pattern) {
                    violations.push(Violation {
                        file: path.to_path_buf(),
                        line: line_idx + 1,
                        pattern,
                        suggestion,
                    });
                }
            }
        }
    }

    if violations.len() > MAX_ALLOWED_VIOLATIONS {
        println!(
            "identifier discipline check: {} violations found in {} files (exceeds ratchet limit of {})",
            violations.len(),
            files_checked,
            MAX_ALLOWED_VIOLATIONS,
        );
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!(
                "  {}:{} — BANNED: {} — {}",
                rel.display(),
                v.line,
                v.pattern,
                v.suggestion,
            );
        }
        anyhow::bail!(
            "{} raw string strip_prefix violation(s) found (exceeds ratchet limit of {}). New raw strip_prefix calls are strictly prohibited.",
            violations.len(),
            MAX_ALLOWED_VIOLATIONS,
        );
    }

    println!(
        "identifier discipline check: {} files scanned, {} legacy violations (within ratchet limit of {})",
        files_checked,
        violations.len(),
        MAX_ALLOWED_VIOLATIONS
    );

    Ok(())
}
