use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use walkdir::WalkDir;

struct ErrorEntry {
    code: String,
    crate_name: String,
    type_name: String,
    variant: String,
    message: String,
    suggestion: Option<String>,
}

/// Scan `AuthsErrorInfo` impls across all crates, then generate (or check) the
/// CLI error registry and per-code markdown documentation.
///
/// Args:
/// * `workspace_root`: Path to the repository root.
/// * `check`: If `true`, fail instead of writing — used as a CI gate.
pub fn run(workspace_root: &Path, check: bool) -> Result<()> {
    println!("Scanning error codes...");
    let entries = scan_all_crates(workspace_root)?;
    validate_unique_codes(&entries)?;

    let mut stale: Vec<String> = Vec::new();

    // --- docs/errors/*.md ---
    let docs_dir = workspace_root.join("docs/errors");
    if !check {
        std::fs::create_dir_all(&docs_dir)?;
    }

    let expected_files: BTreeSet<String> =
        entries.iter().map(|e| format!("{}.md", e.code)).collect();

    for entry in &entries {
        let content = generate_doc(entry);
        let path = docs_dir.join(format!("{}.md", entry.code));
        let label = format!("docs/errors/{}.md", entry.code);
        check_or_write(&path, &content, check, &mut stale, &label)?;
    }

    if docs_dir.exists() {
        for dir_entry in std::fs::read_dir(&docs_dir)? {
            let dir_entry = dir_entry?;
            let name = dir_entry.file_name().to_string_lossy().to_string();
            if name.starts_with("AUTHS-E")
                && name.ends_with(".md")
                && !expected_files.contains(&name)
            {
                if check {
                    stale.push(format!("docs/errors/{name} (orphaned)"));
                } else {
                    std::fs::remove_file(dir_entry.path())?;
                    println!("  removed  docs/errors/{name}");
                }
            }
        }
    }

    // --- docs/errors/index.md ---
    let index_content = generate_error_index(&entries);
    let index_path = docs_dir.join("index.md");
    check_or_write(
        &index_path,
        &index_content,
        check,
        &mut stale,
        "docs/errors/index.md",
    )?;

    // --- mkdocs.yml nav entry ---
    let mkdocs_path = workspace_root.join("mkdocs.yml");
    update_mkdocs_nav(&mkdocs_path, &entries, check, &mut stale)?;

    // --- registry.rs ---
    let registry_content = generate_registry(&entries);
    let registry_path = workspace_root.join("crates/auths-cli/src/errors/registry.rs");
    check_or_write(
        &registry_path,
        &registry_content,
        check,
        &mut stale,
        "registry.rs",
    )?;

    if check && !stale.is_empty() {
        bail!(
            "Error docs are out of date — run `cargo xtask gen-error-docs` to regenerate:\n{}",
            stale
                .iter()
                .map(|s| format!("  - {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    println!("  total    {} error codes", entries.len());
    Ok(())
}

fn check_or_write(
    path: &Path,
    content: &str,
    check: bool,
    stale: &mut Vec<String>,
    label: &str,
) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing == content {
        // up to date
    } else if check {
        stale.push(label.to_string());
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("  updated  {label}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

fn scan_all_crates(workspace_root: &Path) -> Result<Vec<ErrorEntry>> {
    let crates_dir = workspace_root.join("crates");
    let mut all_entries: Vec<ErrorEntry> = Vec::new();

    for dir_entry in WalkDir::new(&crates_dir).into_iter().filter_map(|e| e.ok()) {
        let path = dir_entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let path_str = path.to_string_lossy();
        if path_str.contains("crates/xtask/") {
            continue;
        }

        if let Some(crate_name) = extract_crate_name(path, &crates_dir) {
            let entries = parse_file(path, &crate_name)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            all_entries.extend(entries);
        }
    }

    all_entries.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(all_entries)
}

fn extract_crate_name(path: &Path, crates_dir: &Path) -> Option<String> {
    let relative = path.strip_prefix(crates_dir).ok()?;
    let first = relative.components().next()?;
    Some(first.as_os_str().to_string_lossy().to_string())
}

// ---------------------------------------------------------------------------
// Per-file parsing
// ---------------------------------------------------------------------------

fn parse_file(path: &Path, crate_name: &str) -> Result<Vec<ErrorEntry>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let lines: Vec<&str> = content.lines().collect();

    let error_messages = parse_enum_error_attrs(&lines);
    let impls = parse_error_info_impls(&lines);

    let mut entries = Vec::new();
    for impl_info in &impls {
        for code_map in &impl_info.codes {
            let message = error_messages
                .get(&(impl_info.type_name.clone(), code_map.variant.clone()))
                .cloned()
                .unwrap_or_default();
            let suggestion = impl_info
                .suggestions
                .iter()
                .find(|s| s.variant == code_map.variant)
                .map(|s| s.text.clone());

            entries.push(ErrorEntry {
                code: code_map.code.clone(),
                crate_name: crate_name.to_string(),
                type_name: impl_info.type_name.clone(),
                variant: code_map.variant.clone(),
                message,
                suggestion,
            });
        }
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Phase 1: Parse enum definitions for #[error("...")] attributes
// ---------------------------------------------------------------------------

fn parse_enum_error_attrs(lines: &[&str]) -> BTreeMap<(String, String), String> {
    let mut result = BTreeMap::new();
    let mut current_enum: Option<String> = None;
    let mut brace_depth: i32 = 0;
    let mut pending_message: Option<String> = None;
    let mut in_multiline_error = false;
    let mut multiline_buf = String::new();

    for line in lines {
        let trimmed = line.trim();

        if current_enum.is_none() {
            if let Some(name) = extract_enum_name(trimmed) {
                current_enum = Some(name);
                brace_depth = count_char(trimmed, '{') as i32 - count_char(trimmed, '}') as i32;
                continue;
            }
            continue;
        }

        // Track brace depth
        if !in_multiline_error {
            brace_depth += count_char(trimmed, '{') as i32;
            brace_depth -= count_char(trimmed, '}') as i32;
        }

        if brace_depth <= 0 {
            current_enum = None;
            pending_message = None;
            in_multiline_error = false;
            multiline_buf.clear();
            continue;
        }

        // Handle multi-line #[error(...)]
        if in_multiline_error {
            multiline_buf.push(' ');
            multiline_buf.push_str(trimmed);
            if trimmed.contains(")]") {
                in_multiline_error = false;
                if let Some(msg) = extract_error_message(&multiline_buf) {
                    pending_message = Some(msg);
                }
                multiline_buf.clear();
            }
            continue;
        }

        if trimmed.starts_with("#[error(") {
            if trimmed.contains(")]") {
                if let Some(msg) = extract_error_message(trimmed) {
                    pending_message = Some(msg);
                }
            } else {
                in_multiline_error = true;
                multiline_buf = trimmed.to_string();
            }
            continue;
        }

        // Skip other attributes and comments
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }

        // Variant name line
        if let Some(variant) = extract_variant_name(trimmed) {
            if let Some(ref enum_name) = current_enum {
                if let Some(msg) = pending_message.take() {
                    result.insert((enum_name.clone(), variant), msg);
                }
            }
        }
    }

    result
}

fn extract_enum_name(line: &str) -> Option<String> {
    let after = line
        .strip_prefix("pub enum ")
        .or_else(|| line.strip_prefix("pub(crate) enum "))?;

    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    if name.is_empty() || !line.contains('{') {
        return None;
    }

    Some(name)
}

fn extract_error_message(attr: &str) -> Option<String> {
    if attr.contains("transparent") {
        return None;
    }
    let start = attr.find('"')? + 1;
    let rest = &attr[start..];
    let end = rest.rfind('"')?;
    Some(rest[..end].to_string())
}

fn extract_variant_name(line: &str) -> Option<String> {
    let first = line.chars().next()?;
    if !first.is_uppercase() {
        return None;
    }
    let name: String = line
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn count_char(s: &str, ch: char) -> usize {
    s.chars().filter(|c| *c == ch).count()
}

// ---------------------------------------------------------------------------
// Phase 2: Parse `impl AuthsErrorInfo for` blocks
// ---------------------------------------------------------------------------

struct ImplInfo {
    type_name: String,
    codes: Vec<CodeMapping>,
    suggestions: Vec<SuggestionMapping>,
}

struct CodeMapping {
    variant: String,
    code: String,
}

struct SuggestionMapping {
    variant: String,
    text: String,
}

fn parse_error_info_impls(lines: &[&str]) -> Vec<ImplInfo> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        if trimmed.contains("AuthsErrorInfo for ") && trimmed.contains("impl") {
            if let Some(type_name) = extract_impl_type_name(trimmed) {
                let impl_end = find_block_end(lines, i);
                let impl_lines = &lines[i..impl_end];

                let codes = parse_error_code_method(impl_lines);
                let suggestions = parse_suggestion_method(impl_lines);

                if !codes.is_empty() {
                    results.push(ImplInfo {
                        type_name,
                        codes,
                        suggestions,
                    });
                }

                i = impl_end;
                continue;
            }
        }
        i += 1;
    }
    results
}

fn extract_impl_type_name(line: &str) -> Option<String> {
    let idx = line.find("AuthsErrorInfo for ")?;
    let after = &line[idx + "AuthsErrorInfo for ".len()..];
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn find_block_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
        }
    }
    lines.len()
}

fn parse_error_code_method(impl_lines: &[&str]) -> Vec<CodeMapping> {
    let mut results = Vec::new();
    let mut in_method = false;
    let mut brace_depth = 0i32;

    for line in impl_lines {
        let trimmed = line.trim();

        if trimmed.contains("fn error_code") {
            in_method = true;
            brace_depth = 0;
        }

        if in_method {
            brace_depth += count_char(trimmed, '{') as i32;
            brace_depth -= count_char(trimmed, '}') as i32;

            if trimmed.contains("Self::") && trimmed.contains("\"AUTHS-E") {
                if let Some(mapping) = parse_code_arm(trimmed) {
                    results.push(mapping);
                }
            }

            if brace_depth <= 0 && !results.is_empty()
                || trimmed.starts_with("fn ") && in_method && !trimmed.contains("fn error_code")
            {
                break;
            }
        }
    }
    results
}

fn parse_code_arm(line: &str) -> Option<CodeMapping> {
    let self_idx = line.find("Self::")?;
    let after_self = &line[self_idx + 6..];
    let variant: String = after_self
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    let code_start = line.find("\"AUTHS-E")? + 1;
    let code_rest = &line[code_start..];
    let code_end = code_rest.find('"')?;
    let code = code_rest[..code_end].to_string();

    if variant.is_empty() || !code.starts_with("AUTHS-E") {
        return None;
    }

    Some(CodeMapping { variant, code })
}

fn parse_suggestion_method(impl_lines: &[&str]) -> Vec<SuggestionMapping> {
    let mut results = Vec::new();
    let mut in_method = false;
    let mut brace_depth = 0i32;

    for line in impl_lines {
        let trimmed = line.trim();

        if trimmed.contains("fn suggestion") {
            in_method = true;
            brace_depth = 0;
        }

        if in_method {
            brace_depth += count_char(trimmed, '{') as i32;
            brace_depth -= count_char(trimmed, '}') as i32;

            if trimmed.contains("Self::") && trimmed.contains("Some(\"") {
                if let Some(mapping) = parse_suggestion_arm(trimmed) {
                    results.push(mapping);
                }
            }

            if brace_depth <= 0 && !results.is_empty()
                || trimmed.starts_with("fn ") && in_method && !trimmed.contains("fn suggestion")
            {
                break;
            }
        }
    }
    results
}

fn parse_suggestion_arm(line: &str) -> Option<SuggestionMapping> {
    let self_idx = line.find("Self::")?;
    let after_self = &line[self_idx + 6..];
    let variant: String = after_self
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    let some_idx = line.find("Some(\"")?;
    let text_start = some_idx + 6;
    let text_rest = &line[text_start..];
    let text_end = text_rest.rfind("\")")?;
    let text = text_rest[..text_end].to_string();

    if variant.is_empty() {
        return None;
    }

    Some(SuggestionMapping { variant, text })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_unique_codes(entries: &[ErrorEntry]) -> Result<()> {
    let mut seen: BTreeMap<&str, &ErrorEntry> = BTreeMap::new();
    for entry in entries {
        if let Some(existing) = seen.get(entry.code.as_str()) {
            bail!(
                "Duplicate error code {}: {}::{} and {}::{}",
                entry.code,
                existing.crate_name,
                existing.type_name,
                entry.crate_name,
                entry.type_name,
            );
        }
        seen.insert(&entry.code, entry);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generation: docs/errors/*.md
// ---------------------------------------------------------------------------

fn generate_doc(entry: &ErrorEntry) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n", entry.code));
    out.push('\n');
    out.push_str(&format!("**Crate:** `{}`  \n", entry.crate_name));
    out.push_str(&format!(
        "**Type:** `{}::{}`\n",
        entry.type_name, entry.variant
    ));
    out.push('\n');
    out.push_str("## Message\n");
    out.push('\n');
    if entry.message.is_empty() {
        out.push_str("_(transparent — see inner error)_\n");
    } else {
        out.push_str(&format!("{}\n", entry.message));
    }
    if let Some(ref suggestion) = entry.suggestion {
        out.push('\n');
        out.push_str("## Suggestion\n");
        out.push('\n');
        out.push_str(&format!("{}\n", suggestion));
    }
    out
}

// ---------------------------------------------------------------------------
// Generation: docs/errors/index.md
// ---------------------------------------------------------------------------

fn generate_error_index(entries: &[ErrorEntry]) -> String {
    let mut out = String::from("<!-- generated by cargo xtask gen-error-docs — do not edit -->\n");
    out.push_str("# Error Code Reference\n\n");
    out.push_str("All error codes emitted by the Auths CLI and libraries. ");
    out.push_str("Run `auths error <CODE>` to look up any code from the terminal.\n\n");
    out.push_str("| Code | Crate | Type | Message |\n");
    out.push_str("|------|-------|------|---------|\n");

    for entry in entries {
        let msg = if entry.message.is_empty() {
            "_(transparent)_".to_string()
        } else {
            entry.message.replace('|', "\\|")
        };
        out.push_str(&format!(
            "| [{}]({}.md) | `{}` | `{}::{}` | {} |\n",
            entry.code, entry.code, entry.crate_name, entry.type_name, entry.variant, msg
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// Generation: mkdocs.yml nav entry
// ---------------------------------------------------------------------------

fn update_mkdocs_nav(
    mkdocs_path: &Path,
    entries: &[ErrorEntry],
    check: bool,
    stale: &mut Vec<String>,
) -> Result<()> {
    let content = std::fs::read_to_string(mkdocs_path)
        .with_context(|| format!("cannot read {}", mkdocs_path.display()))?;

    let marker_start = "  # --- ERROR CODES (auto-generated) ---";
    let marker_end = "  # --- END ERROR CODES ---";

    let mut nav_block = String::new();
    nav_block.push_str(marker_start);
    nav_block.push('\n');
    nav_block.push_str("  - Error Codes:\n");
    nav_block.push_str("      - errors/index.md\n");

    let mut prev_crate = String::new();
    for entry in entries {
        if entry.crate_name != prev_crate {
            nav_block.push_str(&format!("      - {}:\n", entry.crate_name));
            prev_crate.clone_from(&entry.crate_name);
        }
        nav_block.push_str(&format!(
            "          - \"{}\": errors/{}.md\n",
            entry.code, entry.code
        ));
    }

    nav_block.push_str(marker_end);

    if let Some(start_idx) = content.find(marker_start) {
        if let Some(end_idx) = content.find(marker_end) {
            let end_of_marker = end_idx + marker_end.len();
            let new_content = format!(
                "{}{}{}",
                &content[..start_idx],
                nav_block,
                &content[end_of_marker..]
            );
            if new_content != content {
                if check {
                    stale.push("mkdocs.yml (error codes nav)".to_string());
                } else {
                    std::fs::write(mkdocs_path, &new_content)
                        .with_context(|| "failed to write mkdocs.yml")?;
                    println!("  updated  mkdocs.yml");
                }
            }
        }
    } else {
        // Markers not yet present — insert before the last nav section
        let insert_content = format!("\n{}\n", nav_block);
        if let Some(contributing_idx) = content.find("  - Contributing:") {
            let new_content = format!(
                "{}{}{}",
                &content[..contributing_idx],
                insert_content,
                &content[contributing_idx..]
            );
            if check {
                stale.push("mkdocs.yml (error codes nav — missing markers)".to_string());
            } else {
                std::fs::write(mkdocs_path, &new_content)
                    .with_context(|| "failed to write mkdocs.yml")?;
                println!("  updated  mkdocs.yml (inserted error codes nav)");
            }
        } else {
            bail!("Cannot find insertion point in mkdocs.yml — add markers manually:\n  {marker_start}\n  {marker_end}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Generation: registry.rs
// ---------------------------------------------------------------------------

fn generate_registry(entries: &[ErrorEntry]) -> String {
    let mut out = String::new();

    out.push_str("//! Error code registry — **generated** by `cargo xtask gen-error-docs`.\n");
    out.push_str("//!\n");
    out.push_str(
        "//! Do not edit manually. Re-run the generator after changing any `AuthsErrorInfo` impl:\n",
    );
    out.push_str("//! ```sh\n");
    out.push_str("//! cargo xtask gen-error-docs\n");
    out.push_str("//! ```\n");
    out.push_str("//!\n");
    out.push_str("//! ## Range Allocation\n");
    out.push_str("//!\n");
    out.push_str("//! | Range   | Crate            | Layer |\n");
    out.push_str("//! |---------|------------------|-------|\n");
    out.push_str("//! | E0xxx   | Reserved/meta    | -     |\n");
    out.push_str("//! | E1xxx   | auths-crypto     | 0     |\n");
    out.push_str("//! | E2xxx   | auths-verifier   | 1     |\n");
    out.push_str("//! | E3xxx   | auths-core       | 2     |\n");
    out.push_str("//! | E4xxx   | auths-id         | 3     |\n");
    out.push_str("//! | E5xxx   | auths-sdk        | 3-4   |\n");
    out.push_str("//! | E6xxx   | auths-cli        | 6     |\n");
    out.push('\n');

    // --- explain() ---
    out.push_str(
        "/// Returns the explanation markdown for a given error code, or `None` if unknown.\n",
    );
    out.push_str("///\n");
    out.push_str("/// Args:\n");
    out.push_str("/// * `code`: An error code string like `\"AUTHS-E3001\"`.\n");
    out.push_str("pub fn explain(code: &str) -> Option<&'static str> {\n");
    out.push_str("    match code {\n");

    let mut prev_group = String::new();
    for entry in entries {
        let group = format!("{} ({})", entry.crate_name, entry.type_name);
        if group != prev_group {
            if !prev_group.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("        // --- {group} ---\n"));
            prev_group = group;
        }
        let doc = generate_doc(entry)
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        out.push_str(&format!(
            "        \"{}\" => Some(\"{}\"),\n",
            entry.code, doc
        ));
    }

    out.push_str("\n        _ => None,\n");
    out.push_str("    }\n");
    out.push_str("}\n");
    out.push('\n');

    // --- all_codes() ---
    out.push_str("/// Returns a sorted slice of all registered error codes.\n");
    out.push_str("pub fn all_codes() -> &'static [&'static str] {\n");
    out.push_str("    static CODES: &[&str] = &[\n");
    for entry in entries {
        out.push_str(&format!("        \"{}\",\n", entry.code));
    }
    out.push_str("    ];\n");
    out.push_str("    CODES\n");
    out.push_str("}\n");
    out.push('\n');

    // --- Tests ---
    out.push_str("#[cfg(test)]\n");
    out.push_str("mod tests {\n");
    out.push_str("    use super::*;\n");
    out.push('\n');

    out.push_str("    #[test]\n");
    out.push_str("    fn explain_returns_content_for_known_code() {\n");
    if let Some(first) = entries.first() {
        out.push_str(&format!(
            "        assert!(explain(\"{}\").is_some());\n",
            first.code
        ));
    }
    out.push_str("    }\n");
    out.push('\n');

    out.push_str("    #[test]\n");
    out.push_str("    fn explain_returns_none_for_unknown_code() {\n");
    out.push_str("        assert!(explain(\"AUTHS-E9999\").is_none());\n");
    out.push_str("    }\n");
    out.push('\n');

    out.push_str("    #[test]\n");
    out.push_str("    fn all_codes_is_sorted() {\n");
    out.push_str("        let codes = all_codes();\n");
    out.push_str("        assert!(!codes.is_empty());\n");
    out.push_str("        for window in codes.windows(2) {\n");
    out.push_str("            assert!(\n");
    out.push_str("                window[0] < window[1],\n");
    out.push_str("                \"codes not sorted: {} >= {}\",\n");
    out.push_str("                window[0],\n");
    out.push_str("                window[1]\n");
    out.push_str("            );\n");
    out.push_str("        }\n");
    out.push_str("    }\n");
    out.push('\n');

    out.push_str("    #[test]\n");
    out.push_str("    fn all_codes_count_matches_registry() {\n");
    out.push_str(&format!(
        "        assert_eq!(all_codes().len(), {});\n",
        entries.len()
    ));
    out.push_str("    }\n");

    out.push_str("}\n");

    out
}
