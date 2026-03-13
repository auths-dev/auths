use std::collections::HashSet;
use std::path::Path;

// All DID/newtype rules are now propagated to crate configs (fn-70.3 complete).
// Keep this mechanism for any future rules that need staged rollout.
const DEFERRED_RULE_PREFIXES: &[&str] = &[];

pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    let workspace_toml = workspace_root.join("clippy.toml");
    let workspace_methods = extract_disallowed_paths(&workspace_toml, "disallowed-methods")?;
    let workspace_types = extract_disallowed_paths(&workspace_toml, "disallowed-types")?;

    let crate_clippy_files = find_crate_clippy_files(workspace_root)?;

    let mut has_errors = false;

    for crate_toml in &crate_clippy_files {
        let crate_methods = extract_disallowed_paths(crate_toml, "disallowed-methods")?;
        let crate_types = extract_disallowed_paths(crate_toml, "disallowed-types")?;

        let rel = crate_toml
            .strip_prefix(workspace_root)
            .unwrap_or(crate_toml);

        for method in &workspace_methods {
            if is_deferred(method) {
                continue;
            }
            if !crate_methods.contains(method) {
                eprintln!(
                    "DRIFT: {rel} missing disallowed-method: {method}",
                    rel = rel.display()
                );
                has_errors = true;
            }
        }

        if !crate_types.is_empty() || !workspace_types.is_empty() {
            for ty in &workspace_types {
                if is_deferred(ty) {
                    continue;
                }
                if !crate_types.is_empty() && !crate_types.contains(ty) {
                    eprintln!(
                        "DRIFT: {rel} missing disallowed-type: {ty}",
                        rel = rel.display()
                    );
                    has_errors = true;
                }
            }
        }
    }

    if has_errors {
        anyhow::bail!(
            "clippy.toml sync check failed. Crate-level clippy.toml files must contain \
             all workspace-root rules. See above for details."
        );
    }

    println!(
        "clippy.toml sync OK — {} crate-level files checked against workspace root",
        crate_clippy_files.len()
    );
    Ok(())
}

fn is_deferred(path: &str) -> bool {
    DEFERRED_RULE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn find_crate_clippy_files(workspace_root: &Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    let crates_dir = workspace_root.join("crates");
    if crates_dir.is_dir() {
        for entry in std::fs::read_dir(&crates_dir)? {
            let entry = entry?;
            let clippy_toml = entry.path().join("clippy.toml");
            if clippy_toml.is_file() {
                files.push(clippy_toml);
            }
        }
    }
    let packages_dir = workspace_root.join("packages");
    if packages_dir.is_dir() {
        for entry in std::fs::read_dir(&packages_dir)? {
            let entry = entry?;
            let clippy_toml = entry.path().join("clippy.toml");
            if clippy_toml.is_file() {
                files.push(clippy_toml);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn extract_disallowed_paths(toml_path: &Path, key: &str) -> anyhow::Result<HashSet<String>> {
    let content = std::fs::read_to_string(toml_path)?;
    let mut paths = HashSet::new();

    let in_target_section = find_array_section(&content, key);
    if let Some(section) = in_target_section {
        for line in section.lines() {
            if let Some(path) = extract_path_value(line) {
                paths.insert(path);
            }
        }
    }

    Ok(paths)
}

fn find_array_section<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key} = [");
    let start = content.find(&needle)?;
    let rest = &content[start..];
    let end = rest.find(']')?;
    Some(&rest[..=end])
}

fn extract_path_value(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    let path_key = "path = \"";
    let idx = trimmed.find(path_key)?;
    let after = &trimmed[idx + path_key.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_path_value() {
        let line = r#"  { path = "chrono::offset::Utc::now", reason = "inject ClockProvider" },"#;
        assert_eq!(
            extract_path_value(line),
            Some("chrono::offset::Utc::now".to_string())
        );
    }

    #[test]
    fn test_extract_path_value_comment_line() {
        assert_eq!(extract_path_value("  # === Workspace rules ==="), None);
    }

    #[test]
    fn test_extract_path_value_empty() {
        assert_eq!(extract_path_value(""), None);
    }

    #[test]
    fn test_is_deferred() {
        assert!(!is_deferred("auths_verifier::IdentityDID::new_unchecked"));
        assert!(!is_deferred("chrono::offset::Utc::now"));
        assert!(!is_deferred("std::fs::read"));
    }
}
