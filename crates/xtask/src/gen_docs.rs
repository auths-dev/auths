use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// A CLI command whose flags we want to auto-document.
struct Cmd {
    /// Args to pass after `auths` (not including `--help`).
    args: &'static [&'static str],
    /// The marker name used in `<!-- BEGIN GENERATED: <marker> -->` comments.
    marker: &'static str,
    /// Doc file path relative to workspace root.
    doc_file: &'static str,
}

const COMMANDS: &[Cmd] = &[
    // --- Primary ---
    Cmd {
        args: &["init"],
        marker: "auths init",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["verify"],
        marker: "auths verify",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["status"],
        marker: "auths status",
        doc_file: "docs/cli/commands/primary.md",
    },
    // --- device ---
    Cmd {
        args: &["device", "link"],
        marker: "auths device link",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["device", "revoke"],
        marker: "auths device revoke",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["device", "extend"],
        marker: "auths device extend",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // --- id ---
    Cmd {
        args: &["id", "init-did"],
        marker: "auths id init-did",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["id", "rotate"],
        marker: "auths id rotate",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // --- key ---
    Cmd {
        args: &["key", "import"],
        marker: "auths key import",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["key", "export"],
        marker: "auths key export",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["key", "delete"],
        marker: "auths key delete",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // --- policy ---
    Cmd {
        args: &["policy", "explain"],
        marker: "auths policy explain",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["policy", "test"],
        marker: "auths policy test",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["policy", "diff"],
        marker: "auths policy diff",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // --- emergency ---
    Cmd {
        args: &["emergency", "revoke-device"],
        marker: "auths emergency revoke-device",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["emergency", "rotate-now"],
        marker: "auths emergency rotate-now",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["emergency", "freeze"],
        marker: "auths emergency freeze",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["emergency", "report"],
        marker: "auths emergency report",
        doc_file: "docs/cli/commands/advanced.md",
    },
];

/// Build the `auths` binary then regenerate all flag tables in the doc files.
///
/// Args:
/// * `workspace_root`: Path to the repository root.
/// * `check`: If `true`, fail instead of writing — used as a CI gate.
pub fn run(workspace_root: &Path, check: bool) -> Result<()> {
    // Build the binary (incremental — fast if nothing changed).
    println!("Building auths-cli...");
    let status = Command::new("cargo")
        .args(["build", "--package", "auths-cli"])
        .current_dir(workspace_root)
        .status()
        .context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build --package auths-cli failed");
    }

    let binary = workspace_root.join("target/debug/auths");
    let mut stale: Vec<&str> = Vec::new();

    for cmd in COMMANDS {
        let table = generate_table(&binary, cmd.args)
            .with_context(|| format!("failed to generate table for `{}`", cmd.marker))?;

        let doc_path = workspace_root.join(cmd.doc_file);
        let original = std::fs::read_to_string(&doc_path)
            .with_context(|| format!("failed to read {}", doc_path.display()))?;

        let updated = splice(&original, cmd.marker, &table).with_context(|| {
            format!("marker not found for `{}` in {}", cmd.marker, cmd.doc_file)
        })?;

        if updated != original {
            if check {
                stale.push(cmd.marker);
            } else {
                std::fs::write(&doc_path, &updated)
                    .with_context(|| format!("failed to write {}", doc_path.display()))?;
                println!("  updated  {}", cmd.marker);
            }
        } else {
            println!("  ok       {}", cmd.marker);
        }
    }

    if check && !stale.is_empty() {
        bail!(
            "CLI docs are out of date — run `cargo xtask gen-docs` to regenerate:\n{}",
            stale
                .iter()
                .map(|m| format!("  - {m}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    Ok(())
}

/// Run `auths <args> --help` and render a markdown flag table.
fn generate_table(binary: &Path, args: &[&str]) -> Result<String> {
    let mut full_args: Vec<&str> = args.to_vec();
    full_args.push("--help");

    let out = Command::new(binary)
        .args(&full_args)
        .output()
        .with_context(|| format!("failed to run auths {:?}", args))?;

    // clap writes --help to stdout; some versions use stderr on error.
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);

    parse_help_to_table(&text)
}

/// Parse clap's `--help` output into a markdown flag table.
///
/// Handles both `Options:` and `Arguments:` sections. Skips `-h/--help` and
/// `-V/--version`. Returns a table string ending with a newline.
fn parse_help_to_table(help: &str) -> Result<String> {
    let mut in_section = false;
    let mut rows: Vec<(String, String, String)> = Vec::new(); // (flag, default, desc)

    for line in help.lines() {
        let trimmed = line.trim_start();

        // Enter Options or Arguments section.
        if trimmed == "Options:" || trimmed == "Arguments:" {
            in_section = true;
            continue;
        }
        // Leave section on any non-indented non-empty line (next section header).
        if in_section && !line.is_empty() && !line.starts_with(' ') {
            in_section = false;
        }
        if !in_section || !trimmed.starts_with('-') && !trimmed.starts_with('<') {
            continue;
        }
        // Skip internal flags.
        if trimmed.contains("--help") || trimmed.contains("--version") {
            continue;
        }

        if let Some((flag_str, desc_str)) = split_flag_line(trimmed) {
            let (desc, default) = extract_default(&desc_str);
            rows.push((flag_str, default, desc));
        }
    }

    if rows.is_empty() {
        return Ok("_No options._\n".to_string());
    }

    let mut table = String::new();
    table.push_str("| Flag | Default | Description |\n");
    table.push_str("|------|---------|-------------|\n");
    for (flag, default, desc) in rows {
        let d = if default.is_empty() {
            "—".to_string()
        } else {
            format!("`{default}`")
        };
        // Escape pipe characters inside cells.
        let desc = desc.replace('|', "\\|");
        table.push_str(&format!("| `{flag}` | {d} | {desc} |\n"));
    }
    Ok(table)
}

/// Split a clap help line at the first run of 2+ spaces.
/// Returns `(flag_part, description_part)`.
fn split_flag_line(trimmed: &str) -> Option<(String, String)> {
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b' ' && bytes[i + 1] == b' ' {
            let flag = trimmed[..i].trim().to_string();
            let desc = trimmed[i..].trim().to_string();
            if !flag.is_empty() {
                return Some((flag, desc));
            }
        }
        i += 1;
    }
    if !trimmed.is_empty() {
        Some((trimmed.trim().to_string(), String::new()))
    } else {
        None
    }
}

/// Strip `[default: x]` and `[possible values: ...]` annotations from a
/// description string. Returns `(clean_description, default_value)`.
fn extract_default(desc: &str) -> (String, String) {
    let mut s = desc.to_string();
    let mut default = String::new();

    if let Some(start) = s.find("[default: ") {
        if let Some(end) = s[start..].find(']') {
            default = s[start + 10..start + end].to_string();
            s = format!("{}{}", &s[..start], &s[start + end + 1..]);
        }
    }
    if let Some(start) = s.find("[possible values: ") {
        if let Some(end) = s[start..].find(']') {
            s = format!("{}{}", &s[..start], &s[start + end + 1..]);
        }
    }
    (s.trim().to_string(), default)
}

/// Splice `generated` content between `<!-- BEGIN GENERATED: marker -->` and
/// `<!-- END GENERATED: marker -->` tags in `content`.
fn splice(content: &str, marker: &str, generated: &str) -> Result<String> {
    let begin_tag = format!("<!-- BEGIN GENERATED: {marker} -->");
    let end_tag = format!("<!-- END GENERATED: {marker} -->");

    let begin_pos = content
        .find(&begin_tag)
        .with_context(|| format!("BEGIN GENERATED tag not found for `{marker}`"))?;
    let end_pos = content
        .find(&end_tag)
        .with_context(|| format!("END GENERATED tag not found for `{marker}`"))?;

    if end_pos < begin_pos {
        bail!("END GENERATED appears before BEGIN GENERATED for `{marker}`");
    }

    let after_begin = begin_pos + begin_tag.len();
    Ok(format!(
        "{}\n{}\n{}{}",
        &content[..after_begin],
        generated.trim_end(),
        end_tag,
        &content[end_pos + end_tag.len()..],
    ))
}
