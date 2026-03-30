use anyhow::{Context, Result, bail};
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
    // ── Primary ─────────────────────────────────────────────────────────
    Cmd {
        args: &["init"],
        marker: "auths init",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["sign"],
        marker: "auths sign",
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
    Cmd {
        args: &["whoami"],
        marker: "auths whoami",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["tutorial"],
        marker: "auths tutorial",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["doctor"],
        marker: "auths doctor",
        doc_file: "docs/cli/commands/primary.md",
    },
    Cmd {
        args: &["pair"],
        marker: "auths pair",
        doc_file: "docs/cli/commands/primary.md",
    },
    // ── device ──────────────────────────────────────────────────────────
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
    // ── id ──────────────────────────────────────────────────────────────
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
    // ── key ─────────────────────────────────────────────────────────────
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
    // ── policy ──────────────────────────────────────────────────────────
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
    // ── emergency ───────────────────────────────────────────────────────
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
    // ── git ─────────────────────────────────────────────────────────────
    Cmd {
        args: &["signers", "sync"],
        marker: "auths signers sync",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["git", "install-hooks"],
        marker: "auths git install-hooks",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── trust ───────────────────────────────────────────────────────────
    Cmd {
        args: &["trust", "pin"],
        marker: "auths trust pin",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["trust", "list"],
        marker: "auths trust list",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["trust", "remove"],
        marker: "auths trust remove",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["trust", "show"],
        marker: "auths trust show",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── org ─────────────────────────────────────────────────────────────
    Cmd {
        args: &["org", "create"],
        marker: "auths org create",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["org", "add-member"],
        marker: "auths org add-member",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["org", "revoke-member"],
        marker: "auths org revoke-member",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["org", "list-members"],
        marker: "auths org list-members",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── audit ───────────────────────────────────────────────────────────
    Cmd {
        args: &["audit"],
        marker: "auths audit",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── agent ───────────────────────────────────────────────────────────
    Cmd {
        args: &["agent", "start"],
        marker: "auths agent start",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "stop"],
        marker: "auths agent stop",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "status"],
        marker: "auths agent status",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "env"],
        marker: "auths agent env",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "lock"],
        marker: "auths agent lock",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "unlock"],
        marker: "auths agent unlock",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "install-service"],
        marker: "auths agent install-service",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["agent", "uninstall-service"],
        marker: "auths agent uninstall-service",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── witness ─────────────────────────────────────────────────────────
    Cmd {
        args: &["witness", "start"],
        marker: "auths witness start",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["witness", "add"],
        marker: "auths witness add",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["witness", "remove"],
        marker: "auths witness remove",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["witness", "list"],
        marker: "auths witness list",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── scim ────────────────────────────────────────────────────────────
    Cmd {
        args: &["scim", "serve"],
        marker: "auths scim serve",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "quickstart"],
        marker: "auths scim quickstart",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "test-connection"],
        marker: "auths scim test-connection",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "tenants"],
        marker: "auths scim tenants",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "add-tenant"],
        marker: "auths scim add-tenant",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "rotate-token"],
        marker: "auths scim rotate-token",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["scim", "status"],
        marker: "auths scim status",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── config ──────────────────────────────────────────────────────────
    Cmd {
        args: &["config", "set"],
        marker: "auths config set",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["config", "get"],
        marker: "auths config get",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["config", "show"],
        marker: "auths config show",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── approval ────────────────────────────────────────────────────────
    Cmd {
        args: &["approval", "list"],
        marker: "auths approval list",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["approval", "grant"],
        marker: "auths approval grant",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── artifact ────────────────────────────────────────────────────────
    Cmd {
        args: &["artifact", "sign"],
        marker: "auths artifact sign",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["artifact", "verify"],
        marker: "auths artifact verify",
        doc_file: "docs/cli/commands/advanced.md",
    },
    Cmd {
        args: &["artifact", "publish"],
        marker: "auths artifact publish",
        doc_file: "docs/cli/commands/advanced.md",
    },
    // ── completions ─────────────────────────────────────────────────────
    Cmd {
        args: &["completions"],
        marker: "auths completions",
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

/// Run `auths <args> -h` and render a description + markdown flag table.
fn generate_table(binary: &Path, args: &[&str]) -> Result<String> {
    let mut full_args: Vec<&str> = args.to_vec();
    full_args.push("-h");

    let out = Command::new(binary)
        .args(&full_args)
        .output()
        .with_context(|| format!("failed to run auths {:?}", args))?;

    // clap writes -h to stdout; some versions use stderr on error.
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);

    let description = extract_description(&text);
    let rows = parse_help_rows(&text)?;

    let mut out = String::new();
    if !description.is_empty() {
        out.push_str(&description);
        out.push_str("\n\n");
    }

    if rows.is_empty() {
        out.push_str("_No options._");
        return Ok(out);
    }

    out.push_str("| Flag | Default | Description |\n");
    out.push_str("|------|---------|-------------|\n");
    for (flag, default, desc) in rows {
        let d = if default.is_empty() {
            "—".to_string()
        } else {
            format!("`{default}`")
        };
        let desc = desc.replace('|', "\\|");
        out.push_str(&format!("| `{flag}` | {d} | {desc} |\n"));
    }
    Ok(out)
}

/// Extract the command description from clap's help output.
///
/// The description is the first non-empty line, before the `Usage:` line.
fn extract_description(help: &str) -> String {
    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Usage:") {
            break;
        }
        return trimmed.to_string();
    }
    String::new()
}

/// Parse clap's `-h` output into structured flag rows.
///
/// Returns `Vec<(flag, default, description)>`. Handles both `Options:` and
/// `Arguments:` sections. Skips `-h/--help` and `-V/--version`. Handles
/// continuation lines where clap wraps long descriptions onto the next
/// indented line.
fn parse_help_rows(help: &str) -> Result<Vec<(String, String, String)>> {
    let mut in_section = false;
    let mut raw_rows: Vec<(String, String)> = Vec::new(); // (flag, raw_desc)

    let lines: Vec<&str> = help.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();

        if trimmed == "Options:" || trimmed == "Arguments:" {
            in_section = true;
            i += 1;
            continue;
        }
        if in_section && !line.is_empty() && !line.starts_with(' ') {
            in_section = false;
        }
        if !in_section {
            i += 1;
            continue;
        }

        if trimmed.starts_with('-') || trimmed.starts_with('<') {
            if trimmed.contains("--help") || trimmed.contains("--version") {
                i += 1;
                continue;
            }

            if let Some((flag_str, desc_str)) = split_flag_line(trimmed) {
                let mut desc = desc_str;
                // If description is empty, check the next line for a continuation.
                // Clap wraps long descriptions onto an indented continuation line.
                if desc.is_empty() && i + 1 < lines.len() {
                    let next = lines[i + 1];
                    let next_trimmed = next.trim_start();
                    let indent = next.len() - next.trim_start().len();
                    if indent >= 10
                        && !next_trimmed.starts_with('-')
                        && !next_trimmed.starts_with('<')
                        && !next_trimmed.is_empty()
                    {
                        desc = next_trimmed.to_string();
                        i += 1;
                    }
                }
                raw_rows.push((flag_str, desc));
            }
        }
        i += 1;
    }

    let rows = raw_rows
        .into_iter()
        .map(|(flag, raw_desc)| {
            let (desc, default) = extract_default(&raw_desc);
            (flag, default, desc)
        })
        .collect();
    Ok(rows)
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

    if let Some(start) = s.find("[default: ")
        && let Some(end) = s[start..].find(']')
    {
        default = s[start + 10..start + end].to_string();
        s = format!("{}{}", &s[..start], &s[start + end + 1..]);
    }
    if let Some(start) = s.find("[possible values: ")
        && let Some(end) = s[start..].find(']')
    {
        s = format!("{}{}", &s[..start], &s[start + end + 1..]);
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
