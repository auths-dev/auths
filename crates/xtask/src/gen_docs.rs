use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// A discovered CLI command to document.
struct DiscoveredCmd {
    args: Vec<String>,
    marker: String,
    group: String,
}

/// Commands to exclude from documentation entirely (internal/debug).
const EXCLUDED_COMMANDS: &[&str] = &["debug", "commit", "log", "account"];

/// Groups whose commands go into the primary doc file.
const PRIMARY_GROUPS: &[&str] = &["Primary", "Setup & Troubleshooting", "Utilities"];

/// Groups whose commands go into the advanced doc file.
const ADVANCED_GROUPS: &[&str] = &["Advanced", "Internal"];

/// Strip ANSI escape codes from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Parse `auths --help-all` output into (group_name, Vec<command_name>) pairs.
fn parse_groups(help_all: &str) -> Vec<(String, Vec<String>)> {
    let clean = strip_ansi(help_all);
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut current_group: Option<String> = None;
    let mut current_cmds: Vec<String> = Vec::new();

    for line in clean.lines() {
        let trimmed = line.trim();

        // Stop at "Options:" — that's the global flags section, not a command group.
        if trimmed == "Options:" {
            if let Some(ref name) = current_group {
                groups.push((name.clone(), std::mem::take(&mut current_cmds)));
            }
            break;
        }

        // Group header: a non-indented line ending with ':'
        if !line.starts_with(' ')
            && trimmed.ends_with(':')
            && !trimmed.starts_with("Usage:")
            && !trimmed.is_empty()
        {
            if let Some(ref name) = current_group {
                groups.push((name.clone(), std::mem::take(&mut current_cmds)));
            }
            current_group = Some(trimmed.trim_end_matches(':').to_string());
            continue;
        }

        // Command line: indented, starts with command name
        if current_group.is_some() && line.starts_with("  ") && !trimmed.is_empty() {
            if let Some(cmd_name) = trimmed.split_whitespace().next() {
                if cmd_name != "help" {
                    current_cmds.push(cmd_name.to_string());
                }
            }
        }

        if current_group.is_some()
            && !line.starts_with(' ')
            && !trimmed.ends_with(':')
            && !trimmed.is_empty()
        {
            if let Some(ref name) = current_group {
                groups.push((name.clone(), std::mem::take(&mut current_cmds)));
            }
            current_group = None;
        }
    }

    if let Some(name) = current_group {
        groups.push((name, current_cmds));
    }

    groups
}

/// Parse `auths <cmd> --help` to extract subcommand names from the Commands: section.
fn parse_subcommands(binary: &Path, parent: &str) -> Result<Option<Vec<String>>> {
    let out = Command::new(binary)
        .args([parent, "--help"])
        .output()
        .with_context(|| format!("failed to run auths {parent} --help"))?;

    let text = strip_ansi(
        &(String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)),
    );

    let mut in_commands = false;
    let mut subs = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands {
            if !line.starts_with(' ') && !trimmed.is_empty() {
                break;
            }
            if let Some(name) = trimmed.split_whitespace().next() {
                if name != "help" {
                    subs.push(name.to_string());
                }
            }
        }
    }

    if subs.is_empty() {
        Ok(None)
    } else {
        Ok(Some(subs))
    }
}

/// Discover all documentable commands by parsing CLI help output.
fn discover_commands(binary: &Path) -> Result<Vec<DiscoveredCmd>> {
    let out = Command::new(binary)
        .arg("--help-all")
        .output()
        .context("failed to run auths --help-all")?;

    let help_all =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let groups = parse_groups(&help_all);

    let mut commands = Vec::new();

    for (group, cmds) in &groups {
        for cmd in cmds {
            if EXCLUDED_COMMANDS.contains(&cmd.as_str()) {
                continue;
            }

            match parse_subcommands(binary, cmd)? {
                Some(subs) => {
                    for sub in subs {
                        let args = vec![cmd.clone(), sub.clone()];
                        let marker = format!("auths {} {}", cmd, sub);
                        commands.push(DiscoveredCmd {
                            args,
                            marker,
                            group: group.clone(),
                        });
                    }
                }
                None => {
                    let args = vec![cmd.clone()];
                    let marker = format!("auths {}", cmd);
                    commands.push(DiscoveredCmd {
                        args,
                        marker,
                        group: group.clone(),
                    });
                }
            }
        }
    }

    Ok(commands)
}

/// Generate a complete markdown doc file for a set of group names.
///
/// Produces a file with `## Group Name` headers, then `### auths command`
/// sections with flag tables inside `<!-- BEGIN/END GENERATED -->` markers.
fn generate_doc_file(
    binary: &Path,
    title: &str,
    group_names: &[&str],
    commands: &[DiscoveredCmd],
) -> Result<String> {
    let mut out = format!("# {title}\n");

    for group_name in group_names {
        // Collect commands in this group
        let group_cmds: Vec<&DiscoveredCmd> =
            commands.iter().filter(|c| c.group == *group_name).collect();

        if group_cmds.is_empty() {
            continue;
        }

        out.push_str(&format!("\n## {group_name}\n"));

        for cmd in &group_cmds {
            let cmd_display = format!("auths {}", cmd.args.join(" "));
            let table = generate_table(binary, &cmd.args)
                .with_context(|| format!("failed to generate table for `{}`", cmd.marker))?;

            out.push_str(&format!("\n### {cmd_display}\n\n"));
            out.push_str(&format!("```bash\n{cmd_display}\n```\n\n"));
            out.push_str(&format!("<!-- BEGIN GENERATED: {} -->\n", cmd.marker));
            out.push_str(table.trim_end());
            out.push('\n');
            out.push_str(&format!("<!-- END GENERATED: {} -->\n", cmd.marker));
        }
    }

    Ok(out)
}

/// Build the `auths` binary then regenerate all CLI doc files.
///
/// Commands are auto-discovered from `auths --help-all`. The doc files are
/// regenerated from scratch with proper group headings matching the CLI's
/// own category structure.
pub fn run(workspace_root: &Path, check: bool) -> Result<()> {
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
    println!("Discovering commands...");
    let commands = discover_commands(&binary)?;
    println!("  found {} commands", commands.len());

    let files: Vec<(&str, &str, &[&str])> = vec![
        (
            "docs/cli/commands/primary.md",
            "Primary Commands",
            PRIMARY_GROUPS,
        ),
        (
            "docs/cli/commands/advanced.md",
            "Advanced Commands",
            ADVANCED_GROUPS,
        ),
    ];

    let mut stale: Vec<String> = Vec::new();

    for (rel_path, title, groups) in &files {
        let doc_path = workspace_root.join(rel_path);
        let generated = generate_doc_file(&binary, title, groups, &commands)?;

        let original = std::fs::read_to_string(&doc_path).unwrap_or_default();

        if generated != original {
            if check {
                stale.push(rel_path.to_string());
            } else {
                std::fs::write(&doc_path, &generated)
                    .with_context(|| format!("failed to write {}", doc_path.display()))?;
                println!("  wrote {rel_path}");
            }
        } else {
            println!("  ok   {rel_path}");
        }
    }

    if check && !stale.is_empty() {
        bail!(
            "CLI docs are out of date — run `cargo xtask gen-docs` to regenerate:\n{}",
            stale
                .iter()
                .map(|f| format!("  - {f}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    Ok(())
}

/// Run `auths <args> -h` and render a description + markdown flag table.
fn generate_table(binary: &Path, args: &[String]) -> Result<String> {
    let mut full_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    full_args.push("-h");

    let out = Command::new(binary)
        .args(&full_args)
        .output()
        .with_context(|| format!("failed to run auths {:?}", args))?;

    let text = strip_ansi(
        &(String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)),
    );

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
fn parse_help_rows(help: &str) -> Result<Vec<(String, String, String)>> {
    let mut in_section = false;
    let mut raw_rows: Vec<(String, String)> = Vec::new();

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

/// Strip `[default: x]` and `[possible values: ...]` annotations.
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
