//! Command-drift lint: fails if user-facing strings reference an `auths`
//! command (or long flag) that doesn't exist in the real command tree.
//!
//! Scans the repo-root README.md, every Markdown file under `docs/cli/`, and
//! every string literal in `crates/auths-cli/src/**/*.rs`, then validates each
//! `auths <cmd> [<sub>]` mention against the tree discovered from the built
//! binary's `--help-all` output. This is the ratchet that keeps README/docs/CLI
//! promises and the actual clap tree from drifting apart again.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

use crate::gen_docs::{parse_groups, parse_subcommands, strip_ansi};

/// Words that may immediately precede `auths` in prose about the system
/// ("your auths identity"). A mention preceded by one of these is skipped.
const DETERMINERS: &[&str] = &[
    "the", "your", "a", "an", "this", "its", "my", "our", "every", "each", "of", "with", "using",
    "called", "named",
];

/// Words after `auths ` that can never be commands (ordinary prose). Add an
/// entry here when the lint flags plain English; add to `ALLOWED_PHRASES`
/// instead when a specific full sentence needs exempting.
const STOPWORDS: &[&str] = &[
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "binary",
    "by",
    "can",
    "cli",
    "context",
    "data",
    "directory",
    "does",
    "expects",
    "finds",
    "for",
    "from",
    "has",
    "home",
    "in",
    "instead",
    "is",
    "it",
    "needs",
    "of",
    "on",
    "or",
    "repo",
    "repository",
    "requires",
    "stores",
    "team",
    "that",
    "the",
    "then",
    "this",
    "to",
    "uses",
    "version",
    "versions",
    "via",
    "when",
    "will",
    "with",
    "works",
    "your",
];

/// Exact substrings that exempt the containing string/line (last resort —
/// justify every entry).
const ALLOWED_PHRASES: &[&str] = &["auths slsa generate"];

struct CmdNode {
    subs: BTreeMap<String, CmdNode>,
    flags: HashSet<String>,
}

struct CommandTree {
    top: BTreeMap<String, CmdNode>,
}

struct Violation {
    file: PathBuf,
    line: usize,
    msg: String,
}

/// Build the auths binary, discover the real command tree, and scan all
/// user-facing strings for references to commands/flags that don't exist.
///
/// Args:
/// * `workspace_root`: Repository root (parent of `crates/`).
///
/// Usage:
/// ```ignore
/// check_command_drift::run(workspace_root())?;
/// ```
pub fn run(workspace_root: &Path) -> anyhow::Result<()> {
    check_xtask_alias_ships(workspace_root)?;
    check_release_stages_witness_node(workspace_root)?;

    println!("Building auths-cli...");
    let status = Command::new("cargo")
        .args(["build", "--package", "auths-cli"])
        .current_dir(workspace_root)
        .status()?;
    if !status.success() {
        anyhow::bail!("cargo build --package auths-cli failed");
    }
    let binary = workspace_root.join("target/debug/auths");

    println!("Discovering command tree...");
    let tree = build_command_tree(&binary)?;
    println!("  {} top-level commands", tree.top.len());

    let mut violations = Vec::new();
    scan_readme(workspace_root, &tree, &mut violations)?;
    let docs_scanned = scan_docs_cli(workspace_root, &tree, &mut violations)?;
    let files_scanned = scan_rust_sources(workspace_root, &tree, &mut violations)?;

    if violations.is_empty() {
        println!(
            "command-drift check: README + {} docs/cli files + {} CLI source files scanned, 0 violations",
            docs_scanned, files_scanned
        );
        Ok(())
    } else {
        println!("command-drift check: {} violations", violations.len());
        for v in &violations {
            let rel = v.file.strip_prefix(workspace_root).unwrap_or(&v.file);
            println!("  {}:{} — VIOLATION: {}", rel.display(), v.line, v.msg);
        }
        anyhow::bail!(
            "{} command-drift violations found. Fix the string, or add a \
             STOPWORDS/ALLOWED_PHRASES entry in check_command_drift.rs if it is prose.",
            violations.len()
        )
    }
}

/// Every doc prints `cargo xtask …`; that shorthand only resolves from a clone
/// when `.cargo/config.toml` ships the `[alias] xtask` entry. A bare `.cargo/`
/// ignore once excluded that file entirely, so a fresh clone got `error: no such
/// command: xtask`. Fail closed if the alias is missing.
fn check_xtask_alias_ships(workspace_root: &Path) -> anyhow::Result<()> {
    let path = workspace_root.join(".cargo/config.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!(
            "{}: {e} — the `cargo xtask` alias must be committed so clones resolve it",
            path.display()
        )
    })?;
    let defines_xtask = text
        .lines()
        .skip_while(|l| l.trim() != "[alias]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .any(|l| l.trim_start().starts_with("xtask"));
    if !defines_xtask {
        anyhow::bail!(
            "{} has no `[alias] xtask` entry — `cargo xtask …` in the docs will not resolve \
             from a clone",
            path.display()
        );
    }
    Ok(())
}

/// The docs present `witness-node` as an installable binary; the release must
/// stage it or `brew install` ships an archive without it. Assert the release
/// workflow copies `witness-node` out of the build directory.
fn check_release_stages_witness_node(workspace_root: &Path) -> anyhow::Result<()> {
    let path = workspace_root.join(".github/workflows/release.yml");
    let text =
        std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let stages_it = text.lines().any(|line| {
        let line = line.trim();
        (line.starts_with("cp ") || line.contains("Copy-Item"))
            && line.contains("release/")
            && line.contains("witness-node")
    });
    if !stages_it {
        anyhow::bail!(
            "{} does not stage `witness-node` into the release archive — the docs present it \
             as an installable binary",
            path.display()
        );
    }
    Ok(())
}

/// Discover the full two-level command tree (plus per-node long-flag sets)
/// from the built binary's help output.
fn build_command_tree(binary: &Path) -> anyhow::Result<CommandTree> {
    let out = Command::new(binary).arg("--help-all").output()?;
    let help_all =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let groups = parse_groups(&help_all);

    let mut top = BTreeMap::new();
    for (_group, cmds) in &groups {
        for cmd in cmds {
            let mut subs = BTreeMap::new();
            if let Some(sub_names) = parse_subcommands(binary, cmd)? {
                for sub in sub_names {
                    let flags = extract_flags(binary, &[cmd, &sub])?;
                    let node = CmdNode {
                        subs: BTreeMap::new(),
                        flags,
                    };
                    subs.insert(sub, node);
                }
            }
            let flags = extract_flags(binary, &[cmd])?;
            top.insert(cmd.clone(), CmdNode { subs, flags });
        }
    }
    // `help` is implicit in clap and filtered out of the parsed groups.
    top.insert(
        "help".to_string(),
        CmdNode {
            subs: BTreeMap::new(),
            flags: HashSet::new(),
        },
    );
    Ok(CommandTree { top })
}

/// Collect every `--long-flag` mentioned anywhere in `auths <args> -h` output.
///
/// Deliberately over-collects (flags named in descriptions and examples count)
/// — for a drift lint, over-collection means fewer false positives.
fn extract_flags(binary: &Path, args: &[&str]) -> anyhow::Result<HashSet<String>> {
    let mut full_args: Vec<&str> = args.to_vec();
    full_args.push("-h");
    let out = Command::new(binary).args(&full_args).output()?;
    let text = strip_ansi(
        &(String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)),
    );
    let re = regex_lite::Regex::new(r"--[a-z0-9][a-z0-9-]*").expect("valid flag regex");
    let mut flags: HashSet<String> = re
        .find_iter(&text)
        .map(|m| m.as_str().to_string())
        .collect();
    flags.insert("--help".to_string());
    flags.insert("--version".to_string());
    Ok(flags)
}

fn scan_readme(
    workspace_root: &Path,
    tree: &CommandTree,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<()> {
    let path = workspace_root.join("README.md");
    let text = std::fs::read_to_string(&path)?;
    for (i, line) in text.lines().enumerate() {
        check_text(line, tree, &path, i + 1, violations);
    }
    Ok(())
}

/// Walk `docs/cli/**/*.md` and check every line, same as the README scan.
fn scan_docs_cli(
    workspace_root: &Path,
    tree: &CommandTree,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<u32> {
    let root = workspace_root.join("docs/cli");
    let mut files_scanned = 0u32;
    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "md"))
    {
        let path = entry.path();
        let text = std::fs::read_to_string(path)?;
        files_scanned += 1;
        for (i, line) in text.lines().enumerate() {
            check_text(line, tree, path, i + 1, violations);
        }
    }
    Ok(files_scanned)
}

/// Walk `crates/auths-cli/src` and check every non-test string literal.
fn scan_rust_sources(
    workspace_root: &Path,
    tree: &CommandTree,
    violations: &mut Vec<Violation>,
) -> anyhow::Result<u32> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("failed to set tree-sitter-rust language");

    let root = workspace_root.join("crates/auths-cli/src");
    let mut files_scanned = 0u32;

    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
    {
        let path = entry.path();
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };
        files_scanned += 1;
        scan_rust_node(parsed.root_node(), &source, path, tree, violations);
    }
    Ok(files_scanned)
}

/// Recursive visitor: skips `#[cfg(test)]`/`#[test]` subtrees, checks every
/// string literal (including literals inside macro token trees).
fn scan_rust_node(
    node: tree_sitter::Node,
    source: &str,
    file: &Path,
    tree: &CommandTree,
    violations: &mut Vec<Violation>,
) {
    let kind = node.kind();
    if (kind == "mod_item" || kind == "function_item") && has_test_attribute(node, source) {
        return;
    }
    if kind == "string_literal" || kind == "raw_string_literal" {
        let text = &source[node.byte_range()];
        let line = node.start_position().row + 1;
        check_text(text, tree, file, line, violations);
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_rust_node(child, source, file, tree, violations);
    }
}

/// A node is test code when an immediately preceding sibling attribute is
/// `#[test]` / `#[cfg(test)]` (tree-sitter places attributes as siblings).
fn has_test_attribute(node: tree_sitter::Node, source: &str) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "attribute_item" {
            let text = &source[sib.byte_range()];
            if text.contains("#[test]") || text.contains("#[cfg(test)]") || text.contains("::test]")
            {
                return true;
            }
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }
    false
}

/// Check one text fragment (a README line or one string literal) for
/// `auths <cmd> [<sub>] [--flags…]` mentions that don't exist in the tree.
fn check_text(
    text: &str,
    tree: &CommandTree,
    file: &Path,
    line: usize,
    violations: &mut Vec<Violation>,
) {
    if ALLOWED_PHRASES.iter().any(|p| text.contains(p)) {
        return;
    }
    let re = regex_lite::Regex::new(r"auths ([a-z][a-z0-9_-]*)(?: ([a-z][a-z0-9_-]*))?")
        .expect("valid command regex");

    for caps in re.captures_iter(text) {
        let whole = caps.get(0).expect("match group 0 always present");
        if !standalone_mention(text, whole.start()) {
            continue;
        }
        if preceded_by_determiner(text, whole.start()) {
            continue;
        }

        let level1 = caps.get(1).expect("group 1 always present").as_str();
        let Some(node) = tree.top.get(level1) else {
            if !STOPWORDS.contains(&level1) {
                violations.push(Violation {
                    file: file.to_path_buf(),
                    line,
                    msg: format!("`auths {level1}` is not a real command"),
                });
            }
            continue;
        };

        let mut resolved: &CmdNode = node;
        let mut resolved_path = format!("auths {level1}");
        let mut match_end = caps.get(1).expect("group 1").end();

        if let Some(l2) = caps.get(2) {
            let level2 = l2.as_str();
            if !node.subs.is_empty() {
                if let Some(sub_node) = node.subs.get(level2) {
                    resolved = sub_node;
                    resolved_path = format!("auths {level1} {level2}");
                    match_end = l2.end();
                } else if !STOPWORDS.contains(&level2) {
                    violations.push(Violation {
                        file: file.to_path_buf(),
                        line,
                        msg: format!("`auths {level1} {level2}` is not a real subcommand"),
                    });
                    continue;
                }
            }
        }

        check_flags(
            &text[match_end..],
            resolved,
            &resolved_path,
            file,
            line,
            violations,
        );
    }
}

/// `auths` must be a standalone word: reject when the preceding character is
/// part of an identifier, path, or domain (`auths-dev`, `auths.dev`,
/// `auths-base/auths`, `preauths`).
fn standalone_mention(text: &str, start: usize) -> bool {
    match text[..start].chars().next_back() {
        None => true,
        Some(c) => !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')),
    }
}

/// True when the word before the mention is a determiner — prose about the
/// system ("your auths identity"), not a command invocation.
fn preceded_by_determiner(text: &str, start: usize) -> bool {
    let before = &text[..start];
    let trimmed = before.trim_end_matches(|c: char| !c.is_ascii_alphabetic());
    let prev_word: String = trimmed
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    DETERMINERS.contains(&prev_word.to_ascii_lowercase().as_str())
}

/// Validate `--long-flags` that follow a resolved command, up to the first
/// shell/string delimiter. Bare words and short flags are ignored — only
/// long flags are unambiguous enough to validate. Validation stops entirely
/// at the first bare command-shaped word: it may be a third-level subcommand
/// (or a flag value) whose flag set this two-level tree doesn't know.
fn check_flags(
    rest: &str,
    node: &CmdNode,
    resolved_path: &str,
    file: &Path,
    line: usize,
    violations: &mut Vec<Violation>,
) {
    let segment: &str = rest
        .split(['`', '\'', '"', '|', ';', '&', ')', '\n'])
        .next()
        .unwrap_or("");
    for token in segment.split_whitespace() {
        if !token.starts_with("--")
            && token
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return;
        }
        if let Some(flag) = token.strip_prefix("--") {
            let name = format!("--{}", flag.split('=').next().unwrap_or(flag));
            if !name
                .chars()
                .skip(2)
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                continue;
            }
            if !node.flags.contains(&name) {
                violations.push(Violation {
                    file: file.to_path_buf(),
                    line,
                    msg: format!("`{resolved_path}` has no `{name}` flag"),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(flags: &[&str]) -> CmdNode {
        CmdNode {
            subs: BTreeMap::new(),
            flags: flags.iter().map(|f| f.to_string()).collect(),
        }
    }

    fn fake_tree() -> CommandTree {
        let mut device_subs = BTreeMap::new();
        device_subs.insert("link".to_string(), leaf(&["--key", "--device-key"]));
        let mut trust_subs = BTreeMap::new();
        trust_subs.insert("pin".to_string(), leaf(&["--did"]));

        let mut top = BTreeMap::new();
        top.insert("init".to_string(), leaf(&["--profile"]));
        top.insert("sign".to_string(), leaf(&[]));
        top.insert(
            "device".to_string(),
            CmdNode {
                subs: device_subs,
                flags: HashSet::new(),
            },
        );
        top.insert(
            "trust".to_string(),
            CmdNode {
                subs: trust_subs,
                flags: HashSet::new(),
            },
        );
        CommandTree { top }
    }

    fn violations_for(text: &str) -> Vec<String> {
        let tree = fake_tree();
        let mut out = Vec::new();
        check_text(text, &tree, Path::new("t.rs"), 1, &mut out);
        out.into_iter().map(|v| v.msg).collect()
    }

    #[test]
    fn flags_dead_commands() {
        assert!(!violations_for("Run `auths git setup` first").is_empty());
        assert!(!violations_for("auths verify-commit HEAD").is_empty());
        assert!(!violations_for("auths device sync").is_empty());
    }

    #[test]
    fn flags_unknown_long_flag() {
        let v = violations_for("auths device link --device-alias <name>");
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("--device-alias"));
    }

    #[test]
    fn passes_real_commands_and_flags() {
        assert!(violations_for("auths init").is_empty());
        assert!(violations_for("Run 'auths trust pin'").is_empty());
        assert!(violations_for("auths device link --key k --device-key d").is_empty());
        assert!(violations_for("auths sign <file>").is_empty());
    }

    #[test]
    fn ignores_non_command_shapes() {
        assert!(violations_for("the auths-dev org").is_empty());
        assert!(violations_for("see auths.dev for docs").is_empty());
        assert!(violations_for("auths-sign is a binary").is_empty());
        assert!(violations_for("Auths stores your identity").is_empty());
    }

    #[test]
    fn determiner_and_stopword_guards() {
        assert!(violations_for("using your auths identity").is_empty());
        assert!(violations_for("failed to build auths context").is_empty());
    }

    #[test]
    fn flag_check_stops_at_delimiters() {
        assert!(violations_for("auths sign x && git push --force").is_empty());
        assert!(violations_for("`auths init` then `git commit --amend`").is_empty());
    }

    #[test]
    fn tree_sitter_extraction_skips_tests_and_comments() {
        let source = r#"
            fn prod() {
                println!("auths bogus");
            }
            // auths alsobogus in a comment
            #[cfg(test)]
            mod tests {
                #[test]
                fn t() { let _ = "auths testonly"; }
            }
        "#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("language");
        let parsed = parser.parse(source, None).expect("parse");
        let tree = fake_tree();
        let mut violations = Vec::new();
        scan_rust_node(
            parsed.root_node(),
            source,
            Path::new("t.rs"),
            &tree,
            &mut violations,
        );
        assert_eq!(violations.len(), 1, "only the prod string literal counts");
        assert!(violations[0].msg.contains("bogus"));
    }

    #[test]
    fn help_all_parse_includes_hidden_groups() {
        let help =
            "Primary:\n  init  Set up\n\nInternal:\n  debug  Debug tools\n\nOptions:\n  -h\n";
        let groups = parse_groups(help);
        let all: Vec<&String> = groups.iter().flat_map(|(_, c)| c).collect();
        assert!(all.iter().any(|c| *c == "init"));
        assert!(all.iter().any(|c| *c == "debug"));
    }
}
