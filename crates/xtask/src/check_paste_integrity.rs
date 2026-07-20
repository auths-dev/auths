//! Paste-integrity lint: fails when a copyable shell block would break the
//! moment a reader pastes it verbatim.
//!
//! It reads two kinds of copyable command text out of a checked-out tree:
//! fenced shell blocks (bash / sh / console / shell / zsh) in Markdown, and the
//! command strings a site actually wires to a copy button — `copy="…"` props
//! and the text shown inside `<Prompt>…</Prompt>` / `<BashLines>…</BashLines>`
//! in TypeScript/TSX. Each block is checked for three paste hazards:
//!
//! * an angle-bracket `<placeholder>` a reader has to hand-edit,
//! * a bare `$VAR` with no matching assignment in the same block, and
//! * a leading `$ ` shell-prompt glyph copied into the payload.
//!
//! A block may opt out only by carrying `paste-integrity: illustrative` on the
//! line immediately above it (for deliberately non-runnable teasers).

use std::collections::HashSet;
use std::path::Path;

use regex_lite::Regex;
use walkdir::{DirEntry, WalkDir};

/// Fenced-code languages whose bodies are copyable shell commands.
const SHELL_LANGS: &[&str] = &["bash", "sh", "console", "shell", "zsh"];

/// Variables the shell always provides, so a reference without a matching
/// assignment in the block is still safe to paste.
const ALWAYS_SET: &[&str] = &[
    "HOME",
    "PATH",
    "PWD",
    "USER",
    "SHELL",
    "TMPDIR",
    "LANG",
    "TERM",
    "CI",
    "GITHUB_WORKSPACE",
    "GITHUB_ENV",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "RUNNER_OS",
    "RUNNER_TEMP",
];

/// The marker that exempts the block immediately below it.
const OPT_OUT_MARKER: &str = "paste-integrity: illustrative";

/// One copyable shell block pulled out of a source file, with enough context
/// to report a precise `path:line` for anything wrong inside it.
struct ShellBlock {
    file: String,
    start_line: usize,
    body: String,
    is_copyable: bool,
    opted_out: bool,
}

/// A single paste hazard found in a block.
struct Violation {
    file: String,
    line: usize,
    reason: String,
}

impl ShellBlock {
    /// Build a copyable block anchored at `start_line` — the shape a copy
    /// button ships and a reader pastes.
    ///
    /// Args:
    /// * `file`: source path used in the reported location.
    /// * `start_line`: 1-based line the block body begins on.
    /// * `body`: the command text, one or more lines.
    ///
    /// Usage:
    /// ```ignore
    /// let block = ShellBlock::copy("verify.tsx", 1, "npx -y @auths-dev/mcp verify");
    /// ```
    #[cfg(test)]
    fn copy(file: &str, start_line: usize, body: &str) -> Self {
        Self {
            file: file.to_string(),
            start_line,
            body: body.to_string(),
            is_copyable: true,
            opted_out: false,
        }
    }

    /// Point a violation at the `offset`-th body line of this block.
    fn at(&self, offset: usize, reason: impl Into<String>) -> Violation {
        Violation {
            file: self.file.clone(),
            line: self.start_line + offset,
            reason: reason.into(),
        }
    }
}

/// Scan a checked-out tree for copyable shell blocks that break on a literal
/// paste, printing every hazard and failing if any are found.
///
/// Args:
/// * `root`: the tree to scan (an `auths`, site, or docs checkout).
///
/// Usage:
/// ```ignore
/// check_paste_integrity::run(std::path::Path::new("."))?;
/// ```
pub fn run(root: &Path) -> anyhow::Result<()> {
    let mut violations = Vec::new();
    let mut files_scanned = 0u32;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_skipped_dir(e))
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let blocks = match ext {
            "md" | "mdx" | "mdoc" => markdown_blocks(&rel, &source),
            "ts" | "tsx" => site_blocks(&rel, &source),
            _ => continue,
        };
        files_scanned += 1;
        for block in &blocks {
            violations.extend(lint_block(block));
        }
    }

    if violations.is_empty() {
        println!(
            "paste-integrity check: {files_scanned} files scanned, every copyable shell block survives a literal paste"
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("{}:{} — {}", v.file, v.line, v.reason);
        }
        anyhow::bail!(
            "{} paste-integrity violation(s): a copyable shell block would break on a literal paste",
            violations.len()
        )
    }
}

/// Prune build output, dependencies, and hidden directories from the walk
/// without ever pruning the scan root itself.
fn is_skipped_dir(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    name == "target" || name == "node_modules" || name.starts_with('.')
}

/// Apply the three paste-hazard rules to one copyable block.
fn lint_block(block: &ShellBlock) -> Vec<Violation> {
    if block.opted_out || !block.is_copyable {
        return Vec::new();
    }
    let angle = Regex::new(r"<[A-Za-z][^>]*>").unwrap();
    let var = Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").unwrap();
    let assigned = collect_assignments(&block.body);

    let mut out = Vec::new();
    for (offset, raw) in block.body.lines().enumerate() {
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        if angle.is_match(line) {
            out.push(block.at(offset, "angle-bracket placeholder in a copyable command"));
        }
        if line.trim_start().starts_with("$ ") {
            out.push(block.at(
                offset,
                "leading `$ ` shell-prompt glyph in a copyable block",
            ));
        }
        for name in unset_vars(line, &var, &assigned) {
            out.push(block.at(
                offset,
                format!("`${name}` used with no assignment in the same block"),
            ));
        }
    }
    out
}

/// Names assigned anywhere in the block, via `export NAME=` or a bare `NAME=`
/// command prefix. Such names are in scope for a later `$NAME`.
fn collect_assignments(body: &str) -> HashSet<String> {
    let re = Regex::new(r"(?:^|\s)(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=").unwrap();
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Return the names of `$VAR` / `${VAR}` references on this line that would be
/// empty on paste — skipping shell positionals/specials (which never match the
/// name pattern), single-quoted literals (the shell does not expand them),
/// escaped `\$`, assignments made earlier in the block, and the handful of
/// variables the shell always sets.
fn unset_vars(line: &str, var: &Regex, assigned: &HashSet<String>) -> Vec<String> {
    let quoted = single_quoted_spans(line);
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    for caps in var.captures_iter(line) {
        let whole = caps.get(0).unwrap();
        let start = whole.start();
        if start >= 1 && bytes[start - 1] == b'\\' {
            continue;
        }
        if quoted.iter().any(|(s, e)| start >= *s && start < *e) {
            continue;
        }
        let name = caps.get(1).unwrap().as_str();
        if name == "_" || assigned.contains(name) || ALWAYS_SET.contains(&name) {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

/// Byte ranges on the line that fall inside single quotes, where the shell
/// performs no variable expansion.
fn single_quoted_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;
    for (i, c) in line.char_indices() {
        if c == '\'' {
            match open {
                Some(start) => {
                    spans.push((start, i));
                    open = None;
                }
                None => open = Some(i + 1),
            }
        }
    }
    spans
}

/// Drop a trailing shell comment so a placeholder or variable named only in
/// prose after `#` is not treated as a command. A `#` opens a comment only at
/// the start of a word and outside quotes, so URL fragments and quoted `#`
/// survive.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => {
                let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
                if prev.is_none() || prev == Some(b' ') || prev == Some(b'\t') {
                    return &line[..i];
                }
            }
            _ => {}
        }
    }
    line
}

/// Pull every fenced shell block out of a Markdown source, tracking the line
/// each body starts on and honouring an immediately-preceding opt-out marker.
fn markdown_blocks(file: &str, source: &str) -> Vec<ShellBlock> {
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(lang) = fence_language(lines[i].trim_start()) else {
            i += 1;
            continue;
        };
        let open = i;
        let mut j = open + 1;
        while j < lines.len() && !lines[j].trim_start().starts_with("```") {
            j += 1;
        }
        if SHELL_LANGS.contains(&lang.as_str()) {
            blocks.push(ShellBlock {
                file: file.to_string(),
                start_line: open + 2,
                body: lines[open + 1..j].join("\n"),
                is_copyable: true,
                opted_out: preceding_marker(&lines, open),
            });
        }
        i = j + 1;
    }
    blocks
}

/// The lower-cased language tag on an opening code fence, if the line opens one.
fn fence_language(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("```")?;
    let lang: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if lang.is_empty() {
        None
    } else {
        Some(lang.to_ascii_lowercase())
    }
}

/// True when the nearest non-blank line above `index` carries the opt-out marker.
fn preceding_marker(lines: &[&str], index: usize) -> bool {
    let mut k = index;
    while k > 0 {
        k -= 1;
        let line = lines[k].trim();
        if line.is_empty() {
            continue;
        }
        return line.contains(OPT_OUT_MARKER);
    }
    false
}

/// Pull copyable command strings out of TypeScript/TSX: the `copy="…"` prop a
/// copy button ships, and the text shown inside `<Prompt>…</Prompt>` /
/// `<BashLines>…</BashLines>`.
fn site_blocks(file: &str, source: &str) -> Vec<ShellBlock> {
    let mut blocks = Vec::new();

    let copy = Regex::new(r#"\bcopy=(?:"([^"]*)"|'([^']*)')"#).unwrap();
    for caps in copy.captures_iter(source) {
        let m = caps.get(1).or_else(|| caps.get(2)).unwrap();
        blocks.push(string_block(file, source, m.start(), m.as_str()));
    }

    for tag in ["Prompt", "BashLines"] {
        let re = Regex::new(&format!(r"(?s)<{tag}[^>]*>(.*?)</{tag}>")).unwrap();
        for caps in re.captures_iter(source) {
            let inner = caps.get(1).unwrap();
            let text = decode_entities(inner.as_str());
            blocks.push(string_block(file, source, inner.start(), &text));
        }
    }

    blocks
}

/// Wrap an extracted command string as a copyable block anchored at the source
/// line it starts on.
fn string_block(file: &str, source: &str, offset: usize, body: &str) -> ShellBlock {
    ShellBlock {
        file: file.to_string(),
        start_line: line_at(source, offset),
        body: body.to_string(),
        is_copyable: true,
        opted_out: false,
    }
}

/// The 1-based line number of a byte offset in `source`.
fn line_at(source: &str, offset: usize) -> usize {
    source[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Turn the HTML entities a TSX author writes for shell metacharacters back
/// into the characters a reader would actually paste.
fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#36;", "$")
        .replace("&rsquo;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angle_bracket_placeholder_is_flagged() {
        let block = ShellBlock::copy(
            "verify.tsx",
            1,
            "npx -y @auths-dev/mcp verify-spend --log spend.jsonl --agent <agent> --root <root>",
        );
        assert!(
            lint_block(&block)
                .iter()
                .any(|v| v.reason.contains("placeholder")),
            "an <agent>/<root> placeholder must fail the paste check"
        );
    }

    #[test]
    fn interpolated_command_passes() {
        let block = ShellBlock::copy(
            "verify.tsx",
            1,
            "npx -y @auths-dev/mcp verify-spend --log spend.jsonl --registry ./registry \
             --agent did:keri:EHiKP_2dx1U88s4Upir4BxQ1Qc21203WaW1JfSJvn0i2 \
             --root did:keri:EF6K8G4ZgfIjt788itIogc8eDXP948mAo1aQgXwQZJa2",
        );
        assert!(
            lint_block(&block).is_empty(),
            "the interpolated form pastes cleanly and must pass"
        );
    }

    #[test]
    fn buyer_integration_pane_snippet_passes() {
        let block = ShellBlock::copy(
            "integration-pane.tsx",
            16,
            "npx -y @auths-dev/mcp wrap --scope paid.call --budget '$1' --ttl 30m \
             --rail x402 --test-mode -- npx -y mcp-remote https://api.example.com/mcp",
        );
        assert!(
            lint_block(&block).is_empty(),
            "the known-good interpolated pane must never regress"
        );
    }

    #[test]
    fn exported_variable_reference_passes() {
        let block = ShellBlock::copy(
            "anchor.md",
            14,
            "export AGENT_DID=did:keri:EXAMPLE\nauths-mcp export-attestation --agent \"$AGENT_DID\"",
        );
        assert!(
            lint_block(&block).is_empty(),
            "a $VAR with a matching assignment in the block is fine"
        );
    }

    #[test]
    fn unassigned_variable_is_flagged() {
        let block = ShellBlock::copy("anchor.md", 5, "auths-mcp anchor --seed $SEED_ID");
        assert!(
            lint_block(&block)
                .iter()
                .any(|v| v.reason.contains("SEED_ID")),
            "a bare $SEED_ID with no assignment must fail"
        );
    }

    #[test]
    fn prompt_glyph_is_flagged() {
        let block = ShellBlock::copy("landing.tsx", 56, "$ npx -y @auths-dev/mcp verify-spend");
        assert!(
            lint_block(&block)
                .iter()
                .any(|v| v.reason.contains("prompt")),
            "a leading `$ ` prompt glyph must fail"
        );
    }

    #[test]
    fn command_substitution_and_positionals_pass() {
        let block = ShellBlock::copy(
            "network.tsx",
            141,
            "WITNESS_SEED=$(openssl rand -hex 32) docker compose up -d",
        );
        assert!(
            lint_block(&block).is_empty(),
            "command substitution and inline assignment are safe"
        );
    }

    #[test]
    fn markdown_fenced_block_extraction_reports_precise_lines() {
        let source = "intro\n\n```bash\nauths-mcp anchor --root <root>\n```\n";
        let blocks = markdown_blocks("guide.md", source);
        assert_eq!(blocks.len(), 1);
        let found = lint_block(&blocks[0]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 4, "the placeholder is on source line 4");
    }

    #[test]
    fn illustrative_marker_opts_a_block_out() {
        let source = "<!-- paste-integrity: illustrative -->\n```bash\nauths-mcp verify --agent <agent>\n```\n";
        let blocks = markdown_blocks("guide.md", source);
        assert_eq!(blocks.len(), 1);
        assert!(
            lint_block(&blocks[0]).is_empty(),
            "an explicitly illustrative block is exempt"
        );
    }

    #[test]
    fn tsx_copy_prop_is_extracted_and_linted() {
        let source = "<InkTerminal copy=\"auths-mcp verify --agent <agent>\">\n";
        let blocks = site_blocks("verify.tsx", source);
        assert_eq!(blocks.len(), 1);
        assert!(
            lint_block(&blocks[0])
                .iter()
                .any(|v| v.reason.contains("placeholder"))
        );
    }

    #[test]
    fn prompt_children_entities_are_decoded_and_linted() {
        let source =
            "<Prompt className=\"pl-4\">--registry ./registry --agent &lt;agent&gt;</Prompt>\n";
        let blocks = site_blocks("verify.tsx", source);
        assert_eq!(blocks.len(), 1);
        assert!(
            lint_block(&blocks[0])
                .iter()
                .any(|v| v.reason.contains("placeholder")),
            "an entity-encoded &lt;agent&gt; is still a placeholder on paste"
        );
    }
}
