//! HTML report rendering for audit data.

use crate::domains::diagnostics::AuditSummary;
use crate::ports::git::{CommitRecord, SignatureStatus};

/// Render a full HTML audit report from structured data.
///
/// Args:
/// * `generated_at`: ISO-8601 timestamp string for the report header.
/// * `repository`: Repository path or identifier shown in the report.
/// * `summary`: Aggregate statistics over the commit set.
/// * `commits`: The commit records to render as table rows.
///
/// Usage:
/// ```ignore
/// let html = render_audit_html("2024-01-01T00:00:00Z", "org/repo", &summary, &commits);
/// std::fs::write("report.html", html)?;
/// ```
pub fn render_audit_html(
    generated_at: &str,
    repository: &str,
    summary: &AuditSummary,
    commits: &[CommitRecord],
) -> String {
    let signed_pct = if summary.total_commits > 0 {
        (summary.signed_commits as f64 / summary.total_commits as f64) * 100.0
    } else {
        0.0
    };

    let rows = commits
        .iter()
        .map(render_commit_row)
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; }}
        h1 {{ color: #1a1a1a; }}
        .summary {{ background: #f5f5f5; padding: 1rem; border-radius: 8px; margin: 1rem 0; }}
        .stat {{ display: inline-block; margin-right: 2rem; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #0066cc; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; }}
        .signed {{ color: #22c55e; }}
        .unsigned {{ color: #ef4444; }}
        .verified {{ color: #22c55e; }}
        .unverified {{ color: #f59e0b; }}
    </style>
</head>
<body>
    <h1>Audit Report</h1>
    <p>Generated: {generated_at}</p>
    <p>Repository: {repository}</p>

    <div class="summary">
        <div class="stat">
            <div class="stat-value">{total}</div>
            <div class="stat-label">Total Commits</div>
        </div>
        <div class="stat">
            <div class="stat-value signed">{signed}</div>
            <div class="stat-label">Signed ({signed_pct:.0}%)</div>
        </div>
        <div class="stat">
            <div class="stat-value unsigned">{unsigned}</div>
            <div class="stat-label">Unsigned</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Hash</th>
                <th>Date</th>
                <th>Author</th>
                <th>Message</th>
                <th>Method</th>
                <th>Verified</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"#,
        generated_at = html_escape::encode_text(generated_at),
        repository = html_escape::encode_text(repository),
        total = summary.total_commits,
        signed = summary.signed_commits,
        unsigned = summary.unsigned_commits,
        signed_pct = signed_pct,
        rows = rows,
    )
}

fn render_commit_row(c: &CommitRecord) -> String {
    let (signing_method, is_signed, is_verified) = classify_signature(&c.signature_status);
    let method_class = if is_signed { "signed" } else { "unsigned" };
    let verified_class = if is_verified {
        "verified"
    } else {
        "unverified"
    };
    let verified_text = if !is_signed {
        "-"
    } else if is_verified {
        "Yes"
    } else {
        "No"
    };
    let date = if c.timestamp.len() >= 10 {
        &c.timestamp[..10]
    } else {
        &c.timestamp
    };

    format!(
        r#"<tr>
                <td><code>{hash}</code></td>
                <td>{date}</td>
                <td>{author}</td>
                <td>{message}</td>
                <td class="{method_class}">{method}</td>
                <td class="{verified_class}">{verified}</td>
            </tr>"#,
        hash = html_escape::encode_text(&c.hash),
        date = html_escape::encode_text(date),
        author = html_escape::encode_text(&c.author_name),
        message = html_escape::encode_text(&c.message),
        method_class = method_class,
        method = html_escape::encode_text(signing_method),
        verified_class = verified_class,
        verified = verified_text,
    )
}

fn classify_signature(status: &SignatureStatus) -> (&'static str, bool, bool) {
    match status {
        SignatureStatus::AuthsSigned { .. } => ("auths", true, true),
        SignatureStatus::SshSigned => ("ssh", true, false),
        SignatureStatus::GpgSigned { verified } => ("gpg", true, *verified),
        SignatureStatus::Unsigned => ("none", false, false),
        SignatureStatus::InvalidSignature { .. } => ("invalid", true, false),
    }
}
