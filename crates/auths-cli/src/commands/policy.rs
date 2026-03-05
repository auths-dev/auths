//! Policy governance commands for Auths.
//!
//! Commands for linting, compiling, testing, and comparing policies.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Context, Result, anyhow};
use auths_policy::{
    CompileError, CompiledExpr, EvalContext, Expr, Outcome, PolicyLimits,
    compile_from_json_with_limits,
};
use auths_sdk::workflows::policy_diff::{compute_policy_diff, overall_risk_score};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Manage authorization policies.
#[derive(Parser, Debug, Clone)]
#[command(name = "policy", about = "Manage authorization policies")]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: PolicySubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PolicySubcommand {
    /// Validate policy JSON syntax without full compilation.
    Lint(LintCommand),

    /// Compile a policy file with full validation.
    Compile(CompileCommand),

    /// Evaluate a policy against a context and show the decision.
    Explain(ExplainCommand),

    /// Run a policy against a test suite.
    Test(TestCommand),

    /// Compare two policies and show semantic differences.
    Diff(DiffCommand),
}

/// Validate policy JSON syntax.
#[derive(Parser, Debug, Clone)]
pub struct LintCommand {
    /// Path to the policy file (JSON).
    pub file: PathBuf,
}

/// Compile a policy with full validation.
#[derive(Parser, Debug, Clone)]
pub struct CompileCommand {
    /// Path to the policy file (JSON).
    pub file: PathBuf,
}

/// Evaluate a policy against a context.
#[derive(Parser, Debug, Clone)]
pub struct ExplainCommand {
    /// Path to the policy file (JSON).
    pub file: PathBuf,

    /// Path to the context file (JSON).
    #[clap(long, short = 'c')]
    pub context: PathBuf,
}

/// Run a policy against a test suite.
#[derive(Parser, Debug, Clone)]
pub struct TestCommand {
    /// Path to the policy file (JSON).
    pub file: PathBuf,

    /// Path to the test suite file (JSON).
    #[clap(long, short = 't')]
    pub tests: PathBuf,
}

/// Compare two policies.
#[derive(Parser, Debug, Clone)]
pub struct DiffCommand {
    /// Path to the old policy file (JSON).
    pub old: PathBuf,

    /// Path to the new policy file (JSON).
    pub new: PathBuf,
}

// ── JSON Output Types ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct LintData {
    bytes: usize,
    byte_limit: usize,
}

#[derive(Debug, Serialize)]
struct CompileData {
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExplainOutput {
    decision: String,
    reason_code: String,
    message: String,
    policy_hash: String,
}

#[derive(Debug, Serialize)]
struct TestOutput {
    passed: usize,
    failed: usize,
    total: usize,
    results: Vec<TestResult>,
}

#[derive(Debug, Serialize)]
struct TestResult {
    name: String,
    passed: bool,
    expected: String,
    actual: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct DiffOutput {
    changes: Vec<DiffChange>,
    risk_score: String,
}

#[derive(Debug, Serialize)]
struct DiffChange {
    kind: String,
    description: String,
    risk: String,
}

// ── Test Suite Types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    context: TestContext,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct TestContext {
    issuer: String,
    subject: String,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    chain_depth: u32,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    git_ref: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    environment: Option<String>,
}

// ── Handler ─────────────────────────────────────────────────────────────

pub fn handle_policy(cmd: PolicyCommand) -> Result<()> {
    match cmd.command {
        PolicySubcommand::Lint(lint) => handle_lint(lint),
        PolicySubcommand::Compile(compile) => handle_compile(compile),
        PolicySubcommand::Explain(explain) => handle_explain(explain),
        PolicySubcommand::Test(test) => handle_test(test),
        PolicySubcommand::Diff(diff) => handle_diff(diff),
    }
}

fn handle_lint(cmd: LintCommand) -> Result<()> {
    let out = Output::new();
    let limits = PolicyLimits::default();

    // Read the file
    let content =
        fs::read(&cmd.file).with_context(|| format!("failed to read {}", cmd.file.display()))?;

    let bytes = content.len();

    // Check size limit
    if bytes > limits.max_json_bytes {
        if is_json_mode() {
            JsonResponse::<()>::error(
                "policy lint",
                format!(
                    "file exceeds size limit: {} > {}",
                    bytes, limits.max_json_bytes
                ),
            )
            .print()?;
        } else {
            out.println(&format!(
                "{} File exceeds size limit: {} bytes (limit: {})",
                out.error("x"),
                bytes,
                limits.max_json_bytes
            ));
        }
        anyhow::bail!(
            "file exceeds size limit: {} > {}",
            bytes,
            limits.max_json_bytes
        );
    }

    // Parse JSON
    match serde_json::from_slice::<Expr>(&content) {
        Ok(_expr) => {
            if is_json_mode() {
                JsonResponse::success(
                    "policy lint",
                    LintData {
                        bytes,
                        byte_limit: limits.max_json_bytes,
                    },
                )
                .print()?;
            } else {
                out.println(&format!("{} Valid JSON", out.success("ok")));
                out.println(&format!("{} All ops recognized", out.success("ok")));
                out.println(&format!(
                    "{} {} bytes (limit: {})",
                    out.success("ok"),
                    bytes,
                    limits.max_json_bytes
                ));
            }
        }
        Err(e) => {
            if is_json_mode() {
                JsonResponse::<()>::error("policy lint", e.to_string()).print()?;
            } else {
                out.println(&format!("{} Invalid JSON: {}", out.error("x"), e));
            }
            anyhow::bail!("lint failed: {}", e);
        }
    }

    Ok(())
}

fn handle_compile(cmd: CompileCommand) -> Result<()> {
    let out = Output::new();
    let limits = PolicyLimits::default();

    let content =
        fs::read(&cmd.file).with_context(|| format!("failed to read {}", cmd.file.display()))?;

    match compile_from_json_with_limits(&content, &limits) {
        Ok(policy) => {
            let stats = compute_policy_stats(policy.expr());
            let hash = hex::encode(policy.source_hash());

            if is_json_mode() {
                JsonResponse::success(
                    "policy compile",
                    CompileData {
                        nodes: Some(stats.nodes),
                        depth: Some(stats.depth),
                        hash: Some(hash),
                        errors: vec![],
                    },
                )
                .print()?;
            } else {
                out.println(&format!("{} Compiled successfully", out.success("ok")));
                out.println(&format!(
                    "  Nodes: {} (limit: {})",
                    stats.nodes, limits.max_total_nodes
                ));
                out.println(&format!(
                    "  Depth: {} (limit: {})",
                    stats.depth, limits.max_depth
                ));
                out.println(&format!("  Hash:  {}", hash));
            }
        }
        Err(errors) => {
            let error_strs: Vec<String> = errors.iter().map(format_compile_error).collect();

            if is_json_mode() {
                JsonResponse {
                    success: false,
                    command: "policy compile".to_string(),
                    data: Some(CompileData {
                        nodes: None,
                        depth: None,
                        hash: None,
                        errors: error_strs,
                    }),
                    error: None,
                }
                .print()?;
            } else {
                out.println(&format!(
                    "{} Compilation failed ({} errors):",
                    out.error("x"),
                    errors.len()
                ));
                for error in &error_strs {
                    out.println(&format!("  {}", error));
                }
            }
        }
    }

    Ok(())
}

fn handle_explain(cmd: ExplainCommand) -> Result<()> {
    let out = Output::new();
    let limits = PolicyLimits::default();

    // Load and compile policy
    let policy_content = fs::read(&cmd.file)
        .with_context(|| format!("failed to read policy: {}", cmd.file.display()))?;

    let policy = compile_from_json_with_limits(&policy_content, &limits).map_err(|errors| {
        anyhow!(
            "policy compilation failed: {}",
            errors
                .iter()
                .map(format_compile_error)
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;

    // Load context
    let ctx_content = fs::read(&cmd.context)
        .with_context(|| format!("failed to read context: {}", cmd.context.display()))?;

    let test_ctx: TestContext =
        serde_json::from_slice(&ctx_content).with_context(|| "failed to parse context JSON")?;

    let eval_ctx = build_eval_context(&test_ctx)?;

    // Evaluate
    let decision = auths_policy::evaluate3(&policy, &eval_ctx);
    let hash = hex::encode(policy.source_hash());

    if is_json_mode() {
        JsonResponse::success(
            "policy explain",
            ExplainOutput {
                decision: format!("{:?}", decision.outcome),
                reason_code: format!("{:?}", decision.reason),
                message: decision.message.clone(),
                policy_hash: hash,
            },
        )
        .print()?;
    } else {
        let decision_str = match decision.outcome {
            Outcome::Allow => out.success("ALLOW"),
            Outcome::Deny => out.error("DENY"),
            Outcome::Indeterminate => out.warn("INDETERMINATE"),
        };
        out.println(&format!("Decision: {}", decision_str));
        out.println(&format!("  Reason: {:?}", decision.reason));
        out.println(&format!("  Message: {}", decision.message));
        out.println(&format!("Policy hash: {}", hash));
    }

    Ok(())
}

fn handle_test(cmd: TestCommand) -> Result<()> {
    let out = Output::new();
    let limits = PolicyLimits::default();

    // Load and compile policy
    let policy_content = fs::read(&cmd.file)
        .with_context(|| format!("failed to read policy: {}", cmd.file.display()))?;

    let policy = compile_from_json_with_limits(&policy_content, &limits).map_err(|errors| {
        anyhow!(
            "policy compilation failed: {}",
            errors
                .iter()
                .map(format_compile_error)
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;

    // Load test suite
    let tests_content = fs::read(&cmd.tests)
        .with_context(|| format!("failed to read tests: {}", cmd.tests.display()))?;

    let test_cases: Vec<TestCase> = serde_json::from_slice(&tests_content)
        .with_context(|| "failed to parse test suite JSON")?;

    let mut results: Vec<TestResult> = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    for test in test_cases {
        let eval_ctx = match build_eval_context(&test.context) {
            Ok(ctx) => ctx,
            Err(e) => {
                results.push(TestResult {
                    name: test.name.clone(),
                    passed: false,
                    expected: test.expect.clone(),
                    actual: "ERROR".into(),
                    message: Some(e.to_string()),
                });
                failed += 1;
                continue;
            }
        };

        let decision = auths_policy::evaluate3(&policy, &eval_ctx);
        let actual = format!("{:?}", decision.outcome);
        let expected_normalized = normalize_outcome(&test.expect);
        let test_passed = actual == expected_normalized;

        if test_passed {
            passed += 1;
        } else {
            failed += 1;
        }

        results.push(TestResult {
            name: test.name,
            passed: test_passed,
            expected: expected_normalized,
            actual,
            message: if test_passed {
                None
            } else {
                Some(decision.message.clone())
            },
        });
    }

    let total = passed + failed;

    if is_json_mode() {
        JsonResponse::success(
            "policy test",
            TestOutput {
                passed,
                failed,
                total,
                results,
            },
        )
        .print()?;
    } else {
        for result in &results {
            let status = if result.passed {
                out.success("ok")
            } else {
                out.error("FAIL")
            };
            out.println(&format!(
                "  {} {}: {} (expected {})",
                status, result.name, result.actual, result.expected
            ));
            if let Some(msg) = &result.message {
                out.println(&format!("      {}", out.dim(msg)));
            }
        }
        out.println(&format!("{}/{} passed", passed, total));
    }

    if failed > 0 {
        anyhow::bail!("{} test(s) failed", failed);
    }

    Ok(())
}

fn handle_diff(cmd: DiffCommand) -> Result<()> {
    let out = Output::new();

    // Parse both policy files (don't need full compilation for structural diff)
    let old_content = fs::read(&cmd.old)
        .with_context(|| format!("failed to read old policy: {}", cmd.old.display()))?;
    let new_content = fs::read(&cmd.new)
        .with_context(|| format!("failed to read new policy: {}", cmd.new.display()))?;

    let old_expr: Expr =
        serde_json::from_slice(&old_content).with_context(|| "failed to parse old policy JSON")?;
    let new_expr: Expr =
        serde_json::from_slice(&new_content).with_context(|| "failed to parse new policy JSON")?;

    let changes = compute_policy_diff(&old_expr, &new_expr);
    let risk_score = overall_risk_score(&changes);

    if is_json_mode() {
        JsonResponse::success(
            "policy diff",
            DiffOutput {
                changes: changes
                    .iter()
                    .map(|c| DiffChange {
                        kind: c.kind.clone(),
                        description: c.description.clone(),
                        risk: c.risk.clone(),
                    })
                    .collect(),
                risk_score: risk_score.clone(),
            },
        )
        .print()?;
    } else if changes.is_empty() {
        out.println("No changes detected");
    } else {
        out.println("Changes:");
        for change in &changes {
            let risk_marker = match change.risk.as_str() {
                "HIGH" => out.error("HIGH RISK"),
                "MEDIUM" => out.warn("MEDIUM"),
                _ => out.dim("LOW"),
            };
            let kind_marker = match change.kind.as_str() {
                "added" => "+",
                "removed" => "-",
                "changed" => "~",
                _ => "?",
            };
            out.println(&format!(
                "  {} {}: {} [{}]",
                kind_marker, change.description, risk_marker, change.risk
            ));
        }
        out.println("");
        let risk_display = match risk_score.as_str() {
            "HIGH" => out.error(&risk_score),
            "MEDIUM" => out.warn(&risk_score),
            _ => out.dim(&risk_score),
        };
        out.println(&format!("Risk score: {}", risk_display));
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn format_compile_error(error: &CompileError) -> String {
    format!("at {}: {}", error.path, error.message)
}

struct PolicyStats {
    nodes: u32,
    depth: u32,
}

fn compute_policy_stats(expr: &CompiledExpr) -> PolicyStats {
    fn count_nodes(expr: &CompiledExpr) -> u32 {
        match expr {
            CompiledExpr::True | CompiledExpr::False => 1,
            CompiledExpr::And(children) | CompiledExpr::Or(children) => {
                1 + children.iter().map(count_nodes).sum::<u32>()
            }
            CompiledExpr::Not(inner) => 1 + count_nodes(inner),
            _ => 1,
        }
    }

    fn compute_depth(expr: &CompiledExpr) -> u32 {
        match expr {
            CompiledExpr::True | CompiledExpr::False => 1,
            CompiledExpr::And(children) | CompiledExpr::Or(children) => {
                1 + children.iter().map(compute_depth).max().unwrap_or(0)
            }
            CompiledExpr::Not(inner) => 1 + compute_depth(inner),
            _ => 1,
        }
    }

    PolicyStats {
        nodes: count_nodes(expr),
        depth: compute_depth(expr),
    }
}

fn build_eval_context(test: &TestContext) -> Result<EvalContext> {
    let mut ctx = EvalContext::try_from_strings(Utc::now(), &test.issuer, &test.subject)
        .map_err(|e| anyhow!("invalid DID: {}", e))?;

    ctx = ctx.revoked(test.revoked);
    ctx = ctx.chain_depth(test.chain_depth);

    for cap in &test.capabilities {
        let canonical = auths_policy::CanonicalCapability::parse(cap)
            .map_err(|e| anyhow!("invalid capability '{}': {}", cap, e))?;
        ctx = ctx.capability(canonical);
    }

    if let Some(role) = &test.role {
        ctx = ctx.role(role.clone());
    }

    if let Some(exp) = test.expires_at {
        ctx = ctx.expires_at(exp);
    }

    if let Some(ts) = test.timestamp {
        ctx = ctx.timestamp(ts);
    }

    if let Some(repo) = &test.repo {
        ctx = ctx.repo(repo.clone());
    }

    if let Some(git_ref) = &test.git_ref {
        ctx = ctx.git_ref(git_ref.clone());
    }

    if !test.paths.is_empty() {
        ctx = ctx.paths(test.paths.clone());
    }

    if let Some(env) = &test.environment {
        ctx = ctx.environment(env.clone());
    }

    Ok(ctx)
}

fn normalize_outcome(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "allow" => "Allow".into(),
        "deny" => "Deny".into(),
        "indeterminate" => "Indeterminate".into(),
        _ => s.to_string(),
    }
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for PolicyCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_policy(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_sdk::workflows::policy_diff::{
        PolicyChange, compute_policy_diff, overall_risk_score,
    };

    #[test]
    fn test_normalize_outcome() {
        assert_eq!(normalize_outcome("allow"), "Allow");
        assert_eq!(normalize_outcome("Allow"), "Allow");
        assert_eq!(normalize_outcome("ALLOW"), "Allow");
        assert_eq!(normalize_outcome("deny"), "Deny");
        assert_eq!(normalize_outcome("Deny"), "Deny");
        assert_eq!(normalize_outcome("indeterminate"), "Indeterminate");
    }

    #[test]
    fn test_overall_risk_score() {
        let high = vec![PolicyChange {
            kind: "removed".into(),
            description: "NotRevoked".into(),
            risk: "HIGH".into(),
        }];
        assert_eq!(overall_risk_score(&high), "HIGH");

        let medium = vec![PolicyChange {
            kind: "added".into(),
            description: "HasCapability(sign)".into(),
            risk: "MEDIUM".into(),
        }];
        assert_eq!(overall_risk_score(&medium), "MEDIUM");

        let low = vec![PolicyChange {
            kind: "added".into(),
            description: "RepoIs(org/repo)".into(),
            risk: "LOW".into(),
        }];
        assert_eq!(overall_risk_score(&low), "LOW");

        assert_eq!(overall_risk_score(&[]), "LOW");
    }

    #[test]
    fn test_collect_predicates_via_diff() {
        let old = Expr::And(vec![Expr::NotRevoked, Expr::HasCapability("sign".into())]);
        let new = Expr::And(vec![Expr::NotRevoked]);
        let changes = compute_policy_diff(&old, &new);
        assert!(
            changes
                .iter()
                .any(|c| c.description.contains("HasCapability") && c.kind == "removed")
        );
    }

    #[test]
    fn test_structural_change_and_to_or() {
        let old = Expr::And(vec![Expr::True]);
        let new = Expr::Or(vec![Expr::True]);
        let changes = compute_policy_diff(&old, &new);
        let structural = changes.iter().find(|c| c.kind == "changed");
        assert!(structural.is_some());
        assert_eq!(structural.unwrap().risk, "HIGH");
    }
}
