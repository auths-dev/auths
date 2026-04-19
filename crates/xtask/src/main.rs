// Build tooling — env::var access is expected.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod check_anchor_discipline;
mod check_clippy_sync;
mod check_constant_time;
mod check_curve_agnostic;
mod check_rfc6979;
mod gen_docs;
mod gen_error_docs;
mod gen_schema;
mod schemas;
mod test_integration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Auths project-internal build/CI tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate docs/cloud-ci/telemetry/schema.json and schema.md from AuditEvent
    GenSchema,
    /// Regenerate CLI flag tables in docs from `auths --help` output.
    /// Pass `--check` to fail if any table is out of date (CI gate).
    GenDocs {
        /// Fail instead of writing if any doc is stale (CI mode).
        #[arg(long)]
        check: bool,
    },
    /// Generate JSON Schema files from Rust contract types into schemas/
    GenerateSchemas,
    /// Validate test fixture JSON files against committed schemas
    ValidateSchemas,
    /// Regenerate error code docs and CLI registry from `AuthsErrorInfo` impls.
    /// Pass `--check` to fail if any output is stale (CI gate).
    GenErrorDocs {
        /// Fail instead of writing if any output is stale (CI mode).
        #[arg(long)]
        check: bool,
    },
    /// Run CLI integration tests with environment isolation.
    TestIntegration {
        /// Run only tests matching this filter expression.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Check that crate-level clippy.toml files contain all workspace-root rules.
    CheckClippySync,
    /// AST-level curve-agnostic enforcement via tree-sitter.
    /// Scans production code for curve-specific names outside auths-crypto.
    CheckCurveAgnostic,
    /// Anchor discipline enforcement via tree-sitter.
    /// Bans direct store_attestation/store_org_member/load_all_attestations in
    /// SDK domains and CLI commands.
    CheckAnchorDiscipline,
    /// Constant-time comparison enforcement via tree-sitter.
    /// Bans == on .as_bytes() in production code (use subtle::ct_eq instead).
    CheckConstantTime,
    /// RFC 6979 deterministic-ECDSA enforcement via tree-sitter.
    /// Bans `sign_with_rng`, `sign_digest_with_rng`, etc. in production.
    CheckRfc6979,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let workspace_root = || {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent() // crates/
            .and_then(|p| p.parent()) // workspace root
            .expect("could not determine workspace root")
    };
    match cli.command {
        Command::GenSchema => gen_schema::run(workspace_root()),
        Command::GenDocs { check } => gen_docs::run(workspace_root(), check),
        Command::GenerateSchemas => schemas::generate(workspace_root()),
        Command::ValidateSchemas => schemas::validate(workspace_root()),
        Command::GenErrorDocs { check } => gen_error_docs::run(workspace_root(), check),
        Command::TestIntegration { filter } => test_integration::run(filter.as_deref()),
        Command::CheckClippySync => check_clippy_sync::run(workspace_root()),
        Command::CheckCurveAgnostic => check_curve_agnostic::run(workspace_root()),
        Command::CheckAnchorDiscipline => check_anchor_discipline::run(workspace_root()),
        Command::CheckConstantTime => check_constant_time::run(workspace_root()),
        Command::CheckRfc6979 => check_rfc6979::run(workspace_root()),
    }
}
