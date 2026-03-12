// Build tooling — env::var access is expected.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod ci_setup;
mod gen_docs;
mod gen_error_docs;
mod gen_schema;
mod schemas;
mod shell;
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
    /// One-time setup: create a CI release-signing device and set GitHub secrets
    CiSetup,
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
        Command::CiSetup => ci_setup::run(),
        Command::GenSchema => gen_schema::run(workspace_root()),
        Command::GenDocs { check } => gen_docs::run(workspace_root(), check),
        Command::GenerateSchemas => schemas::generate(workspace_root()),
        Command::ValidateSchemas => schemas::validate(workspace_root()),
        Command::GenErrorDocs { check } => gen_error_docs::run(workspace_root(), check),
        Command::TestIntegration { filter } => test_integration::run(filter.as_deref()),
    }
}
