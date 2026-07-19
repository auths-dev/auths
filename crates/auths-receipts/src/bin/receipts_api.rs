// CLI process boundary: environment configuration and the wall clock are read
// here and injected down — the sanctioned boundary allowances every auths binary takes.
#![allow(clippy::print_stderr, clippy::print_stdout, clippy::disallowed_methods)]

//! # receipts-api — the enterprise retainer HTTP surface (plan RC-E3.3)
//!
//! A thin, stateless-per-request axum service over the same `auths-evidence`
//! core the MCP tools call. Subcommands: `serve` (the API), `accounts create`,
//! `keys issue`, `keys revoke`, `billing rollup`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("receipts-api: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(auths_receipts::api::cli::run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("receipts-api: {e}");
            ExitCode::FAILURE
        }
    }
}
