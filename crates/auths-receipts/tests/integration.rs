// Test binary: unwrap/expect and boundary allowances are the repo's sanctioned
// test-code exemptions (clippy.toml allow-unwrap-in-tests does not reach
// integration-test helper fns).
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

//! Integration-test entry point (single binary; cases under `tests/cases/`).

mod cases;
