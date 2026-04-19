//! Integration-test entry point for `auths-pairing-protocol` (fn-129.T2).
//!
//! Mirrors `auths-keri/tests/integration.rs` + `auths-crypto/tests/integration.rs`
//! shape per the CLAUDE.md "Writing Tests" convention. Submodules land under
//! `tests/cases/*.rs`; T3/T6/T7/T9 register their cases in `cases/mod.rs`.

#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

mod cases;
