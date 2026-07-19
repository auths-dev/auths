//! Integration entry point for `auths-anchor`.
//!
//! The test cases live under `cases/`. `cases/invariants.rs` turns the AWN
//! Appendix A invariants into named tests (E4): the test name is the invariant,
//! the body is the adversarial "what input would violate this?" answer.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

mod cases;
