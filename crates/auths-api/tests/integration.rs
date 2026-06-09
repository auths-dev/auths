//! Integration tests for auths-api.
//!
//! The legacy bearer-token agent flow tests (provision → authorize → revoke) were
//! removed in Epic E along with the agent API. The relying-party middleware tests
//! (fn-153.9) exercise the HTTP contract over the SDK presentation surface.

#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

mod cases;
