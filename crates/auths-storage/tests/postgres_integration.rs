//! Integration tests for the Postgres registry backend.
//!
//! These run against the local Postgres at `127.0.0.1:5432`. The shared harness
//! (`postgres_cases::support`) self-provisions the `auths_registry_test`
//! database and isolates every test by a unique tenant id, so tests share one
//! schema without colliding. If Postgres cannot be reached the tests print a
//! clear skip and pass — but Postgres is expected to be up.

#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

mod postgres_cases;
