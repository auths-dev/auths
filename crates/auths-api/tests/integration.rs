//! Integration tests for auths-api
//!
//! Tests the full HTTP flow: provision → authorize → revoke
//! Starts a real server and makes HTTP requests to verify the API works end-to-end.

mod cases;

pub use cases::*;
