//! Integration tests for auths-api.
//!
//! The legacy bearer-token agent flow tests (provision → authorize → revoke) were
//! removed in Epic E along with the agent API. The crate is currently a health-only
//! skeleton; HTTP-flow tests return when a domain surface is mounted over the SDK.

mod cases;
