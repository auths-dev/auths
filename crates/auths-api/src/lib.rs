//! Auths API Server — thin HTTP presentation layer.
//!
//! The legacy bearer-token agent API (`/v1/agents`, Redis sessions, in-memory
//! `AgentRegistry`) was removed in Epic E: the real agent surface is the SDK/CLI
//! (`auths id agent …`, agents as KERI `dip`-delegated identifiers). This crate is
//! currently a minimal server skeleton exposing only a health check; domain routes
//! will be (re)mounted over the SDK as an HTTP surface is needed (tracked in E.9).

pub mod app;
pub mod error;

#[path = "middleware.rs"]
pub mod middleware;

pub use app::{build_router, AppState};
pub use error::ApiError;
