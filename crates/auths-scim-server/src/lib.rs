//! SCIM 2.0 provisioning server for Auths agent identities.
//!
//! Provides HTTP endpoints for IdP-driven lifecycle management of agent
//! identities via the SCIM protocol (RFC 7643/7644).

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;
