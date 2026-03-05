//! Adapter that converts OIDC bridge claims into policy evaluation contexts.
//!
//! This module bridges the gap between the OIDC bridge's `OidcClaims` and
//! the policy engine's `EvalContext`, enabling workload authorization policies
//! to gate token exchange.
