//! Integration test cases.
//!
//! The legacy bearer-token agent flow tests were removed in Epic E. The relying-party
//! middleware tests (rp_auth) and the control-plane HTTP tests (control_plane_http)
//! exercise the current surface over the SDK.

mod control_plane_http;
mod rp_auth;
