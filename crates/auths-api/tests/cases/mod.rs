//! Integration test cases.
//!
//! The legacy bearer-token agent flow tests were removed in Epic E. The relying-party
//! middleware tests (rp_auth) and the control-plane HTTP tests
//! (`../control_plane_http.rs`) exercise the current surface over the SDK.

mod rp_auth;
