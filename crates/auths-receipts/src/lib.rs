//! # auths-receipts — accountability & dispute (Portfolio 1)
//!
//! The receipts domain over the `auths-evidence` trust core: dispute-evidence
//! assembly, the non-custodial escrow record + rule track, and the shared server
//! plumbing the three binaries (`auths-receipts-server`, `auths-escrow-server`,
//! `receipts-api`) mount. All trust logic lives in `auths-evidence`; this crate
//! adds domain workflows and presentation only.

pub mod dispute;
pub mod escrow;
pub mod exhibit;
pub mod reversal;
pub mod server;

#[cfg(feature = "api")]
pub mod api;
