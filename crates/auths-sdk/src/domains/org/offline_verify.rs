//! Offline verification of an air-gapped org bundle — re-exported from
//! [`auths_verifier::org_bundle`].
//!
//! The verification core is pure and network-free, so it lives in the leaf
//! verifier crate where every surface (native CLI, FFI, browser WASM) shares
//! one implementation. This module re-exports it for SDK callers; the bundle
//! *builder* (which walks a live registry) is in
//! [`crate::domains::org::bundle`].

pub use auths_verifier::org_bundle::{
    OfflineVerifyReport, OrgBundleError, authenticate_bundled_kel, classify_authority_in_bundle,
    verify_org_bundle,
};
