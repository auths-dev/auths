pub mod events;
#[cfg(feature = "git-storage")]
pub mod helpers;
#[cfg(feature = "git-storage")]
pub mod initialize;
#[cfg(feature = "git-storage")]
pub mod resolve;
#[cfg(feature = "git-storage")]
pub mod rotate;

#[cfg(feature = "git-storage")]
pub use resolve::{
    DefaultDidResolver, DidMethod, DidResolver, DidResolverError, ResolvedDid, did_key_to_ed25519,
    ed25519_to_did_key,
};
