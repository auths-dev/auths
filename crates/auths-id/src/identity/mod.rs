pub mod events;
pub mod helpers;
#[cfg(feature = "git-storage")]
pub mod initialize;
pub mod managed;
#[cfg(feature = "git-storage")]
pub mod resolve;
#[cfg(feature = "git-storage")]
pub mod rotate;

#[cfg(feature = "git-storage")]
pub use resolve::{DefaultDidResolver, DidResolver, DidResolverError, ResolvedDid};
