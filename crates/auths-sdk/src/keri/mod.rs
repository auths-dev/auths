//! Re-exports of KERI cache module from `auths-id`, plus SDK-level
//! copy constants that both the CLI and mobile surfaces consume.

pub mod copy;
/// KEL resolver orchestration (local-first, optional git-remote). Requires the
/// git registry, so it is gated on `backend-git`.
#[cfg(feature = "backend-git")]
pub mod resolver;

pub use auths_id::keri::cache;
pub use auths_id::keri::parse_did_keri;
pub use auths_id::keri::shared_kel::{
    ControllerDescriptor, SharedKelChange, SharedKelError, apply_shared_kel_change,
    incept_shared_kel_prepared, resolve_controller_index, rot_add_controller,
    rot_remove_controller, rot_swap_controller,
};
pub use auths_id::keri::try_stage_anchor;
pub use auths_id::storage::keri::KeriGitStorage;
pub use auths_id::storage::registry::backend::AtomicWriteBatch;
#[cfg(feature = "backend-git")]
pub use resolver::KelResolverChain;
