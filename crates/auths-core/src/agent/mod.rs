//! Agent runtime and IPC.

// IMPORTANT: client.rs uses std::os::unix::net::UnixStream throughout and is
// fundamentally Unix-only. Do NOT remove this #[cfg(unix)] gate — it will break
// the Windows CI build.
#[cfg(unix)]
pub mod client;
mod core;
mod handle;
mod session;

#[cfg(unix)]
pub use client::{
    AgentStatus, add_identity, agent_sign, check_agent_status, list_identities,
    remove_all_identities,
};
pub use core::AgentCore;
pub use handle::{AgentHandle, DEFAULT_IDLE_TIMEOUT};
pub use session::AgentSession;
