//! Re-exports of agent types from `auths-core`.
//!
//! NOTE: SSH agent IPC uses Unix domain sockets — the underlying `auths-core::agent::client`
//! module is `#[cfg(unix)]`-gated. The re-exports below mirror that gate so the SDK
//! compiles on Windows. `AgentHandle` is cross-platform (no socket dependency) and
//! stays unconditionally exported.

pub use auths_core::AgentHandle;

#[cfg(unix)]
pub use auths_core::agent::{
    AgentStatus, add_identity, agent_sign, check_agent_status, remove_all_identities,
};
#[cfg(unix)]
pub use auths_core::api::start_agent_listener_with_handle;
