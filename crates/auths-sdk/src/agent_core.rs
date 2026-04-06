//! Re-exports of agent types from `auths-core`.

pub use auths_core::AgentHandle;
pub use auths_core::agent::{
    AgentStatus, add_identity, agent_sign, check_agent_status, remove_all_identities,
};
pub use auths_core::api::start_agent_listener_with_handle;
