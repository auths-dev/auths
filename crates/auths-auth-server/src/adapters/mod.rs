//! Adapter implementations.

pub mod local_git_resolver;
pub mod memory_client_store;
pub mod memory_store;
pub mod registry_resolver;

pub use local_git_resolver::LocalGitResolver;
pub use memory_client_store::InMemoryClientStore;
pub use memory_store::InMemorySessionStore;
pub use registry_resolver::RegistryIdentityResolver;
