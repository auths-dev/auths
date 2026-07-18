//! PostgreSQL storage backend.
//!
//! A concurrent implementation of the `RegistryBackend` port. See
//! [`adapter::PostgresAdapter`] for the concurrency model and semantics.

mod adapter;
mod schema;

pub use adapter::{DEFAULT_TENANT, PostgresAdapter};
pub use schema::{MIGRATION_SQL, create_database_if_absent};
