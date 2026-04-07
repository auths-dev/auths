//! PostgreSQL storage adapter (stub).
//!
//! Every method returns `RegistryError::NotImplemented` — no panics. This
//! stub exists so that the feature flag compiles and the composition root
//! can be written before the implementation is complete.

use std::ops::ControlFlow;

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::ports::registry::{
    OrgMemberEntry, RegistryBackend, RegistryError, RegistryMetadata, TipInfo,
};
use auths_keri::Prefix;
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;

/// PostgreSQL-backed registry storage (stub).
///
/// All methods return `RegistryError::NotImplemented` until the implementation
/// is complete. Wire this at the composition root via `Arc<dyn RegistryBackend>`.
///
/// Usage:
/// ```rust,ignore
/// use std::sync::Arc;
/// use auths_id::ports::RegistryBackend;
/// use auths_storage::postgres::PostgresAdapter;
///
/// let backend: Arc<dyn RegistryBackend + Send + Sync> =
///     Arc::new(PostgresAdapter::new(pool));
/// ```
pub struct PostgresAdapter;

impl PostgresAdapter {
    /// Create a new `PostgresAdapter`.
    ///
    /// Args:
    /// * `_pool` — `sqlx::PgPool` (reserved for future implementation)
    pub fn new(_pool: ()) -> Self {
        Self
    }
}

impl RegistryBackend for PostgresAdapter {
    fn append_event(&self, _prefix: &Prefix, _event: &Event) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "append_event",
        })
    }

    fn get_event(&self, _prefix: &Prefix, _seq: u64) -> Result<Event, RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "get_event",
        })
    }

    fn visit_events(
        &self,
        _prefix: &Prefix,
        _from_seq: u64,
        _visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "visit_events",
        })
    }

    fn get_tip(&self, _prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        Err(RegistryError::NotImplemented { method: "get_tip" })
    }

    fn get_key_state(&self, _prefix: &Prefix) -> Result<KeyState, RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "get_key_state",
        })
    }

    fn write_key_state(&self, _prefix: &Prefix, _state: &KeyState) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "write_key_state",
        })
    }

    fn visit_identities(
        &self,
        _visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "visit_identities",
        })
    }

    fn store_attestation(&self, _attestation: &Attestation) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "store_attestation",
        })
    }

    fn load_attestation(&self, _did: &DeviceDID) -> Result<Option<Attestation>, RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "load_attestation",
        })
    }

    fn visit_attestation_history(
        &self,
        _did: &DeviceDID,
        _visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "visit_attestation_history",
        })
    }

    fn visit_devices(
        &self,
        _visitor: &mut dyn FnMut(&DeviceDID) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "visit_devices",
        })
    }

    fn store_org_member(&self, _org: &str, _member: &Attestation) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "store_org_member",
        })
    }

    fn visit_org_member_attestations(
        &self,
        _org: &str,
        _visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "visit_org_member_attestations",
        })
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        Err(RegistryError::NotImplemented {
            method: "init_if_needed",
        })
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        Err(RegistryError::NotImplemented { method: "metadata" })
    }
}
