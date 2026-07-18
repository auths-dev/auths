//! PostgreSQL registry backend.
//!
//! A complete, concurrent implementation of the [`RegistryBackend`] port that
//! reproduces the observable semantics of the single-writer
//! [`crate::git::GitRegistryBackend`] — append-only per-prefix KEL logs,
//! monotonic key-state, device-attestation history, org members, and tenant
//! metadata — **without** a global lock.
//!
//! # Concurrency model
//!
//! The git backend takes an exclusive `registry.lock` across every write and a
//! CAS on one ref, so concurrent onboarding of *different* identities serializes
//! (the wall the performance study hit — see
//! `docs/plans/storage/registry-backend-decision.md` and
//! `tests/performance/FINDINGS.md` §6). This backend instead pushes safety into
//! SQL constraints:
//!
//! - `registry_events` has `PRIMARY KEY (tenant, prefix, seq)`. Two writers
//!   racing the same sequence number → exactly one `INSERT` wins; the other hits
//!   a unique violation, mapped to [`RegistryError::EventExists`] — the same
//!   observable "loser aborts" outcome as the git CAS. Writers to *different*
//!   identities touch different rows and never contend.
//! - `registry_key_state` advances forward only; the append path and
//!   [`RegistryBackend::write_key_state`] both guard the update so a stored
//!   key-state can never roll back to a lower sequence.
//!
//! Each mutation runs in its own transaction, validated against the same
//! constraint set the git backend enforces (`validate_append`).
//!
//! # Async bridge
//!
//! The [`RegistryBackend`] trait is synchronous but `sqlx` is async, so the
//! adapter owns a multi-threaded Tokio runtime and drives each query to
//! completion via [`PostgresAdapter::block_on`]. Read-side visitor methods fetch
//! owned rows inside the async block, then invoke the caller's (synchronous)
//! visitor outside it — keeping the futures `Send` and the visitor free of any
//! runtime coupling.

use std::ops::ControlFlow;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use auths_core::storage::keychain::IdentityDID;
use auths_verifier::clock::{ClockProvider, SystemClock};
use auths_verifier::core::Attestation;
use auths_verifier::types::CanonicalDid;

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::keri::validate::{ValidationError, verify_event_crypto, verify_event_said};
use auths_id::ports::registry::{
    OrgMemberEntry, RegistryBackend, RegistryError, RegistryMetadata, TipInfo, ValidatedTenantId,
};
use auths_id::storage::registry::org_member::{MemberInvalidReason, expected_org_issuer};
use auths_keri::{Prefix, Said};

use super::schema::apply_migrations;

/// Tenant key used in single-tenant mode (when no [`ValidatedTenantId`] is set).
pub const DEFAULT_TENANT: &str = "default";

/// Default connection-pool ceiling. Sized for concurrent onboarding fan-out;
/// each in-flight append/read holds one connection for the life of its query.
const MAX_CONNECTIONS: u32 = 32;

/// Current tip + cached key-state for one identity, loaded for validation.
struct CurrentState {
    sequence: u128,
    said: String,
    state: KeyState,
}

/// PostgreSQL-backed registry storage.
///
/// Holds a real [`sqlx::PgPool`] plus an owned Tokio runtime used to drive the
/// async queries from the synchronous [`RegistryBackend`] surface. Clone is
/// cheap — the pool and runtime are shared behind reference counts — so the same
/// backend can be handed to many threads for concurrent writes.
///
/// Usage:
/// ```rust,ignore
/// use std::sync::Arc;
/// use auths_id::ports::RegistryBackend;
/// use auths_storage::postgres::PostgresAdapter;
///
/// let backend = PostgresAdapter::connect("postgres://localhost/auths_registry")?;
/// backend.init_if_needed()?;
/// let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(backend);
/// ```
#[derive(Clone)]
pub struct PostgresAdapter {
    pool: PgPool,
    runtime: Arc<tokio::runtime::Runtime>,
    /// Canonical tenant ID, or `None` in single-tenant mode.
    tenant: Option<String>,
    /// Clock provider — injected so callers/tests control time (no `Utc::now()`).
    clock: Arc<dyn ClockProvider>,
}

impl PostgresAdapter {
    /// Connect to a database (single-tenant) and run schema migrations.
    ///
    /// Args:
    /// * `database_url`: A `postgres://…` connection URL.
    ///
    /// Usage:
    /// ```ignore
    /// let backend = PostgresAdapter::connect("postgres://localhost/auths_registry")?;
    /// ```
    pub fn connect(database_url: &str) -> Result<Self, RegistryError> {
        Self::connect_inner(database_url, None)
    }

    /// Connect to a database for a specific tenant and run schema migrations.
    ///
    /// Args:
    /// * `database_url`: A `postgres://…` connection URL.
    /// * `tenant`: The validated tenant whose rows this backend reads and writes.
    pub fn connect_for_tenant(
        database_url: &str,
        tenant: ValidatedTenantId,
    ) -> Result<Self, RegistryError> {
        Self::connect_inner(database_url, Some(tenant))
    }

    fn connect_inner(
        database_url: &str,
        tenant: Option<ValidatedTenantId>,
    ) -> Result<Self, RegistryError> {
        let runtime = build_runtime()?;
        let pool = runtime
            .block_on(
                PgPoolOptions::new()
                    .max_connections(MAX_CONNECTIONS)
                    .connect(database_url),
            )
            .map_err(map_sqlx)?;
        runtime
            .block_on(apply_migrations(&pool))
            .map_err(map_sqlx)?;
        Ok(Self {
            pool,
            runtime: Arc::new(runtime),
            tenant: tenant.map(|t| t.as_str().to_string()),
            clock: Arc::new(SystemClock),
        })
    }

    /// Wrap an existing pool (single-tenant). Does **not** run migrations — call
    /// [`PostgresAdapter::migrate`] or [`RegistryBackend::init_if_needed`] first.
    ///
    /// Args:
    /// * `pool`: A connected `sqlx::PgPool`.
    pub fn new(pool: PgPool) -> Result<Self, RegistryError> {
        Ok(Self {
            pool,
            runtime: Arc::new(build_runtime()?),
            tenant: None,
            clock: Arc::new(SystemClock),
        })
    }

    /// Set the tenant on an adapter built via [`PostgresAdapter::new`].
    ///
    /// Args:
    /// * `tenant`: The validated tenant whose rows this backend reads and writes.
    #[must_use]
    pub fn with_tenant(mut self, tenant: ValidatedTenantId) -> Self {
        self.tenant = Some(tenant.as_str().to_string());
        self
    }

    /// Override the clock provider (e.g. a fixed clock in tests).
    ///
    /// Args:
    /// * `clock`: The clock provider to inject.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn ClockProvider>) -> Self {
        self.clock = clock;
        self
    }

    /// The underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply (idempotently) the registry schema to the connected database.
    pub fn migrate(&self) -> Result<(), RegistryError> {
        self.block_on(apply_migrations(&self.pool))
            .map_err(map_sqlx)
    }

    /// Tenant key for this backend (`DEFAULT_TENANT` in single-tenant mode).
    fn tenant_key(&self) -> &str {
        self.tenant.as_deref().unwrap_or(DEFAULT_TENANT)
    }

    /// Drive a future to completion on the owned runtime.
    ///
    /// Uses the runtime directly when called from a synchronous context (the CLI
    /// and these tests). If an ambient Tokio runtime is present (e.g. an async
    /// server), the future is driven on a scoped thread so `block_on` is never
    /// called re-entrantly on the current runtime.
    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future,
    {
        match tokio::runtime::Handle::try_current() {
            // Sync caller (CLI, tests): drive the future on the adapter's own runtime.
            Err(_) => self.runtime.block_on(fut),
            // Async caller (e.g. an axum handler): we are already on a runtime worker, so
            // `block_in_place` hands the future to the adapter's runtime without nesting a
            // second runtime on this thread. Runs on THIS thread, so no `Send` bound and no
            // scoped-thread higher-ranked-lifetime tangle with sqlx's borrowed executors.
            Ok(_) => tokio::task::block_in_place(|| self.runtime.block_on(fut)),
        }
    }

    // ── KEL append ────────────────────────────────────────────────────────────

    async fn append_inner(
        &self,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
    ) -> Result<(), RegistryError> {
        let tenant = self.tenant_key();
        let prefix_str = prefix.as_str();
        let seq = event.sequence().value();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;

        let current = load_current_state(&mut *tx, tenant, prefix_str).await?;
        validate_append(prefix, event, current.as_ref())?;

        let new_state = compute_state_after_event(current.as_ref().map(|c| &c.state), event)?;

        let event_bytes = serde_json::to_vec(event)?;
        let now = self.clock.now();
        let attachment_opt: Option<Vec<u8>> = if attachment.is_empty() {
            None
        } else {
            Some(attachment.to_vec())
        };

        let insert = sqlx::query(
            "INSERT INTO registry_events \
             (tenant, prefix, seq, said, event_bytes, attachment, created_at) \
             VALUES ($1, $2, CAST($3 AS NUMERIC), $4, $5, $6, $7)",
        )
        .bind(tenant)
        .bind(prefix_str)
        .bind(u128_to_sql(seq))
        .bind(event.said().as_str())
        .bind(&event_bytes)
        .bind(attachment_opt)
        .bind(to_millis(now))
        .execute(&mut *tx)
        .await;

        if let Err(e) = insert {
            if is_unique_violation(&e) {
                return Err(RegistryError::EventExists {
                    prefix: prefix_str.to_string(),
                    seq,
                });
            }
            return Err(map_sqlx(e));
        }

        let state_bytes = serde_json::to_vec(&new_state)?;
        sqlx::query(
            "INSERT INTO registry_key_state \
             (tenant, prefix, sequence, said, state_bytes, updated_at) \
             VALUES ($1, $2, CAST($3 AS NUMERIC), $4, $5, $6) \
             ON CONFLICT (tenant, prefix) DO UPDATE \
                SET sequence = EXCLUDED.sequence, said = EXCLUDED.said, \
                    state_bytes = EXCLUDED.state_bytes, updated_at = EXCLUDED.updated_at \
              WHERE EXCLUDED.sequence >= registry_key_state.sequence",
        )
        .bind(tenant)
        .bind(prefix_str)
        .bind(u128_to_sql(new_state.sequence))
        .bind(new_state.last_event_said.as_str())
        .bind(&state_bytes)
        .bind(to_millis(now))
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    // ── KEL reads ─────────────────────────────────────────────────────────────

    async fn get_attachment_inner(
        &self,
        prefix: &Prefix,
        seq: u128,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        let row = sqlx::query(
            "SELECT attachment FROM registry_events \
             WHERE tenant = $1 AND prefix = $2 AND seq = CAST($3 AS NUMERIC)",
        )
        .bind(self.tenant_key())
        .bind(prefix.as_str())
        .bind(u128_to_sql(seq))
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        match row {
            None => Ok(None),
            Some(r) => r
                .try_get::<Option<Vec<u8>>, _>("attachment")
                .map_err(map_sqlx),
        }
    }

    async fn get_event_inner(&self, prefix: &Prefix, seq: u128) -> Result<Event, RegistryError> {
        let row = sqlx::query(
            "SELECT event_bytes, attachment FROM registry_events \
             WHERE tenant = $1 AND prefix = $2 AND seq = CAST($3 AS NUMERIC)",
        )
        .bind(self.tenant_key())
        .bind(prefix.as_str())
        .bind(u128_to_sql(seq))
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| RegistryError::event_not_found(prefix, seq))?;

        let bytes: Vec<u8> = row.try_get("event_bytes").map_err(map_sqlx)?;
        let event: Event = serde_json::from_slice(&bytes)?;
        if event.is_delegated() {
            let attachment: Option<Vec<u8>> = row.try_get("attachment").map_err(map_sqlx)?;
            return Ok(rehydrate_source_seal(event, attachment));
        }
        Ok(event)
    }

    async fn fetch_events_from(
        &self,
        prefix: &Prefix,
        from_seq: u128,
    ) -> Result<Vec<Event>, RegistryError> {
        let rows = sqlx::query(
            "SELECT event_bytes, attachment FROM registry_events \
             WHERE tenant = $1 AND prefix = $2 AND seq >= CAST($3 AS NUMERIC) \
             ORDER BY seq ASC",
        )
        .bind(self.tenant_key())
        .bind(prefix.as_str())
        .bind(u128_to_sql(from_seq))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.try_get("event_bytes").map_err(map_sqlx)?;
            let event: Event = serde_json::from_slice(&bytes)?;
            if event.is_delegated() {
                let attachment: Option<Vec<u8>> = row.try_get("attachment").map_err(map_sqlx)?;
                events.push(rehydrate_source_seal(event, attachment));
            } else {
                events.push(event);
            }
        }
        Ok(events)
    }

    async fn get_tip_inner(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        let row = sqlx::query(
            "SELECT sequence::text AS seq, said FROM registry_key_state \
             WHERE tenant = $1 AND prefix = $2",
        )
        .bind(self.tenant_key())
        .bind(prefix.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| RegistryError::identity_not_found(prefix))?;

        let seq_text: String = row.try_get("seq").map_err(map_sqlx)?;
        let said: String = row.try_get("said").map_err(map_sqlx)?;
        Ok(TipInfo::new(
            u128_from_sql(&seq_text)?,
            Said::new_unchecked(said),
        ))
    }

    async fn get_key_state_inner(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        let bytes: Vec<u8> = sqlx::query_scalar(
            "SELECT state_bytes FROM registry_key_state WHERE tenant = $1 AND prefix = $2",
        )
        .bind(self.tenant_key())
        .bind(prefix.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| RegistryError::identity_not_found(prefix))?;

        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn write_key_state_inner(
        &self,
        prefix: &Prefix,
        state: &KeyState,
    ) -> Result<(), RegistryError> {
        let tenant = self.tenant_key();
        let prefix_str = prefix.as_str();

        let existing: Option<String> = sqlx::query_scalar(
            "SELECT sequence::text FROM registry_key_state WHERE tenant = $1 AND prefix = $2",
        )
        .bind(tenant)
        .bind(prefix_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(existing_seq_text) = existing else {
            return Err(RegistryError::identity_not_found(prefix));
        };
        let existing_seq = u128_from_sql(&existing_seq_text)?;

        if state.sequence < existing_seq {
            return Err(RegistryError::ConcurrentModification(format!(
                "key-state rollback rejected for {prefix}: stored sequence {existing_seq} \
                 is newer than incoming {}",
                state.sequence
            )));
        }

        let state_bytes = serde_json::to_vec(state)?;
        sqlx::query(
            "UPDATE registry_key_state \
                SET sequence = CAST($3 AS NUMERIC), said = $4, \
                    state_bytes = $5, updated_at = $6 \
              WHERE tenant = $1 AND prefix = $2 AND CAST($3 AS NUMERIC) >= sequence",
        )
        .bind(tenant)
        .bind(prefix_str)
        .bind(u128_to_sql(state.sequence))
        .bind(state.last_event_said.as_str())
        .bind(&state_bytes)
        .bind(to_millis(self.clock.now()))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn fetch_identities(&self) -> Result<Vec<String>, RegistryError> {
        let rows = sqlx::query(
            "SELECT prefix FROM registry_key_state WHERE tenant = $1 ORDER BY prefix ASC",
        )
        .bind(self.tenant_key())
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row.try_get::<String, _>("prefix").map_err(map_sqlx)?);
        }
        Ok(out)
    }

    // ── Attestations ──────────────────────────────────────────────────────────

    async fn store_attestation_inner(&self, att: &Attestation) -> Result<(), RegistryError> {
        let tenant = self.tenant_key();
        let subject = att.subject.as_str();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;

        let existing_ts: Option<Option<i64>> = sqlx::query_scalar(
            "SELECT att_ts FROM registry_attestations \
             WHERE tenant = $1 AND subject_did = $2 ORDER BY id DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        if let Some(old_ts) = existing_ts {
            match (att.timestamp, old_ts) {
                (Some(new_ts), Some(old)) if to_millis(new_ts) <= old => {
                    return Err(RegistryError::StaleAttestation(format!(
                        "new attestation timestamp ({new_ts}) is not newer than existing \
                         ({}) for device {subject}",
                        from_millis(old)
                    )));
                }
                (None, Some(_)) => {
                    return Err(RegistryError::StaleAttestation(format!(
                        "new attestation has no timestamp but existing does for device {subject}"
                    )));
                }
                _ => {}
            }
        }

        let att_bytes = serde_json::to_vec(att)?;
        sqlx::query(
            "INSERT INTO registry_attestations \
             (tenant, subject_did, rid, att_bytes, att_ts, revoked_at, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant)
        .bind(subject)
        .bind(att.rid.to_string())
        .bind(&att_bytes)
        .bind(att.timestamp.map(to_millis))
        .bind(att.revoked_at.map(to_millis))
        .bind(att.expires_at.map(to_millis))
        .bind(to_millis(self.clock.now()))
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn load_attestation_inner(
        &self,
        did: &CanonicalDid,
    ) -> Result<Option<Attestation>, RegistryError> {
        let bytes: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT att_bytes FROM registry_attestations \
             WHERE tenant = $1 AND subject_did = $2 ORDER BY id DESC LIMIT 1",
        )
        .bind(self.tenant_key())
        .bind(did.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        match bytes {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    async fn fetch_attestation_history(
        &self,
        did: &CanonicalDid,
    ) -> Result<Vec<Attestation>, RegistryError> {
        let rows = sqlx::query(
            "SELECT att_bytes FROM registry_attestations \
             WHERE tenant = $1 AND subject_did = $2 ORDER BY id ASC",
        )
        .bind(self.tenant_key())
        .bind(did.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.try_get("att_bytes").map_err(map_sqlx)?;
            out.push(serde_json::from_slice(&bytes)?);
        }
        Ok(out)
    }

    async fn fetch_devices(&self) -> Result<Vec<CanonicalDid>, RegistryError> {
        let rows = sqlx::query(
            "SELECT DISTINCT subject_did FROM registry_attestations \
             WHERE tenant = $1 ORDER BY subject_did ASC",
        )
        .bind(self.tenant_key())
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let did_str: String = row.try_get("subject_did").map_err(map_sqlx)?;
            match CanonicalDid::parse(&did_str) {
                Ok(did) => out.push(did),
                Err(_) => log::warn!("Skipping unparseable device DID from registry: {did_str}"),
            }
        }
        Ok(out)
    }

    // ── Org members ───────────────────────────────────────────────────────────

    async fn store_org_member_inner(
        &self,
        org: &str,
        member: &Attestation,
    ) -> Result<(), RegistryError> {
        let member_bytes = serde_json::to_vec(member)?;
        sqlx::query(
            "INSERT INTO registry_org_members \
             (tenant, org, member_did, member_bytes, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant, org, member_did) DO UPDATE \
                SET member_bytes = EXCLUDED.member_bytes, updated_at = EXCLUDED.updated_at",
        )
        .bind(self.tenant_key())
        .bind(org)
        .bind(member.subject.as_str())
        .bind(&member_bytes)
        .bind(to_millis(self.clock.now()))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn fetch_org_members(&self, org: &str) -> Result<Vec<OrgMemberEntry>, RegistryError> {
        let expected_issuer = expected_org_issuer(org);
        let org_did =
            IdentityDID::parse(&expected_issuer).map_err(|e| RegistryError::InvalidPrefix {
                prefix: org.to_string(),
                reason: e.to_string(),
            })?;

        let rows = sqlx::query(
            "SELECT member_did, member_bytes FROM registry_org_members \
             WHERE tenant = $1 AND org = $2 ORDER BY member_did ASC",
        )
        .bind(self.tenant_key())
        .bind(org)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let member_did_str: String = row.try_get("member_did").map_err(map_sqlx)?;
            let did = match CanonicalDid::parse(&member_did_str) {
                Ok(d) => d,
                Err(_) => {
                    log::warn!("Skipping unparseable member DID: {member_did_str}");
                    continue;
                }
            };
            let bytes: Vec<u8> = row.try_get("member_bytes").map_err(map_sqlx)?;

            let attestation = validate_org_member(&bytes, &did, &member_did_str, &expected_issuer);
            // Mirror the git backend: a member whose issuer DID is unparseable is
            // skipped entirely rather than surfaced as an invalid entry.
            if matches!(&attestation, Err(MemberInvalidReason::Other(_))) {
                log::warn!("Skipping member {member_did_str} with unusable issuer DID");
                continue;
            }

            out.push(OrgMemberEntry {
                org: org_did.clone(),
                did,
                filename: format!("{member_did_str}.json"),
                attestation,
            });
        }
        Ok(out)
    }

    // ── Lifecycle / metadata ──────────────────────────────────────────────────

    async fn init_if_needed_inner(&self) -> Result<bool, RegistryError> {
        apply_migrations(&self.pool).await.map_err(map_sqlx)?;
        let result = sqlx::query(
            "INSERT INTO registry_tenants (tenant, status, created_at) \
             VALUES ($1, 'active', $2) ON CONFLICT (tenant) DO NOTHING",
        )
        .bind(self.tenant_key())
        .bind(to_millis(self.clock.now()))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    async fn metadata_inner(&self) -> Result<RegistryMetadata, RegistryError> {
        let tenant = self.tenant_key();

        let created_at: Option<i64> =
            sqlx::query_scalar("SELECT created_at FROM registry_tenants WHERE tenant = $1")
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        let Some(created_at) = created_at else {
            return Err(RegistryError::NotFound {
                entity_type: "registry".into(),
                id: tenant.to_string(),
            });
        };

        let identity_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM registry_key_state WHERE tenant = $1")
                .bind(tenant)
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx)?;
        let device_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT subject_did) FROM registry_attestations WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM registry_org_members WHERE tenant = $1")
                .bind(tenant)
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx)?;

        let updated_at: Option<i64> = sqlx::query_scalar(
            "SELECT GREATEST( \
                (SELECT MAX(created_at) FROM registry_events WHERE tenant = $1), \
                (SELECT MAX(created_at) FROM registry_attestations WHERE tenant = $1), \
                (SELECT MAX(updated_at) FROM registry_org_members WHERE tenant = $1), \
                (SELECT MAX(updated_at) FROM registry_key_state WHERE tenant = $1))",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(RegistryMetadata::new(
            from_millis(updated_at.unwrap_or(created_at)),
            u64::try_from(identity_count).unwrap_or(0),
            u64::try_from(device_count).unwrap_or(0),
            u64::try_from(member_count).unwrap_or(0),
        ))
    }
}

impl RegistryBackend for PostgresAdapter {
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError> {
        self.block_on(self.append_inner(prefix, event, &[]))
    }

    fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
    ) -> Result<(), RegistryError> {
        self.block_on(self.append_inner(prefix, event, attachment))
    }

    fn get_attachment(&self, prefix: &Prefix, seq: u128) -> Result<Option<Vec<u8>>, RegistryError> {
        self.block_on(self.get_attachment_inner(prefix, seq))
    }

    fn get_event(&self, prefix: &Prefix, seq: u128) -> Result<Event, RegistryError> {
        self.block_on(self.get_event_inner(prefix, seq))
    }

    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u128,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let events = self.block_on(self.fetch_events_from(prefix, from_seq))?;
        for event in &events {
            if visitor(event).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        self.block_on(self.get_tip_inner(prefix))
    }

    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        self.block_on(self.get_key_state_inner(prefix))
    }

    fn write_key_state(&self, prefix: &Prefix, state: &KeyState) -> Result<(), RegistryError> {
        self.block_on(self.write_key_state_inner(prefix, state))
    }

    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let prefixes = self.block_on(self.fetch_identities())?;
        for prefix in &prefixes {
            if visitor(prefix).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError> {
        self.block_on(self.store_attestation_inner(attestation))
    }

    fn load_attestation(&self, did: &CanonicalDid) -> Result<Option<Attestation>, RegistryError> {
        self.block_on(self.load_attestation_inner(did))
    }

    fn visit_attestation_history(
        &self,
        did: &CanonicalDid,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let history = self.block_on(self.fetch_attestation_history(did))?;
        for att in &history {
            if visitor(att).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&CanonicalDid) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let devices = self.block_on(self.fetch_devices())?;
        for did in &devices {
            if visitor(did).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError> {
        self.block_on(self.store_org_member_inner(org, member))
    }

    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let members = self.block_on(self.fetch_org_members(org))?;
        for entry in &members {
            if visitor(entry).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        self.block_on(self.init_if_needed_inner())
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        self.block_on(self.metadata_inner())
    }
}

// ── Pure helpers (no I/O) ──────────────────────────────────────────────────────

/// Build the owned multi-threaded runtime used to drive queries.
fn build_runtime() -> Result<tokio::runtime::Runtime, RegistryError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| RegistryError::Internal(format!("failed to build tokio runtime: {e}")))
}

/// Render a `u128` sequence as its decimal string for a `CAST(... AS NUMERIC)` bind.
fn u128_to_sql(value: u128) -> String {
    value.to_string()
}

/// Encode a timestamp as epoch milliseconds for a `BIGINT` column.
fn to_millis(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

/// Decode a `BIGINT` epoch-milliseconds column back into a timestamp.
fn from_millis(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

/// Parse a `NUMERIC::text` column value back into a `u128`.
fn u128_from_sql(text: &str) -> Result<u128, RegistryError> {
    text.parse::<u128>()
        .map_err(|e| RegistryError::Internal(format!("invalid stored sequence '{text}': {e}")))
}

/// Map a `sqlx` error into the registry's error domain.
fn map_sqlx(err: sqlx::Error) -> RegistryError {
    match err {
        sqlx::Error::RowNotFound => RegistryError::NotFound {
            entity_type: "row".into(),
            id: String::new(),
        },
        other => RegistryError::storage(other),
    }
}

/// Whether a `sqlx` error is a unique-constraint violation (the CAS loser).
fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.is_unique_violation())
}

/// Load the current tip + cached key-state for one identity within a transaction.
async fn load_current_state<'e, E>(
    executor: E,
    tenant: &str,
    prefix: &str,
) -> Result<Option<CurrentState>, RegistryError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "SELECT sequence::text AS seq, said, state_bytes FROM registry_key_state \
         WHERE tenant = $1 AND prefix = $2",
    )
    .bind(tenant)
    .bind(prefix)
    .fetch_optional(executor)
    .await
    .map_err(map_sqlx)?;

    match row {
        None => Ok(None),
        Some(r) => {
            let seq_text: String = r.try_get("seq").map_err(map_sqlx)?;
            let said: String = r.try_get("said").map_err(map_sqlx)?;
            let state_bytes: Vec<u8> = r.try_get("state_bytes").map_err(map_sqlx)?;
            Ok(Some(CurrentState {
                sequence: u128_from_sql(&seq_text)?,
                said,
                state: serde_json::from_slice(&state_bytes)?,
            }))
        }
    }
}

/// Validate an event for append against the current tip/state.
///
/// Enforces the same constraint set as the git backend's write path: prefix
/// match, monotonic sequence (already-present seq → `EventExists`, ahead-of-tip
/// → `SequenceGap`), inception-first, chain linkage, SAID integrity, and crypto.
///
/// Args:
/// * `prefix`: The identity prefix the event is being appended under.
/// * `event`: The event to validate.
/// * `current`: The current tip + key-state, or `None` before inception.
fn validate_append(
    prefix: &Prefix,
    event: &Event,
    current: Option<&CurrentState>,
) -> Result<(), RegistryError> {
    let seq = event.sequence().value();

    if event.prefix() != prefix {
        return Err(RegistryError::InvalidPrefix {
            prefix: prefix.to_string(),
            reason: format!(
                "event prefix '{}' does not match expected '{}'",
                event.prefix(),
                prefix
            ),
        });
    }

    let expected_seq = current.map(|c| c.sequence + 1).unwrap_or(0);
    if seq != expected_seq {
        if let Some(c) = current
            && seq <= c.sequence
        {
            return Err(RegistryError::EventExists {
                prefix: prefix.to_string(),
                seq,
            });
        }
        return Err(RegistryError::SequenceGap {
            prefix: prefix.to_string(),
            expected: expected_seq,
            got: seq,
        });
    }

    if seq == 0 && !event.is_inception() {
        return Err(RegistryError::Internal(
            "First event (seq 0) must be inception".into(),
        ));
    }

    if seq > 0 {
        let prev_said = event.previous().ok_or_else(|| {
            RegistryError::Internal(format!(
                "Event at seq {seq} must have previous SAID (p field)"
            ))
        })?;
        let expected_prev = current
            .map(|c| c.said.as_str())
            .ok_or_else(|| RegistryError::Internal("No tip found for non-zero sequence".into()))?;
        if prev_said.as_str() != expected_prev {
            return Err(RegistryError::SaidMismatch {
                expected: expected_prev.to_string(),
                actual: prev_said.as_str().to_string(),
            });
        }
    }

    verify_event_said(event).map_err(|e| match e {
        ValidationError::InvalidSaid { expected, actual } => RegistryError::SaidMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        },
        other => RegistryError::InvalidEvent {
            reason: other.to_string(),
        },
    })?;

    verify_event_crypto(event, current.map(|c| &c.state)).map_err(|e| match e {
        ValidationError::SignatureFailed { sequence } => RegistryError::InvalidEvent {
            reason: format!("Signature verification failed at sequence {sequence}"),
        },
        ValidationError::CommitmentMismatch { sequence } => RegistryError::InvalidEvent {
            reason: format!("Pre-rotation commitment mismatch at sequence {sequence}"),
        },
        other => RegistryError::InvalidEvent {
            reason: other.to_string(),
        },
    })?;

    Ok(())
}

/// Compute the key-state after applying an event to the prior state.
///
/// Ported from the git backend so both produce identical key-state transitions.
///
/// Args:
/// * `current_state`: The prior key-state, or `None` for an inception event.
/// * `event`: The event to apply.
fn compute_state_after_event(
    current_state: Option<&KeyState>,
    event: &Event,
) -> Result<KeyState, RegistryError> {
    match event {
        Event::Icp(icp) => Ok(KeyState::from_inception(
            icp.i.clone(),
            icp.k.clone(),
            icp.n.clone(),
            icp.kt.clone(),
            icp.nt.clone(),
            icp.d.clone(),
            icp.b.clone(),
            icp.bt.clone(),
            icp.c.clone(),
        )),
        Event::Dip(dip) => Ok(KeyState::from_inception(
            dip.i.clone(),
            dip.k.clone(),
            dip.n.clone(),
            dip.kt.clone(),
            dip.nt.clone(),
            dip.d.clone(),
            dip.b.clone(),
            dip.bt.clone(),
            dip.c.clone(),
        )),
        Event::Rot(rot) => {
            let mut state = current_state
                .cloned()
                .ok_or_else(|| RegistryError::Internal("Rotation without prior state".into()))?;
            state.apply_rotation(
                rot.k.clone(),
                rot.n.clone(),
                rot.kt.clone(),
                rot.nt.clone(),
                event.sequence().value(),
                rot.d.clone(),
                &rot.br,
                &rot.ba,
                rot.bt.clone(),
                rot.c.clone(),
            );
            Ok(state)
        }
        Event::Drt(drt) => {
            let mut state = current_state.cloned().ok_or_else(|| {
                RegistryError::Internal("Delegated rotation without prior state".into())
            })?;
            state.apply_rotation(
                drt.k.clone(),
                drt.n.clone(),
                drt.kt.clone(),
                drt.nt.clone(),
                event.sequence().value(),
                drt.d.clone(),
                &drt.br,
                &drt.ba,
                drt.bt.clone(),
                drt.c.clone(),
            );
            Ok(state)
        }
        Event::Ixn(ixn) => {
            let mut state = current_state
                .cloned()
                .ok_or_else(|| RegistryError::Internal("Interaction without prior state".into()))?;
            state.apply_interaction(event.sequence().value(), ixn.d.clone());
            Ok(state)
        }
    }
}

/// Re-attach a delegated event's `-G` source seal from its stored attachment.
///
/// A `dip`/`drt` JSON body carries no source seal (it lives in the CESR
/// attachment), so a fresh JSON round-trip loses it. This restores it from the
/// stored attachment bytes. Non-delegated events, missing attachments, and
/// sig-only attachments pass through unchanged. Ported from the git backend.
///
/// Args:
/// * `event`: The event freshly deserialized from storage.
/// * `attachment`: The event's stored CESR attachment bytes, if any.
fn rehydrate_source_seal(event: Event, attachment: Option<Vec<u8>>) -> Event {
    let Some(att) = attachment else {
        return event;
    };
    let Ok((_, couples)) = auths_keri::parse_delegated_attachment(&att) else {
        return event;
    };
    let Some(seal) = couples.into_iter().next() else {
        return event;
    };
    match event {
        Event::Dip(mut e) => {
            e.source_seal = Some(seal);
            Event::Dip(e)
        }
        Event::Drt(mut e) => {
            e.source_seal = Some(seal);
            Event::Drt(e)
        }
        other => other,
    }
}

/// Validate a stored org-member attestation blob against its coordinates.
///
/// Returns the parsed attestation when the subject matches the filename DID and
/// the issuer matches `did:keri:{org}`; otherwise the structural reason it is
/// invalid, mirroring the git backend's per-file validation.
///
/// Args:
/// * `bytes`: The stored attestation JSON.
/// * `filename_did`: The member DID parsed from the row key.
/// * `member_did_str`: The raw member DID string.
/// * `expected_issuer`: The expected issuer DID (`did:keri:{org}`).
fn validate_org_member(
    bytes: &[u8],
    filename_did: &CanonicalDid,
    member_did_str: &str,
    expected_issuer: &str,
) -> Result<Attestation, MemberInvalidReason> {
    let att: Attestation = match serde_json::from_slice(bytes) {
        Ok(a) => a,
        Err(e) => return Err(MemberInvalidReason::JsonParseError(e.to_string())),
    };

    if att.subject.as_str() != member_did_str {
        return Err(MemberInvalidReason::SubjectMismatch {
            filename_did: filename_did.clone(),
            attestation_subject: CanonicalDid::new_unchecked(att.subject.as_str()),
        });
    }

    if att.issuer.as_str() != expected_issuer {
        let expected = match IdentityDID::parse(expected_issuer) {
            Ok(d) => d,
            Err(_) => {
                return Err(MemberInvalidReason::Other(
                    "unparseable expected issuer".into(),
                ));
            }
        };
        let actual = match IdentityDID::parse(att.issuer.as_str()) {
            Ok(d) => d,
            Err(_) => return Err(MemberInvalidReason::Other("unparseable issuer DID".into())),
        };
        return Err(MemberInvalidReason::IssuerMismatch {
            expected_issuer: expected,
            actual_issuer: actual,
        });
    }

    Ok(att)
}
