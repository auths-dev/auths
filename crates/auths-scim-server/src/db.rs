//! PostgreSQL sync state queries.

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

/// Row from the `scim_agents` table.
#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub external_id: Option<String>,
    pub identity_did: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub active: bool,
    pub capabilities: Vec<String>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Row from the `scim_tenants` table.
#[derive(Debug, Clone)]
pub struct TenantRow {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub allowed_capabilities: Vec<String>,
    pub is_test: bool,
    pub created_at: DateTime<Utc>,
    pub token_expires_at: Option<DateTime<Utc>>,
}

impl AgentRow {
    fn from_row(row: &tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            external_id: row.get("external_id"),
            identity_did: row.get("identity_did"),
            user_name: row.get("user_name"),
            display_name: row.get("display_name"),
            active: row.get("active"),
            capabilities: row.get("capabilities"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            last_modified: row.get("last_modified"),
            deleted_at: row.get("deleted_at"),
        }
    }
}

impl TenantRow {
    fn from_row(row: &tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            token_hash: row.get("token_hash"),
            allowed_capabilities: row.get("allowed_capabilities"),
            is_test: row.get("is_test"),
            created_at: row.get("created_at"),
            token_expires_at: row.get("token_expires_at"),
        }
    }
}

/// Database operations for SCIM sync state.
pub struct ScimDb;

impl ScimDb {
    /// Find a tenant by token hash.
    pub async fn find_tenant_by_token(
        pool: &Pool,
        token_hash: &str,
    ) -> Result<Option<TenantRow>, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_opt(
                "SELECT * FROM scim_tenants WHERE token_hash = $1",
                &[&token_hash],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(row.as_ref().map(TenantRow::from_row))
    }

    /// Insert a new agent.
    pub async fn insert_agent(
        pool: &Pool,
        tenant_id: Uuid,
        external_id: Option<&str>,
        identity_did: &str,
        user_name: &str,
        display_name: Option<&str>,
        capabilities: &[String],
    ) -> Result<AgentRow, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_one(
                r#"INSERT INTO scim_agents (tenant_id, external_id, identity_did, user_name, display_name, capabilities)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   RETURNING *"#,
                &[&tenant_id, &external_id, &identity_did, &user_name, &display_name, &capabilities],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(AgentRow::from_row(&row))
    }

    /// Find an agent by ID and tenant.
    pub async fn find_agent(
        pool: &Pool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<AgentRow>, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_opt(
                "SELECT * FROM scim_agents WHERE id = $1 AND tenant_id = $2",
                &[&agent_id, &tenant_id],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(row.as_ref().map(AgentRow::from_row))
    }

    /// Find an existing agent by external_id within a tenant (for idempotent POST).
    pub async fn find_by_external_id(
        pool: &Pool,
        tenant_id: Uuid,
        external_id: &str,
    ) -> Result<Option<AgentRow>, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_opt(
                "SELECT * FROM scim_agents WHERE tenant_id = $1 AND external_id = $2",
                &[&tenant_id, &external_id],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(row.as_ref().map(AgentRow::from_row))
    }

    /// List agents for a tenant with pagination.
    pub async fn list_agents(
        pool: &Pool,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<AgentRow>, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let rows = client
            .query(
                "SELECT * FROM scim_agents WHERE tenant_id = $1 ORDER BY created_at ASC OFFSET $2 LIMIT $3",
                &[&tenant_id, &offset, &limit],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(rows.iter().map(AgentRow::from_row).collect())
    }

    /// Count agents for a tenant.
    pub async fn count_agents(
        pool: &Pool,
        tenant_id: Uuid,
    ) -> Result<i64, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM scim_agents WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(row.get(0))
    }

    /// Update an agent's mutable fields.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_agent(
        pool: &Pool,
        agent_id: Uuid,
        tenant_id: Uuid,
        display_name: Option<&str>,
        external_id: Option<&str>,
        capabilities: &[String],
        active: bool,
        expected_version: i64,
    ) -> Result<Option<AgentRow>, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_opt(
                r#"UPDATE scim_agents
                   SET display_name = $3,
                       external_id = $4,
                       capabilities = $5,
                       active = $6,
                       version = version + 1,
                       last_modified = now(),
                       deleted_at = CASE WHEN $6 THEN NULL ELSE now() END
                   WHERE id = $1 AND tenant_id = $2 AND version = $7
                   RETURNING *"#,
                &[
                    &agent_id,
                    &tenant_id,
                    &display_name,
                    &external_id,
                    &capabilities,
                    &active,
                    &expected_version,
                ],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(row.as_ref().map(AgentRow::from_row))
    }

    /// Hard-delete an agent (for SCIM DELETE).
    pub async fn delete_agent(
        pool: &Pool,
        agent_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let count = client
            .execute(
                "DELETE FROM scim_agents WHERE id = $1 AND tenant_id = $2",
                &[&agent_id, &tenant_id],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(count > 0)
    }

    /// Insert a new tenant.
    pub async fn insert_tenant(
        pool: &Pool,
        name: &str,
        token_hash: &str,
        allowed_capabilities: &[String],
        is_test: bool,
        token_expires_at: Option<DateTime<Utc>>,
    ) -> Result<TenantRow, deadpool_postgres::PoolError> {
        let client = pool.get().await?;
        let row = client
            .query_one(
                r#"INSERT INTO scim_tenants (name, token_hash, allowed_capabilities, is_test, token_expires_at)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING *"#,
                &[&name, &token_hash, &allowed_capabilities, &is_test, &token_expires_at],
            )
            .await
            .map_err(deadpool_postgres::PoolError::Backend)?;
        Ok(TenantRow::from_row(&row))
    }
}
