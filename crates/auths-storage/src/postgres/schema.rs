//! Schema migration and database provisioning for the Postgres registry backend.
//!
//! The schema is embedded at compile time (`include_str!`) so the backend needs
//! no migration files on disk at runtime and no `sqlx-migrate` feature. All
//! statements are idempotent (`CREATE TABLE IF NOT EXISTS`), and application is
//! serialized with a session advisory lock so parallel migrators (e.g. one per
//! test process) cannot race the system catalog.

use sqlx::PgPool;

/// The embedded registry schema, applied by [`apply_migrations`].
pub const MIGRATION_SQL: &str = include_str!("../../migrations/0001_registry_backend.sql");

/// Advisory-lock key that serializes concurrent schema migrations.
const MIGRATION_LOCK_KEY: i64 = 0x0A47_5300_5245_4749; // "AuthsREGI"-ish, arbitrary but stable.

/// Apply the embedded schema to a database, idempotently and race-safely.
///
/// Acquires a session advisory lock, runs the (multi-statement) schema via the
/// simple-query protocol, then releases the lock. Safe to call from many
/// processes concurrently — losers block on the advisory lock, then observe the
/// tables already present.
///
/// Args:
/// * `pool`: A connected pool for the target database.
///
/// Usage:
/// ```ignore
/// apply_migrations(&pool).await?;
/// ```
pub(crate) async fn apply_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    let result = sqlx::raw_sql(MIGRATION_SQL).execute(&mut *conn).await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await
        .ok();

    result.map(|_| ())
}

/// Create a database if it does not already exist.
///
/// `CREATE DATABASE` cannot run inside a transaction and has no `IF NOT EXISTS`
/// form, so this connects to the given maintenance database, attempts the
/// create, and treats a "duplicate database" error as success. Useful for
/// provisioning a fresh Postgres-backed registry (and for test setup).
///
/// Args:
/// * `admin_url`: Connection URL to a maintenance database (e.g. `.../postgres`).
/// * `db_name`: Name of the database to ensure exists (validated to `[A-Za-z0-9_]`).
///
/// Usage:
/// ```ignore
/// create_database_if_absent("postgres://localhost/postgres", "auths_registry").await?;
/// ```
pub async fn create_database_if_absent(admin_url: &str, db_name: &str) -> Result<(), sqlx::Error> {
    if db_name.is_empty()
        || !db_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(sqlx::Error::Configuration(
            format!("invalid database name '{db_name}': only [A-Za-z0-9_] allowed").into(),
        ));
    }

    let pool = PgPool::connect(admin_url).await?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(db_name)
        .fetch_optional(&pool)
        .await?;

    if exists.is_none() {
        // Identifier is validated above, so interpolation is safe here.
        match sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&pool)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                let raced = matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42P04"));
                if !raced {
                    pool.close().await;
                    return Err(e);
                }
            }
        }
    }

    pool.close().await;
    Ok(())
}
