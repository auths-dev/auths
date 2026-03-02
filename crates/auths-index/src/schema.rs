//! SQL schema for the attestation index.

pub const CREATE_ATTESTATIONS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS attestations (
    rid TEXT PRIMARY KEY,
    issuer_did TEXT NOT NULL,
    device_did TEXT NOT NULL,
    git_ref TEXT NOT NULL,
    commit_oid TEXT NOT NULL,
    revoked_at TEXT,
    expires_at TEXT,
    updated_at TEXT NOT NULL
)
"#;

pub const CREATE_DEVICE_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_device ON attestations(device_did)
"#;

pub const CREATE_ISSUER_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_issuer ON attestations(issuer_did)
"#;

pub const CREATE_EXPIRES_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_expires ON attestations(expires_at) WHERE expires_at IS NOT NULL
"#;

pub const CREATE_IDENTITIES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS identities (
    prefix       TEXT PRIMARY KEY,
    current_keys TEXT NOT NULL,
    sequence     INTEGER NOT NULL,
    tip_said     TEXT NOT NULL,
    updated_at   TEXT NOT NULL
)
"#;

pub const CREATE_ORG_MEMBERS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS org_members (
    org_prefix    TEXT NOT NULL,
    member_did    TEXT NOT NULL,
    issuer_did    TEXT NOT NULL,
    rid           TEXT NOT NULL,
    revoked_at    TEXT,
    expires_at    TEXT,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (org_prefix, member_did)
)
"#;

pub const CREATE_ORG_MEMBERS_ORG_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_prefix)
"#;

pub const CREATE_ORG_MEMBERS_MEMBER_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_org_members_member ON org_members(member_did)
"#;

/// Initialize the database schema.
pub fn init_schema(conn: &sqlite::Connection) -> std::result::Result<(), sqlite::Error> {
    conn.execute("PRAGMA journal_mode=WAL;")?;
    conn.execute(CREATE_ATTESTATIONS_TABLE)?;
    conn.execute(CREATE_DEVICE_INDEX)?;
    conn.execute(CREATE_ISSUER_INDEX)?;
    conn.execute(CREATE_EXPIRES_INDEX)?;
    conn.execute(CREATE_IDENTITIES_TABLE)?;
    conn.execute(CREATE_ORG_MEMBERS_TABLE)?;
    conn.execute(CREATE_ORG_MEMBERS_ORG_INDEX)?;
    conn.execute(CREATE_ORG_MEMBERS_MEMBER_INDEX)?;
    Ok(())
}
