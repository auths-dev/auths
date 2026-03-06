-- SCIM sync state tables for auths-scim-server.

CREATE TABLE IF NOT EXISTS scim_tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    allowed_capabilities TEXT[] NOT NULL DEFAULT '{}',
    is_test BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_expires_at TIMESTAMPTZ,
    CONSTRAINT tenants_name_unique UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS scim_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES scim_tenants(id) ON DELETE CASCADE,
    external_id TEXT,
    identity_did TEXT NOT NULL,
    user_name TEXT NOT NULL,
    display_name TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_modified TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT agents_tenant_external_unique UNIQUE (tenant_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON scim_agents (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_did ON scim_agents (identity_did);
CREATE INDEX IF NOT EXISTS idx_agents_username ON scim_agents (user_name);
CREATE INDEX IF NOT EXISTS idx_agents_active ON scim_agents (tenant_id, active);
