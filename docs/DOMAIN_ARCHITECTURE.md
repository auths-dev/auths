# Domain Architecture: Entity Ownership & API Contracts

**Status**: Production Readiness Phase 1.5 (fn-89.0)
**Last Updated**: 2026-03-29
**Owner**: Architecture / SDK Team

---

## Overview

This document defines the foundational domain entity ownership map and API contracts that all auths-api services and infrastructure depend on. It ensures consistent semantics across identity, device, signing, auth, and compliance domains.

---

## Domain Entity Ownership Map

### Identity Domain (`domains/identity/`)

**Entities**:
- Developer identity (did:keri)
- Agent provisioning state
- Agent lifecycle (provision → refresh → revoke or expire)

**Storage**:
- Redis key: `agents:{namespace}:{agent_id}`
- TTL: `agent.expires_at`
- Write-through cache (primary source of truth is Redis during normal operation)

**Cache Invalidation**:
- On `agent.provisioned` event
- On `agent.revoked` event
- On `agent.expired` event (fn-89.9 expiry job)

**Lifecycle**:
- `provision` → `active` → `refresh` (token) → `revoke` or `expire`

**API Endpoints**:
- `GET /v1/agents` (list agents in namespace)
- `GET /v1/agents/{id}` (get agent details)
- `POST /v1/agents` (provision new agent)
- `DELETE /v1/agents/{id}` (revoke agent)

---

### Device Domain (`domains/device/`)

**Entities**:
- Agent device keys (Ed25519 public keys)
- Device attestations
- Key rotation state

**Storage**:
- Redis key: `device_keys:{namespace}:{agent_id}:{device_id}`
- TTL: `agent.expires_at` (cascade with agent)
- Indexed hash for fast lookups

**Cache Invalidation**:
- On `device.key_rotated` event
- On agent revocation (cascade delete all device keys)

**Lifecycle**:
- Linked at agent provision
- Rotated periodically (device refresh, future work)
- Revoked with agent

**API Endpoints**:
- `GET /v1/agents/{id}/devices` (list agent's device keys)
- `POST /v1/agents/{id}/devices/{device_id}/rotate` (rotate key, future)

---

### Auth Domain (`domains/auth/`)

**Entities**:
- Bearer tokens
- Token expiry
- Agent authorization state
- Token capabilities

**Storage**:
- Redis key: `tokens:{token_hash}` → `{agent_id, expires_at, capabilities}`
- TTL: `token.expires_at`
- Hash-based for O(1) lookup

**Cache Invalidation**:
- On `token.refreshed` event
- On agent revocation (cascade invalidate all tokens)
- On token expiry (TTL cleanup)

**Lifecycle**:
- Issued at agent provision (initial token)
- Refreshed on demand via `/v1/agents/{id}/token/refresh`
- Invalidated on revoke
- Auto-expired via TTL

**API Endpoints**:
- `POST /v1/agents/{id}/token/refresh` (refresh token)
- `POST /v1/auth/validate` (internal: validate token)

---

### Compliance Domain (`domains/compliance/`)

**Entities**:
- Audit events (immutable)
- Approval workflows (future, fn-90)
- Policy rules (future, fn-90)

**Storage**:
- Redis AOF (append-only file) for durability (fn-89.2)
- Immutable audit log file (retention: 90 days)
- Queryable via `/v1/audit` endpoint

**Cache Invalidation**:
- None (append-only, never invalidated)

**Lifecycle**:
- Immutable (created once, never modified)
- Retained for 90 days
- Queryable with filters (namespace, event type, date range)

**API Endpoints**:
- `GET /v1/audit` (list, filter, query audit logs)
- `GET /v1/audit/{event_id}` (get specific event)

---

### Webhook Domain (`domains/webhooks/`)

**Entities**:
- Webhook subscriptions (admin-configured)
- Delivery state (pending, delivered, failed)
- Dead-letter queue (for failed deliveries)

**Storage**:
- Redis hash: `webhooks:{webhook_id}` (subscription config)
- Redis sorted set: `dlq:{domain_name}` (failed deliveries, by timestamp)
- Persistent (no TTL unless explicitly deleted)

**Cache Invalidation**:
- On subscription change (register, update, delete)
- Manual: admin deletes subscription

**Lifecycle**:
- Registered by admin via bootstrap or API
- Fired on domain events (provision, revoke, etc.)
- Retry on failure (exponential backoff)
- Dead-lettered after N failures

**API Endpoints**:
- `POST /v1/webhooks` (register webhook)
- `GET /v1/webhooks` (list subscriptions)
- `DELETE /v1/webhooks/{id}` (unregister)
- `POST /v1/webhooks/{id}/test` (test delivery)

---

## Cross-Domain Event Contracts

### Identity Domain Events

**`agent.provisioned`**
- **Emitted by**: `Identity::provision_agent()` in `domains/identity/provision.rs`
- **Payload**:
  ```json
  {
    "event_type": "agent.provisioned",
    "agent_id": "agent_ABC...",
    "namespace": "myapp",
    "delegator_did": "did:keri:...",
    "device_public_key": "z...",
    "created_at": "2026-03-29T11:00:00Z",
    "expires_at": "2027-03-29T11:00:00Z"
  }
  ```
- **Triggers**:
  - Write to Redis: `agents:{namespace}:{agent_id}`
  - Emit to audit log (fn-89.5)
  - Queue webhook delivery (fn-89.15)
  - Update agent list cache
- **Transaction**: Atomic via Redis MULTI/EXEC

**`agent.revoked`**
- **Emitted by**: `Identity::revoke_agent()` in `domains/identity/provision.rs`
- **Payload**:
  ```json
  {
    "event_type": "agent.revoked",
    "agent_id": "agent_ABC...",
    "revoked_by": "admin@example.com",
    "revoke_reason": "Compromised key / User request / Expiration",
    "revoked_at": "2026-03-29T12:00:00Z"
  }
  ```
- **Triggers**:
  - Invalidate Redis: `agents:{namespace}:{agent_id}` (DELETE)
  - Cascade: invalidate all `device_keys:*:{agent_id}:*`
  - Cascade: invalidate all `tokens:*` for this agent
  - Emit to audit log
  - Queue webhook delivery
- **Transaction**: Atomic up to cache invalidation; webhooks are async

**`agent.expired`**
- **Emitted by**: Background expiry job (fn-89.9: token lifecycle)
- **Payload**:
  ```json
  {
    "event_type": "agent.expired",
    "agent_id": "agent_ABC...",
    "originally_expired_at": "2027-03-29T11:00:00Z"
  }
  ```
- **Triggers**:
  - Delete from Redis: agent state + device keys + tokens
  - Emit to audit log
  - Queue webhook delivery
- **Transaction**: Atomic

### Device Domain Events

**`device.key_rotated`**
- **Emitted by**: Device rotation endpoint (future: fn-90.5, `domains/device/service.rs`)
- **Payload**:
  ```json
  {
    "event_type": "device.key_rotated",
    "agent_id": "agent_ABC...",
    "device_id": "device_XYZ...",
    "old_key_hash": "sha256:...",
    "new_key_hash": "sha256:...",
    "rotated_at": "2026-03-29T13:00:00Z"
  }
  ```
- **Triggers**:
  - Update Redis: `device_keys:{namespace}:{agent_id}:{device_id}`
  - Emit to audit log (optional)
  - Queue webhook delivery (optional)
- **Transaction**: Atomic

### Auth Domain Events

**`token.refreshed`**
- **Emitted by**: `Auth::refresh_token()` → `POST /v1/agents/{id}/token/refresh` (fn-89.9)
- **Payload**:
  ```json
  {
    "event_type": "token.refreshed",
    "agent_id": "agent_ABC...",
    "new_expires_at": "2026-04-05T11:00:00Z",
    "new_token_hash": "sha256:..."
  }
  ```
- **Triggers**:
  - Update Redis: `tokens:{token_hash}`
  - Emit to audit log
  - Queue webhook delivery (optional)
- **Transaction**: Atomic

---

## Transaction Boundary Definitions

### Bootstrap Workflow (fn-89.8)

**Steps**:
1. Challenge-response (client proves key ownership)
2. Register identity (store in Git, optional)
3. Provision first agent for that identity

**Atomicity**: All-or-nothing
- If any step fails, rollback to initial state
- If agent provision fails, delete identity from IdentityResolver

**Storage Locations**:
- Agent state → Redis
- Identity → Git refs `refs/auths/identities/{namespace}/{did}` (optional)

**Failure Mode**: If bootstrap fails partway through, retry from step 1 (idempotent)

### Agent Provisioning Workflow

**Steps**:
1. Validate capabilities against namespace policy
2. Sign attestation (device signature required)
3. Write agent state to Redis cache
4. Emit `agent.provisioned` event
5. Queue webhooks asynchronously

**Atomicity**: All-or-nothing up to webhook queueing
- Redis MULTI/EXEC for steps 1-4
- Webhooks are async (best-effort, retryable)

**Rollback**: If any step fails, delete created agent state and fail fast

### Token Refresh Workflow

**Steps**:
1. Validate current token (lookup in `tokens:{token_hash}`)
2. Generate new token (from crypto library)
3. Update Redis cache: `tokens:{old_hash}` → DELETE, `tokens:{new_hash}` → WRITE
4. Emit `token.refreshed` event
5. Return new token to client

**Atomicity**: Atomic (no external events until return)
- Redis MULTI/EXEC for token cache update
- Event emission is part of the transaction

**Fallback**: If Redis write fails, client can retry (idempotent if implemented)

### Agent Revocation Workflow

**Steps**:
1. Mark agent as revoked in policy store
2. Invalidate Redis: agent state, device keys, tokens
3. Emit `agent.revoked` event
4. Queue webhooks asynchronously

**Atomicity**: Atomic up to cache invalidation
- Steps 1-3 are atomic (single Redis transaction)
- Webhooks are async

**Cascade**: Revoking an agent automatically:
- Deletes all device keys (`device_keys:*:{agent_id}:*`)
- Invalidates all tokens for that agent
- No new tokens can be issued

---

## Domain Contracts & Public API Surface

### Identity Domain Public API

```rust
/// Provision a new agent for the given namespace.
///
/// Args:
/// * `namespace`: Namespace identifier
/// * `config`: ProvisionConfig (identity, capabilities, ttl)
/// * `identity_resolver`: For storing identity (optional)
/// * `clock`: For timestamp injection
///
/// Usage:
/// ```ignore
/// let agent = identity.provision_agent(
///     "myapp",
///     config,
///     &identity_resolver,
///     &clock,
/// ).await?;
/// ```
pub async fn provision_agent(
    namespace: &str,
    config: ProvisionConfig,
    identity_resolver: &dyn IdentityResolver,
    clock: &dyn ClockProvider,
) -> Result<Agent, ProvisionError>;

/// Revoke an agent (marks as revoked, invalidates cache).
pub async fn revoke_agent(
    namespace: &str,
    agent_id: &str,
    revoked_by: &str,
    reason: &str,
    clock: &dyn ClockProvider,
) -> Result<(), RevocationError>;

/// Get agent details (cache lookup).
pub async fn get_agent(namespace: &str, agent_id: &str) -> Result<Agent, NotFoundError>;

/// List agents in namespace (pagination support in fn-89.13).
pub async fn list_agents(
    namespace: &str,
    limit: usize,
    offset: usize,
) -> Result<Vec<Agent>, QueryError>;
```

### Auth Domain Public API

```rust
/// Validate a bearer token (lookup in tokens cache).
pub async fn validate_token(
    namespace: &str,
    token: &str,
) -> Result<TokenValidation, AuthError>;

/// Refresh a token (issue new token, invalidate old one).
pub async fn refresh_token(
    namespace: &str,
    agent_id: &str,
    current_token: &str,
    ttl_seconds: u64,
    clock: &dyn ClockProvider,
) -> Result<String, RefreshError>;

/// Check if agent has a capability.
pub async fn check_capability(
    namespace: &str,
    agent_id: &str,
    capability: &str,
) -> Result<bool, AuthError>;
```

### Compliance Domain Public API

```rust
/// Emit an audit event (write to audit log + Redis AOF).
pub async fn emit_audit_event(event: AuditEvent) -> Result<(), StorageError>;

/// Query audit logs with filters.
pub async fn query_audit_logs(
    namespace: &str,
    filter: AuditFilter,
    limit: usize,
) -> Result<Vec<AuditEvent>, QueryError>;
```

### Webhook Domain Public API

```rust
/// Dispatch a webhook to all registered subscribers.
pub async fn dispatch_webhook(
    domain: &str,
    event: &str,
    payload: serde_json::Value,
) -> Result<(), DispatchError>;

/// Register a new webhook subscription.
pub async fn register_webhook(
    namespace: &str,
    url: &str,
    events: Vec<String>,
    secret: &str,
) -> Result<WebhookSubscription, RegistrationError>;

/// List all webhook subscriptions for a namespace.
pub async fn list_webhooks(namespace: &str) -> Result<Vec<WebhookSubscription>, QueryError>;
```

---

## Storage Locality Reference

### Redis (Hot Cache)

| Key Pattern | Type | TTL | Usage |
|---|---|---|---|
| `agents:{ns}:{agent_id}` | Hash | `agent.expires_at` | Agent state (name, created_at, device keys list) |
| `device_keys:{ns}:{agent_id}:{device_id}` | Hash | `agent.expires_at` | Device public key + metadata |
| `tokens:{token_hash}` | Hash | `token.expires_at` | Token metadata (agent_id, capabilities, expires_at) |
| `webhooks:{webhook_id}` | Hash | None (persistent) | Webhook subscription config (url, events, secret) |
| `dlq:{domain_name}` | Sorted Set | None (persistent) | Dead-letter queue (failed webhook deliveries, scored by timestamp) |

### Audit Log (Immutable)

- **Redis AOF**: Durability mechanism (fn-89.2)
- **Audit Log File**: Queryable via `/v1/audit` endpoint (fn-89.14)
- **Retention**: 90 days (configurable)
- **Format**: JSONL (one event per line)

### Git (Optional, via IdentityResolver)

- **Path**: `refs/auths/identities/{namespace}/{did}`
- **Contents**: Human-readable identity metadata
- **Purpose**: Optional visibility into registered identities
- **Note**: Not used for runtime lookups (cache-first via Redis)

---

## Domain Dependency Diagram

```
┌─────────────────────────────────────────────────────┐
│         auths-api HTTP Routes Layer                 │
│  /v1/agents, /v1/tokens, /v1/audit, /v1/webhooks  │
└─────────────────┬───────────────────────────────────┘
                  │
      ┌───────────┼────────────────────────────┐
      │           │                            │
      v           v                            v
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Identity    │  │  Auth        │  │  Compliance  │
│  Domain      │  │  Domain      │  │  Domain      │
│              │  │              │  │              │
│ • provision  │  │ • validate   │  │ • audit log  │
│ • revoke     │  │ • refresh    │  │ • queries    │
│ • list       │  │ • capability │  │              │
└──────┬───────┘  └──────┬───────┘  └──────────────┘
       │                 │               │
       └─────────────────┼───────────────┘
                         │
                 ┌───────┴────────┐
                 │                │
                 v                v
        ┌──────────────┐  ┌──────────────┐
        │  Webhook     │  │  Redis       │
        │  Domain      │  │  (Cache)     │
        │              │  │              │
        │ • dispatch   │  │ • MULTI/EXEC │
        │ • register   │  │ • TTL mgmt   │
        │ • dead-letter│  │ • Sentinel HA│
        └──────────────┘  └──────┬───────┘
                                 │
                                 v
                          ┌──────────────┐
                          │ Sentinel HA  │
                          │ + AOF backup │
                          └──────────────┘
```

---

## Key Design Principles

1. **Redis as Source of Truth**: For hot data (agents, tokens). Git is optional (identity visibility only).
2. **Event-Driven**: All state changes emit events for audit + webhooks.
3. **Transaction Boundaries**: Atomic up to cache; webhooks are best-effort async.
4. **TTL-Based Cleanup**: No explicit delete cron; Redis TTL handles cleanup.
5. **Cascade on Revoke**: Agent revocation cascades to devices and tokens.
6. **Audit Trail**: All domain events logged for compliance (fn-89.5, fn-89.14).

---

## Integration Checklist (for fn-89.1 onwards)

- [ ] Read this document before starting fn-89.1
- [ ] Reference Redis keys from "Storage Locality" section
- [ ] Emit events per "Cross-Domain Event Contracts"
- [ ] Respect transaction boundaries from "Transaction Boundary Definitions"
- [ ] Use public APIs from "Domain Contracts & Public API Surface"

---

**Related Tasks**:
- fn-89.1: Redis Sentinel + failover
- fn-89.2: AOF backup + point-in-time recovery
- fn-89.5: Structured audit logging (emit_audit_event)
- fn-89.9: Token refresh endpoint
- fn-89.14: Audit query endpoint
- fn-89.15: Webhook delivery
