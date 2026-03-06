# auths-scim

## Overview

`auths-scim` is the SCIM 2.0 protocol library for Auths. It provides pure protocol types, field mapping, filter parsing, and PATCH application logic for provisioning agent identities via the SCIM standard (RFC 7643 / 7644).

This crate sits at **Layer 3** in the Auths architecture — above cryptographic primitives and identity logic, but below any HTTP server or storage code. It has **zero dependencies on `auths-sdk`, databases, or HTTP frameworks**, making it reusable across different server implementations.

## Core Functionality

### SCIM Resource Types

The primary resource is `ScimUser`, representing an Auths agent identity with an optional extension:

```rust
use auths_scim::{ScimUser, AuthsAgentExtension};

let user = ScimUser {
    schemas: ScimUser::default_schemas(),
    id: "uuid-123".into(),
    user_name: "deploy-bot".into(),
    display_name: Some("Deploy Bot".into()),
    active: true,
    // ...
    auths_extension: Some(AuthsAgentExtension {
        identity_did: "did:keri:Eabc123".into(),
        capabilities: vec!["sign:commit".into(), "deploy:staging".into()],
    }),
    // ...
};
```

The `AuthsAgentExtension` schema (`urn:ietf:params:scim:schemas:extension:auths:2.0:Agent`) surfaces the KERI DID and capability set that are unique to Auths.

### Filter Parsing

A full nom-based parser for SCIM filter expressions (RFC 7644 Section 3.4.2.2):

```rust
use auths_scim::parse_filter;

let filter = parse_filter(r#"userName eq "deploy-bot" and active eq "true""#)?;
// Produces: ScimFilter::And(Compare { .. }, Compare { .. })
```

Supported operators: `eq`, `ne`, `co`, `sw`, `pr`, `and`, `or`, `not`, parenthesized grouping, and schema-qualified attribute paths.

### PATCH Operations

Applies SCIM PATCH operations (RFC 7644 Section 3.5.2) to a `ScimUser`:

```rust
use auths_scim::{apply_patch_operations, PatchOperation};

let ops = vec![PatchOperation {
    op: "Replace".into(),
    path: Some("active".into()),
    value: Some(serde_json::Value::Bool(false)),
}];
let patched = apply_patch_operations(user, &ops)?;
```

Enforces immutability on `id`, `userName`, `meta`, and `identityDid`. Supports Azure AD-style title-case operation names and path-less Replace operations.

### Field Mapping

Conversion functions between SCIM protocol types and Auths domain DTOs:

| Function | Direction |
|----------|-----------|
| `scim_user_to_provision_request()` | SCIM User -> `ProvisionAgentRequest` |
| `provision_result_to_scim_user()` | `ProvisionAgentResult` -> SCIM User |
| `scim_user_to_update_fields()` | SCIM User -> `UpdateAgentFields` |

These DTOs keep `auths-scim` decoupled from `auths-sdk` — the server layer bridges between them.

## Architecture

```
auths-scim (Layer 3 — Protocol Types)
├── constants.rs    Schema URIs
├── resource.rs     ScimUser, ScimMeta, AuthsAgentExtension
├── list.rs         ScimListResponse<T>
├── schema.rs       ServiceProviderConfig, ResourceType
├── error.rs        ScimError (15 variants), ScimErrorResponse
├── filter.rs       nom parser -> ScimFilter AST
├── patch.rs        PatchOp application with immutability checks
└── mapping.rs      SCIM <-> Auths DTO conversions
```

## Where It Fits

```
Identity Providers (Okta, Azure AD, OneLogin)
        │
        ▼  SCIM 2.0 protocol
┌───────────────────┐
│ auths-scim-server │  ← HTTP server (Layer 6)
│ (axum + postgres) │
└───────┬───────────┘
        │  uses
┌───────▼───────────┐
│    auths-scim     │  ← this crate (Layer 3)
│ (protocol types)  │
└───────────────────┘
        │  DTOs bridge to
┌───────▼───────────┐
│    auths-sdk      │  ← identity lifecycle (Layer 5)
└───────────────────┘
```

## SCIM Features Supported

| Feature | Status |
|---------|--------|
| User resource (RFC 7643) | Supported (userName, displayName, active, externalId) |
| Auths agent extension | Supported (identityDid, capabilities) |
| Filtering (RFC 7644 3.4.2.2) | Parsed (eq, ne, co, sw, pr, and, or, not, grouping) |
| PATCH operations (RFC 7644 3.5.2) | Supported (Add, Replace, Remove) |
| Immutability enforcement | Supported (id, userName, meta, identityDid) |
| Capability allowlist validation | Supported |
| Discovery types | ServiceProviderConfig, ResourceType, Schema |
| Error responses (RFC 7644 3.12) | Supported with HTTP status mapping |
