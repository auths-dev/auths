# Open-Source / Cloud Boundaries

How the open-source `auths` repo and the proprietary `auths-cloud` repo relate, where code belongs, and how to keep the boundary clean.

## Two repos, one product

```
auths  (open-source, MIT)              auths-cloud  (proprietary)
├── auths-crypto                       ├── auths-idp          (IdP verification)
├── auths-verifier                     ├── auths-cloud-sdk    (cloud business logic)
├── auths-core                         ├── auths-cloud-cli    (cloud CLI presentation)
├── auths-id                           ├── auths-registry-server
├── auths-sdk                          ├── auths-auth-server
├── auths-storage                      ├── auths-oidc-bridge
├── auths-cli                          ├── auths-scim-server
└── ...                                └── auths-cache
```

`auths` is the self-contained identity system: key management, signing, verification, KERI, Git storage. A developer can use it without ever touching `auths-cloud`.

`auths-cloud` adds enterprise features: IdP binding (OIDC/SAML), hosted registry, OIDC token bridge, SCIM provisioning. It depends on published `auths` crates from crates.io but never the reverse.

## Dependency direction

```
auths-cloud crates
    │
    │  depends on (via crates.io)
    ▼
auths crates
```

**The open-source repo must never depend on or reference the cloud repo.** This is the single most important rule. If a cloud feature needs something in core, the core change must be independently useful and merged first.

## Layer model

Both repos follow the same three-layer pattern:

| Layer | auths | auths-cloud | Responsibility |
|-------|-------|-------------|----------------|
| Domain | `auths-id`, `auths-core`, `auths-verifier` | `auths-idp` | Types, traits, pure logic. No I/O. |
| SDK | `auths-sdk` | `auths-cloud-sdk` | Orchestration. Calls domain functions, injects time, wires ports. No direct I/O -- uses trait abstractions. |
| Presentation | `auths-cli` | `auths-cloud-cli` | Argument parsing, user interaction, display. Owns concrete I/O implementations. |

Dependencies flow strictly downward: **Presentation -> SDK -> Domain**. Never upward.

## Where code belongs

**Put it in `auths` (open-source) when:**
- It's useful without an enterprise IdP (verification, signing, KERI, DID resolution)
- It's a type that must travel across the boundary (e.g., `SealType::IdpBinding`, `IdpBindingSummary`)
- It's read-side infrastructure (the verifier surfaces IdP bindings anchored in the KEL, but doesn't validate the IdP itself)

**Put it in `auths-cloud` (proprietary) when:**
- It requires enterprise IdP credentials or protocols (OIDC client secrets, SAML metadata)
- It's a cloud service (registry, auth server, OIDC bridge)
- It's write-side IdP logic (verifying tokens, creating bindings)

**Rule of thumb:** If removing the cloud repo would break the feature, it belongs in cloud. If the feature still works (just without enterprise IdP data), the core parts belong in open-source.

## Cross-boundary types

Some types must exist in both repos. These live in the open-source crate that needs them, with minimal dependencies:

| Type | Lives in | Why |
|------|----------|-----|
| `SealType::IdpBinding` | `auths-id` | KEL must recognize the seal variant during replay |
| `IdpBindingSummary` | `auths-verifier` | Verification reports include binding data (WASM/FFI compatible) |
| `IDP_BINDING_SEAL_TYPE` | `auths-verifier` | Constant for seal type matching |
| `IdpBindingAttestation` | `auths-idp` (cloud) | Full attestation with enterprise fields -- cloud only |
| `IdpVerifier` trait | `auths-idp` (cloud) | Provider-specific verification -- cloud only |

The pattern: **minimal summary types in open-source, full implementation types in cloud.**

## CLI delegation pattern

The core `auths-cli` provides a stub for cloud commands that delegates to the `auths-cloud` binary:

```
$ auths id bind-idp --provider okta ...

  auths-cli (open-source)
      │
      │  checks: is `auths-cloud` on $PATH?
      │
      ├─ YES -> spawns `auths-cloud id bind-idp --provider okta ...`
      │         (forwards all arguments, inherits stdio)
      │
      └─ NO  -> prints: "IdP binding requires Auths Cloud."
                         "Learn more: https://auths.dev/cloud"
```

This keeps enterprise dependencies out of the open-source binary while making the feature discoverable. The core CLI never imports cloud crates -- it only checks for an external binary.

## SDK port pattern

Both SDKs use port traits to abstract I/O, keeping business logic testable:

```rust
// auths-cloud-sdk/src/ports.rs
#[async_trait]
pub trait BrowserOpener: Send + Sync {
    fn open_url(&self, url: &str) -> Result<(), BindIdpError>;
}

#[async_trait]
pub trait CallbackServer: Send + Sync {
    async fn start_and_wait_for_callback(&self, port: Option<u16>)
        -> Result<CallbackResult, BindIdpError>;
}
```

Concrete implementations (`SystemBrowserOpener`, `LocalCallbackServer`) live in the CLI crate, not the SDK. Tests use mock implementations.

## Versioning and publishing

The cloud repo depends on published versions of core crates:

```toml
# auths-cloud/Cargo.toml
auths-id = "0.0.1-rc.3"    # from crates.io
auths-verifier = "0.0.1-rc.3"
```

When a core change is needed for a cloud feature:
1. Make the core change in `auths`, merge to main
2. Publish the affected crate(s) to crates.io
3. Bump the version in `auths-cloud/Cargo.toml`
4. Build the cloud feature on top

Never use `path = "../auths/crates/..."` dependencies in cloud. The published version is the contract.

## Checklist for cross-boundary work

When building a feature that spans both repos:

- [ ] Core types/traits merged and published first
- [ ] Cloud crate depends on published core version, not path
- [ ] No `auths-cloud` imports in any `auths` crate
- [ ] Domain logic has no direct I/O (file, network, browser)
- [ ] SDK orchestrates via injected ports, receives `now: DateTime<Utc>`
- [ ] CLI owns concrete I/O and calls SDK functions
- [ ] Stub command in core CLI delegates to cloud binary (no enterprise deps in open-source)
- [ ] Summary/read-side types in open-source, full implementation types in cloud
