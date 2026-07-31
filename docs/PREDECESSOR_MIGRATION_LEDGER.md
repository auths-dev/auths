# Auths predecessor migration and deferral ledger

**Status:** Historical evidence inventory for the experimental
`auths-dev/auths` predecessor

**Current product:** [Auths](https://auths.dev)

**Current implementation:**
[auths-dev/auths-proof](https://github.com/auths-dev/auths-proof), whose
repository name remains a temporary coordinate

**Governing decisions:**
[public naming consolidation](https://github.com/auths-dev/auths-proof/issues/54),
[human approval and custody specification](https://github.com/auths-dev/auths-proof/blob/main/docs/specs/0029-human-approval-and-custody.md),
and [Phase 11 custody deferral](https://github.com/auths-dev/auths-proof/issues/59)

## Purpose

This ledger prevents two opposite mistakes: losing useful research from this
repository, or treating experimental predecessor code as assurance evidence
for the current Auths implementation.

The current project is intentionally identity-method agnostic. Nothing in this
ledger imports the predecessor's KERI coupling, broad signing APIs, storage
architecture, or platform assumptions. “Migrated” means a requirement or
bounded contract has an identified current owner. It does not mean predecessor
source was copied or that a deployable provider passed production gates.

## Dispositions

| Area | Predecessor evidence | Current disposition | Current authority | Remaining gate |
| --- | --- | --- | --- | --- |
| Secure Enclave | [`SecureEnclaveBridge.swift`](../crates/auths-core/swift/SecureEnclaveBridge.swift) demonstrates P-256 key creation, opaque key handles, public-key export, LocalAuthentication user presence, and signing. | **Contract migrated; implementation deferred.** The current design preserves opaque non-exportable keys and user presence, but replaces unchecked Rust FFI with a bounded, versioned helper-process protocol. | [AP-SPEC-029 sections 6.3 and 12](https://github.com/auths-dev/auths-proof/blob/main/docs/specs/0029-human-approval-and-custody.md) | [Issue #59](https://github.com/auths-dev/auths-proof/issues/59): helper protocol, hostile-message tests, Secure Enclave provider, restart/invalidation, packaging, recovery, and security review. |
| Custody and keychain | [`crates/auths-core/src/storage`](../crates/auths-core/src/storage) contains macOS/iOS keychain, Linux Secret Service, Windows Credential Manager, PKCS#11, encrypted-file, memory, and Secure Enclave work. Some platform paths are experimental or stubs. | **Provider-neutral boundary migrated; platform providers deferred.** Current `auths-custody` owns exact transaction-bound external signing and no private keys. It does not adopt the predecessor storage abstraction wholesale. | [`auths-custody`](https://github.com/auths-dev/auths-proof/tree/main/product/integrations/auths-custody) and [AP-SPEC-029 sections 6.1, 6.4–6.6](https://github.com/auths-dev/auths-proof/blob/main/docs/specs/0029-human-approval-and-custody.md) | [Issue #59](https://github.com/auths-dev/auths-proof/issues/59): capability discovery, explicit fallback, software/headless providers, native macOS/Linux/Windows evidence, lifecycle, and zeroization review. |
| Storage | The predecessor combines identity records, key material, alias indexes, passphrase caching, encrypted files, and operating-system stores behind storage interfaces. | **Requirements selectively preserved; architecture not migrated.** The current project keeps protocol/core semantics free of storage and makes custody an external product integration. Any future persistent provider must begin from its own threat model and narrow contract. | [AP-SPEC-029 ownership and non-goals](https://github.com/auths-dev/auths-proof/blob/main/docs/specs/0029-human-approval-and-custody.md) and [`auths-author`](https://github.com/auths-dev/auths-proof/tree/main/core/crates/auths-author) | [Issue #59](https://github.com/auths-dev/auths-proof/issues/59): protected persistence, corruption handling, rotation, backup, recovery, uninstall, and platform assessment. |
| Signing workflow | [`signing.rs`](../crates/auths-sdk/src/workflows/signing.rs) explores agent-first, hardware, and passphrase-backed signing fallbacks for commits and tags. | **Exact-request construction migrated; general workflow retired.** Current `auths-author` constructs domain-separated external signing requests and `auths-custody` rejects transaction substitution. The predecessor's general commit-signing path and silent fallback shape are not current product APIs. | [`auths-author`](https://github.com/auths-dev/auths-proof/tree/main/core/crates/auths-author), [`auths-custody`](https://github.com/auths-dev/auths-proof/tree/main/product/integrations/auths-custody), and [AP-SPEC-029](https://github.com/auths-dev/auths-proof/blob/main/docs/specs/0029-human-approval-and-custody.md) | [Issue #59](https://github.com/auths-dev/auths-proof/issues/59): bounded provider implementation, cancellation/unavailability behavior, exact approval binding, explicit fallback, and scoped security review. |

## What this ledger does not claim

- The predecessor implementation is not part of the current release-candidate
  source closure.
- The Swift bridge, platform stores, and signing workflow are not current
  production-custody evidence.
- Published predecessor `0.1.x` packages are not deleted, reclaimed, or
  rewritten by this notice.
- The current repository is not coupled to KERI or any other single identity
  method.
- Touch ID and other biometrics indicate operating-system-mediated user
  presence; they are not Auths identities and no biometric material belongs in
  Auths.
- This notice does not authorize repository archival, renaming, package
  yanking, publication, native binary distribution, or a production security
  claim.

## Reuse rule

Future work may study the predecessor as prior art, but every reused idea must
enter through the current owner boundary, a bounded pull request, current
tests, packaging evidence, and the applicable review gate. Historical code is
an input to design—not a shortcut around current assurance requirements.
