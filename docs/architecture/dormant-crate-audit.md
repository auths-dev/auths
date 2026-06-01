# Dormant / Deferred Crate Audit (pre-launch)

**Status: audit only — nothing deleted, nothing feature-gated.** Any removal or
gating is a separate, explicitly-approved post-launch task. This document records
who depends on each candidate crate and whether touching it would break a build
target or CLI surface, so the "should we delete X?" question has a written answer
instead of a guess.

Verified against the tree on the `dev-keriCompliantDevices` branch.

## Summary

| Crate | Workspace consumers | Build/CLI impact if removed | Verdict |
|-------|--------------------|-----------------------------|---------|
| `auths-infra-rekor` | `auths-cli` (unconditional) | Breaks the **default** `auths-cli` build and `auths artifact sign --log sigstore-rekor` | **KEEP — live** |
| `auths-scim` | none (no Rust consumers) | None | **KEEP — dormant, revisit post-launch** |
| `auths-radicle` | none (no Rust consumers) | None, but **under active WIP** this branch | **KEEP — WIP** |
| `auths-mobile-ffi` | none (separate workspace) | None to the main workspace | **KEEP — resolve per A.5** |

## auths-infra-rekor — KEEP (live, implemented)

- **Consumer:** unconditional dependency of `auths-cli` (`crates/auths-cli/Cargo.toml:49`,
  no feature gate). Wired at `crates/auths-cli/src/commands/artifact/mod.rs:252-253`
  via `auths_infra_rekor::RekorClient::public()` behind `auths artifact sign --log sigstore-rekor`.
  Deleting it breaks the **default** CLI build, not just an optional feature.
- **Implementation state — CORRECTION to the task spec:** the spec described
  `client.rs` internals as stubbed (`build_intoto_entry → json!({})`,
  `parse_entry_response → LogEntry::default()`). **That is stale.** As of this audit:
  - `build_dsse` builds a real DSSE envelope (`application/vnd.auths+json` payload,
    base64 payload + signature, PEM-encoded verifier key).
  - `parse_entry_response` parses a real inclusion proof and the checkpoint bound to
    that proof.
  - `grep todo!|unimplemented!|json!({})` across `crates/auths-infra-rekor/src` = **0 hits.**
- **Remaining gap:** the open item is the **end-to-end live demo** against a real
  Rekor instance (Epic H.6), i.e. proving an Auths-produced DSSE entry is accepted
  and round-trips — not unfinished code. Track under H.6, not as a deletion candidate.

## auths-scim — KEEP (dormant)

- **Consumers:** none. No workspace crate references `auths_scim` outside the crate
  itself; not a dependency in any `Cargo.toml`.
- **Stubs:** none (`grep todo!|unimplemented!` = 0).
- **Action:** none now. It compiles on its current build surface and harms nothing by
  existing. Capture a post-launch issue (Epic H.5) to decide keep-vs-archive once the
  SCIM provisioning surface is prioritized.

## auths-radicle — KEEP (active WIP)

- **Consumers:** none outside the crate itself.
- **State:** **actively modified on this branch** (dirty working-tree files under
  `crates/auths-radicle/src`). It is not dormant — it is in-progress. Do not gate or
  remove; that would collide with in-flight work.
- **Stubs:** none flagged.
- **Action:** none now; revisit post-launch with `auths-scim` if desired (H.5).

## auths-mobile-ffi — KEEP, resolve per A.5 (deferred)

- **Consumers:** none in the main workspace (it is its own Cargo workspace with its own
  lockfile and `target/`).
- **State:** under active WIP (dirty `src/lib.rs`, `identity_context.rs`,
  `pairing_context.rs`, plus untracked modules). Carries **2 stub/TODO markers** tied to
  the KERI-type duplication that A.5 (`fn-135.5`) addresses: a private `IcpEvent` with an
  in-body `x` signature field and duplicate `compute_said` / `compute_next_commitment` /
  `finalize_icp_event`, wire-incompatible with `auths_keri`.
- **A.5 resolution status — DEFERRED:** the A.5 reroute (consume canonical
  `auths_keri` types, externalize the signature via `serialize_attachment`) must edit
  `mobile-ffi/src/lib.rs`, which is currently **dirty with the user's `DeviceDID →
  CanonicalDid` WIP**. Editing it would entangle the dedup with that in-flight refactor
  and could not be cleanly committed. The recommended A.5 decision is **KEEP +
  reroute** (not quarantine), to be executed once the mobile WIP settles. Until then the
  duplicate is flagged here, not removed.

## What this audit deliberately does NOT do

- No crate deleted. No crate feature-gated out of the default build.
- No edit to `auths-scim` / `auths-radicle` build surfaces.
- The earlier `prompt.md` §8.4 draft that called for deleting `auths-infra-rekor` and
  gating `auths-scim`/`auths-radicle` is **rescinded for pre-launch** and recorded here
  only so the rescission is traceable.
