# ADR 004: OpenAPI spec generation — hand-rolled YAML, CI drift-gate

**Status:** Accepted
**Date:** 2026-04-20
**Scope:** Pairing daemon HTTP contract (`docs/api-spec.yaml`) and the
rule that keeps it in sync with the handler code.

## Context

The pairing daemon exposes six routes (see `crates/auths-pairing-daemon/src/router.rs:71-86`):

- `GET /health`
- `GET /v1/pairing/sessions/lookup`
- `GET /v1/pairing/sessions/{id}`
- `POST /v1/pairing/sessions/{id}/response`
- `POST /v1/pairing/sessions/{id}/confirm`
- `GET /v1/pairing/sessions/{id}/confirmation`

Today the only structural documentation is the Rust handler signatures in
`handlers.rs` and the error-code mapping in `error.rs`. The mobile team
hand-rolls `$MOBILE/shared/api-spec.yaml` by reading the Rust source.
This is slow, error-prone, and invisible to mobile CI's drift check
(`$MOBILE/scripts/ci/check-api-spec-drift.sh`, currently no-ops because
the canonical spec path does not exist).

The mobile hardening work requires a canonical spec in this
repo. The question is: how to produce it.

## Decision

**Maintain `docs/api-spec.yaml` as a hand-rolled OpenAPI 3.1 document,
enforced against handler/router changes by a PR-level CI drift check
and linted via Spectral.**

Rationale is spelled out in the *Alternatives considered* section.

## Alternatives considered

### A — Generate from Rust via `utoipa` + `utoipa-axum`

`utoipa` is the most mature crate in this space. It emits OpenAPI 3.0
(3.1 support has improved but is still partial at time of writing) from
macro-annotated handlers and types.

**Rejected for now because:**
- Every handler and response type requires `#[utoipa::path(...)]` and
  `#[derive(ToSchema)]` macros. For six routes the ratio of scaffolding
  to spec content is unfavorable.
- `utoipa`'s handle on OpenAPI 3.1 specifics (JSON Schema 2020-12
  alignment, `webhooks`, `pathItems` in components) is partial. We want
  3.1 for forward compatibility with the rest of the JSON-Schema-adjacent
  artifacts in this repo (e.g., `schemas/secure-envelope-kat.schema.json`).
- Binding the spec to handler-type derivations commits us to the exact
  layout of `SubmitResponseRequest` et al. Hand-rolling lets us emit a
  spec optimized for mobile-side ergonomics (examples, narrative
  `description`s, `x-canonical-signing-input` extensions describing how
  `Auths-Sig` and `Auths-HMAC` inputs are canonicalized) without
  contorting the Rust types to match.

Revisit at > 20 routes or when `utoipa` ships full 3.1 support.

### B — Generate via `aide`

`aide` is axum-native and is the only Rust crate with first-class
OpenAPI 3.1 support today. Lower macro noise than `utoipa`, but the
ecosystem is smaller and less battle-tested.

**Rejected because:**
- Same scaffolding burden as `utoipa` at this scale.
- Small ecosystem — one maintainer, sporadic releases. Adopting `aide`
  puts the daemon's public spec on an external timeline.

### C — Hand-rolled YAML + CI drift gate (accepted)

`docs/api-spec.yaml` is produced and maintained by hand. CI enforces:

1. **Lint** — `npx @stoplight/spectral-cli lint docs/api-spec.yaml`
   with `spectral:oas` as the baseline ruleset, plus any project-specific
   custom rules (minimum: every `/v1/pairing/sessions/*` path must
   declare at least one security scheme).
2. **Drift gate** — a small shell check that fails PRs which modify
   `crates/auths-pairing-daemon/src/{handlers,router,error}.rs` without
   a matching diff to `docs/api-spec.yaml`. A label (`api-no-spec-change`)
   set by the reviewer can override for changes that are provably
   spec-invariant (e.g., internal renaming).
3. **PR checklist** — `CONTRIBUTING.md`'s pull-request checklist gains a
   bullet calling out the spec-update requirement, so reviewers catch it
   even when CI label-overrides are in play.

Consequences:

- **Drift risk.** Non-zero. The mitigations above are cheap but not
  perfectly sound — a handler change that adds a new error variant but
  routes it through an existing status code will slip through the
  file-level drift check. Code review remains the last line of defense;
  `#[non_exhaustive]` on `DaemonError` partially mitigates this by
  forcing reviewers to look at every call site when a new variant lands.
- **Maintenance burden.** Low while the route count stays at roughly
  six. Rescales linearly with routes.
- **Generator lock-in.** Zero. If we later adopt `utoipa` or `aide`, the
  hand-rolled YAML is the spec-of-record that the generated version
  must match — a migration aid rather than a rewrite.

## Migration path to a generator

When one of these triggers fires, revisit the decision:

- Route count exceeds ~20 — hand-rolling no longer scales.
- `utoipa` ships full OpenAPI 3.1 — removes the 3.0/3.1 concern.
- A drift incident ships to mobile CI that the hand-roll + checklist
  missed — evidence that the current process is insufficient.

At that point the migration is: adopt `utoipa`, derive the initial
spec from handlers, diff against the hand-rolled YAML, reconcile
differences by either (a) adjusting the Rust types or (b) adding
`#[utoipa::...]` attributes, retire the hand-rolled file once the
generated output matches.

## Consequences

- **Spectral ruleset baseline**: `spectral:oas`. Custom rules (at minimum):
  - `auths-security-required-on-session-paths` — every
    `/v1/pairing/sessions/*` path declares at least one `security` entry.
  - `auths-servers-required` — top-level `servers` list is present with
    a non-empty placeholder URL.
- **Drift check baseline**: fail PR if
  `crates/auths-pairing-daemon/src/{handlers,router,error}.rs` changed
  without a matching change to `docs/api-spec.yaml`. Label
  `api-no-spec-change` overrides.

## References

- `crates/auths-pairing-daemon/src/router.rs:71-86` — route list.
- `crates/auths-pairing-daemon/src/error.rs` — error-code enum.
- `auths-mobile/shared/api-spec.yaml` — starting template for the hand-roll.
- OpenAPI 3.1.0: https://spec.openapis.org/oas/v3.1.0.html.
- Spectral: https://docs.stoplight.io/docs/spectral/9ffa04e052cc1-spectral-cli.
- `utoipa`: https://github.com/juhaku/utoipa.
- `aide`: https://github.com/tamasfe/aide.
