# ADR 008 — Credential-grade capabilities via ACDC + TEL (Epic F)

**Status:** Accepted
**Context:** Epic F ("ACDC + TEL credentials"). Capabilities and roles become
verifiable credentials — **ACDC** (Authentic Chained Data Containers) — with
KERI-native per-credential revocation — **TEL** (Transaction Event Log) — anchored
to the issuer's KEL. This is the credential-grade upgrade to Epic E's *advisory*,
delegator-anchored scope seal: per-capability revocation (revoke one credential
without rotating keys or revoking the identity), third-party verifiability, and a
holder-bound presentation model. It is **not** full vLEI/IPEX interop.

## Context

Epic F is optional to the core thesis — device-bound commit signing, provable by KEL
replay, needs none of it. It was nonetheless built **first-class, not as a deferred
afterthought**: when we ship credential-grade authorization it must be *robust* —
minimal trust surface, maximal trust guarantees. The non-negotiable v1 properties:
credentials are **holder-bound, never bearer**; revocation is **witnessed**
(transitively, via the KEL anchor) and **freshness-checked**, never
trust-on-first-sight-silently; both curves (**P-256 default + Ed25519**) are exercised
from day one; and the SAID layout is forward-compatible for `e` so edges are additive.
We defer *features* (full IPEX, edge/rule content, OIDC, escrow). We do **not** defer
security properties.

Exhaustive search at the start of Epic F found no ACDC/TEL/credential/registry code —
only forward-reference comments — but the exact KERI primitives needed already existed
and were keripy-1.3.4 byte-aligned (SAID-ification, CESR encoders, TEL→KEL anchoring as
a `Seal::KeyEvent` in an `ixn`, signing-time key recovery, KEL-position revocation
ordering, the policy-context bridge template). Epic F built the credential layer **on**
that substrate.

The decisions below were surfaced during gap analysis and are recorded here as the
load-bearing scoping and authority choices.

## Decisions

1. **D1 — ACDC is ADDITIVE, not a commit-time replacement.** Epic E's `agentscope:`
   seal + `Auths-Scope` trailer remain the *commit-time signing* fast path. ACDC subsumes
   the **attestation** authority fields (`capabilities`/`role`) — the migration target the
   roadmap names. Commit verification is **not** rewritten in v1; an `Auths-Credential`
   trailer that makes ACDC the commit-time authority is the deferred integration point
   (see Deferrals). This keeps blast radius sane and matches "not required for the core
   thesis."

2. **D2 — Backerless (`NB`) registry, with witness-enforced revocation.** Event types
   `vcp` (registry inception, once per issuer), `iss` (issuance), `rev` (revocation).
   Never `bis`/`brv`/`vrt`/TEL backers — a parallel trust system is the wrong mechanism.
   **Robustness comes from witnessing the KEL anchor, not from TEL backers:** every
   `vcp`/`iss`/`rev` is anchored by a `Seal::KeyEvent` in the issuer's KEL `ixn`, which
   post-Epic-D is witness-receipted. The F.9 pre-flight finding (proven by test) is that
   the Epic-D KEL gate quorum-gates *establishment* events only — "ixn never gates" — so
   the verifier (F.5) itself quorum-checks the **lifecycle anchoring ixns**
   (`vcp`/`iss`/`rev`) via the KAWA `WitnessAgreement` algorithm (Option A). See the
   composed witness claim below.

3. **D3 — Holder-bound minimal ACDC `{v,d,i,ri,s,a}` (NOT a bearer token).** The subject
   `a.i` is a **KERI AID** (D5 guarantees the issuee has a KEL); authority is honored only
   when the presenter proves current control of that AID. Possession of the ACDC alone
   grants nothing — this avoids the bearer-token red flag. For commit signing this is
   automatic (the signer's KEL). For third-party presentation, v1 requires a
   **presentation signature** by the subject's signing-time key over
   `(credential-SAID, audience, nonce)` (F.8) — a thin precursor to IPEX, not full IPEX.
   One pinned JSON-Schema-2020-12 capability schema; the schema SAID is embedded and
   immutable.

4. **D4 — Fail-closed + revocation-freshness (v1).** A TEL event whose KEL anchor is not
   present locally is rejected, never accepted (no escrow of out-of-order events). **Plus:
   freshness is a first-class verdict — owned by the SDK resolution layer, not the pure
   verifier.** The pure verifier (F.5) cannot resolve a KEL tip or judge staleness (no
   network, no clock of its own); it checks what it is handed and reports the **"as-of"
   position** of that input plus the witness-quorum status. The SDK `credentials::verify`
   (F.4) resolves the issuer KEL/TEL/receipts to the witnessed tip, then judges freshness:
   "not revoked" means no `rev` anchored at or before the resolved tip, and an
   unresolvable/stale tip yields `StaleOrUnresolvable` (fail-closed), never a silent valid.

5. **D5 — Separate issuance step.** Delegate first (`agents::add` / `org::add_member` →
   issuee gets a KEL), THEN `credentials::issue(issuer, issuee_did, caps, …)`; hard-fail if
   the issuee prefix has no KEL. The `vcp` registry is lazily incepted on first issuance
   per issuer.

6. **D6 — Revocation is per-CREDENTIAL** (TEL `rev`), distinct from the coarse
   `agents::revoke` (whole delegate). This per-capability granularity is what ACDC buys.

7. **D7 — SAID protocol tag parameterized.** `compute_said` previously hardcoded
   `KERI10JSON`; F.1 parameterized the version/protocol tag (a `Protocol` enum) so ACDC
   emits `ACDC10JSON…` for keripy interop. The 17-char version-string layout and **all KEL
   SAIDs are unchanged**.

8. **D8 — Dual-curve is a v1 acceptance gate, not a follow-up.** The agents suite was
   once Ed25519-only and hid a P-256 break for an entire epic. Epic F does not repeat that:
   every credential/TEL signature and every embedded key is **curve-tagged in-band** (CESR
   prefix / multicodec / explicit field — never dispatch on byte length), and the keripy
   fixtures **and** unit tests run issue → verify → revoke for **both P-256 (default) and
   Ed25519**. `check-curve-agnostic` stays at 0 violations.

### RegistryBackend freeze-touch resolution (F.3)

TEL storage required touching the **frozen** `RegistryBackend` trait. The resolution was
to **extend** it — `append_tel_event` / `visit_tel_events` / `store_credential`, plus an
`AtomicWriteOp::AppendTelEvent` and a `refs/.../tel/<reg>/<cred>/<sn>` layout. The
documented atomicity justification: the ACDC blob, the TEL event, and the KEL anchoring
`ixn` must land in **one commit**, mirroring the existing attestation write-batch
exception. `anchor_tel_event` reuses the staged single-author `ixn` path
(`author_root_anchor_ixn` was refactored into a `stage_root_anchor_ixn`), and
`ensure_registry` lazily incepts an idempotent backerless `vcp` per issuer. A `kt≥2`
issuer is rejected with a typed error (single-author anchoring only — same limit as Epic
E org delegation).

### `agentscope:` seal vs ACDC capability precedence (F.6)

There are two on-chain encodings of a capability/role grant, serving different decision
grades, reconciled by a documented `CapsSource` precedence rule
(`auths-id/src/policy/mod.rs`):

- **`agentscope:` scope seal** — the Epic-E `Seal::Digest` anchored in the delegator's
  `ixn`. It is **commit-time advisory**: the offline fast path a verifier reads straight
  off the KEL without a live presentation. It is the low-latency convenience source, not
  an authority of record.
- **ACDC credential** — the **authoritative** caps/role source for credential-grade
  decisions. Authority derived from it is honored only through a **holder-verified
  presentation** (F.8) at the policy seam (`context_from_credential`).

**Anti-divergence rule:** the same grant MUST NOT be authored into both encodings with
diverging caps/role. When both exist for one grant, `CapsSource::governing` selects the
ACDC — the credential governs the credential-grade decision; the `agentscope:` seal
remains valid only as the advisory commit-time fast path.

## The composed witness claim (F.9) — canonical assurance

This is the precise, honest statement of what `Valid` means under each witness policy.
It is quoted here verbatim as the canonical assurance:

> Under `RequireWitnesses`, a credential is `Valid` only if (a) the issuer's KEL
> establishment events reached quorum [Epic D], (b) its `vcp` *and* `iss` anchoring ixns
> reached quorum [F.5/A], and (c) no quorum-reaching `rev` anchor exists at/before the
> presentation's KEL position. Under `Warn` (default), under-quorum is a warning (TOFS)
> and `detect_duplicity` still catches revocation-hiding-via-fork.

## What shipped (NOT deferred)

These v1 properties **shipped** in Epic F and must not be mistaken for future work:

- **Holder-binding (F.8)** — credential-derived authority is honored only on proof of
  current control of the subject AID by KEL replay plus a fresh presentation signature
  over `(credential-SAID, audience, nonce)`. The interactive challenge-response path
  (verifier-issued single-use nonce) is the v1 default; a non-interactive
  `(audience, purpose, short-TTL)` path exists with a documented within-TTL residual.
  `PresentationVerdict` distinguishes `HolderNotCurrentKey` / `WrongAudience` /
  `NonceMismatchOrConsumed` / `Expired` / `SubjectKelInvalid` / `CredentialNotValid`.
- **Lifecycle witness-quorum (F.5/F.9)** — the verifier enforces witness quorum over the
  `vcp`/`iss`/`rev` anchoring ixns (not just establishment events) via KAWA, per the
  composed claim above. `WitnessQuorumNotMet` names which lifecycle anchor missed.
- **Revocation freshness (F.4)** — the SDK resolves to the witnessed tip and owns the
  `StaleOrUnresolvable` fail-closed verdict; absence-of-`rev` is never silently treated as
  valid.

## Threat model

Each attack is paired with its mitigation. The single residual is stated honestly.

- **Revocation-hiding / equivocation** → the `rev` event is **KEL-anchored**; hiding it
  requires forking the issuer's KEL. The anchoring ixns are **witnessed** under the F.5/F.9
  lifecycle witness-quorum (composed claim, depends on Epic D), and `detect_duplicity`
  flags the fork in both witness modes.
- **Credential theft / replay** → **holder-binding** (F.8): authority needs proof of
  *current* subject-key control via challenge-response (verifier-issued single-use nonce),
  not mere possession. A stolen ACDC blob grants nothing without the subject's current
  signing key.
- **Issuer key compromise + rotation** → the issuer signs with its **signing-time key**;
  verification recovers the key in force at the `iss` anchor position, so a `iss` forged
  with a post-rotation key does **not** verify. Recovery = rotate the issuer key and
  `rev` the affected credentials (or use the `vcp`-level kill-switch). Credentials issued
  before the compromise remain valid until explicitly revoked.
- **Registry / TEL fork** → `detect_duplicity` on the issuer KEL/TEL surfaces the
  divergence; the no-witness stance is **first-valid-seen + refuse** (verdict
  `IssuerKelDuplicitous`), never silent acceptance of a forked branch.
- **Downgrade / staleness** → the SDK freshness verdict `StaleOrUnresolvable` (F.4) plus
  the witness policy: an unresolvable/stale tip **fails closed**; the verifier never
  treats absence-of-`rev` against a stale view as "not revoked."
- **Revocation latency under `RequireWitnesses` (residual — stated honestly)** → a `rev`
  only revokes once it reaches quorum (claim (c) above), so the window between authoring a
  `rev` and its receipts reaching quorum leaves the credential `Valid` to a
  `RequireWitnesses` verifier. The hiding of that `rev` is still fork-detectable via
  `detect_duplicity`, and under `Warn` (default) a seen `rev` revokes immediately. This is
  the deliberate trade-off of witnessed fail-closed revocation; it is not a silent gap.
- **Schema substitution** → the capability schema SAID is **pinned and embedded**; an
  unknown or substituted schema SAID is rejected (`SchemaInvalid`).

## Epic-D dependency

The lifecycle witness-quorum (the witnessing of the `vcp`/`iss`/`rev` anchoring ixns, per
the composed claim) requires **Epic D** landed for its fail-closed mode. Until then, the
default `Warn` mode is honest **trust-on-first-sight** — the same caveat as the commit
path — with under-quorum surfaced as a non-fatal warning and `detect_duplicity` still
catching revocation-hiding-via-fork.

## Forward-compatibility honesty (no over-claim)

The most-compact SAID makes a future **top-level `e`** (edges) block additive: a v1
credential SAID is unchanged for present fields, so edges can be layered without a
breaking change. **Selective / graduated disclosure (`u`/`A`) is NOT additive** — `u`
lives inside the attributes block and changes `a.d` and `d`, so **selective disclosure is
a SAID-breaking v2** (a new schema/version). We claim forward-compatibility only for `e`,
never for SD.

## Consequences (assurance, stated precisely)

- A capability is a first-class, holder-bound, KEL-anchored credential: a third party
  verifies it purely by replay (SAID + embedded schema + issuer signing-time key + TEL
  status by KEL position + witness-quorum) and honors its authority only against a
  holder-verified presentation. No bearer token anywhere on the path.
- Per-credential revocation is independent of key rotation and identity revocation.
- Attestation-borne `capabilities` + `role` are no longer the authority of record — every
  reader was migrated off them (F.10) and the write path that stamped them was removed
  (F.11). OIDC + `delegated_by` remain on the attestation (deferred).
- Under `RequireWitnesses` the assurance is exactly the composed claim above, with the
  documented revocation-latency residual.

## Deferrals (tracked)

Each item below is genuinely out of Epic F v1 scope and has a tracking GitHub issue on
`auths-dev/auths` (each back-referencing this ADR). Holder-binding, lifecycle
witness-quorum, and freshness are **NOT** deferred — they shipped (see "What shipped").

1. **Backed registries (`bis`/`brv`/`vrt`/TEL backers)** —
   [#221](https://github.com/auths-dev/auths/issues/221). v1 is backerless `NB`; trust
   derives from the witnessed KEL anchor, not TEL backers.
2. **ACDC edge (`e`) + rule (`r`) content** —
   [#222](https://github.com/auths-dev/auths/issues/222). The SAID stays forward-compatible
   for a top-level `e`, so edges are additive; the *content* (chaining semantics, rule
   sections) is deferred.
3. **Selective / graduated disclosure (`u`/`A`) content** —
   [#223](https://github.com/auths-dev/auths/issues/223). This is a **SAID-breaking v2**
   (new schema/version), not additive — see "Forward-compatibility honesty."
4. **Full IPEX grant/admit choreography** —
   [#224](https://github.com/auths-dev/auths/issues/224). The v1 presentation *signature*
   (holder-binding over `(cred-SAID, audience, nonce)`) **shipped** in F.8; the full
   grant/admit protocol is deferred.
5. **TEL escrow of out-of-order events** —
   [#225](https://github.com/auths-dev/auths/issues/225). v1 rejects an unanchored TEL
   event rather than escrowing it.
6. **`Auths-Credential` commit trailer (ACDC as commit-time authority)** —
   [#226](https://github.com/auths-dev/auths/issues/226). The two-layer seam (D1) is
   documented; making ACDC the commit-time authority is the deferred integration point.
7. **OIDC → ACDC migration** —
   [#227](https://github.com/auths-dev/auths/issues/227). F.10/F.11 migrated `capabilities`
   + `role` only; OIDC binding stays on the attestation for v1.
8. **Dynamic / `oneOf` schema registry** —
   [#228](https://github.com/auths-dev/auths/issues/228). v1 pins one embedded
   JSON-Schema-2020-12 capability schema.
9. **`delegated_by` → ACDC edge** —
   [#229](https://github.com/auths-dev/auths/issues/229). `delegated_by` stays on the
   attestation; modeling delegation provenance as an ACDC edge depends on (2).

Already filed from F.10:

10. **ACDC-sourced capability gate for artifact/device verification** —
    [#220](https://github.com/auths-dev/auths/issues/220). F.10 removed the legacy
    attestation-borne capability gates on `auths artifact verify` and
    `auths device verify-attestation`; re-introducing a capability gate sourced from a
    holder-verified credential needs an issuer flow.

## Archived `auths-cloud` crates — reuse assessment

When the deferred server/integration items above are scheduled, four archived crates under
`_archived/auths-cloud/crates/` were assessed for reuse. **Cross-cutting finding:** each splits
cleanly into a *standards-driven transport/protocol half* (reusable, stable) and a *domain half*
built on the pre-Epic-E/F model — attestation `capabilities`/`role`, bearer/session tokens, the
removed `add_organization_member` path — which **conflicts with the current KERI/ACDC/KEL-signature
direction and must be rewritten**. Reuse the protocol layers; rewrite the domain layers.

| Archived crate | Verdict | Salvage | Tracking issue |
|---|---|---|---|
| `auths-oidc-bridge` | **Partial reuse — high value** | The OIDC *verification* half (resilient JWKS client w/ circuit-breaker + stale fallback, GitHub-OIDC claim verification, RFC 8693 delegation math) drops into the empty [`auths-oidc-port`] trait impls. The *minting* half issues **Bearer JWTs** — rewrite to mint **ACDC** instead. | [#227](https://github.com/auths-dev/auths/issues/227) (and vision [#119](https://github.com/auths-dev/auths/issues/119)) |
| `auths-scim-server` | **Reuse protocol crate, rewrite server** | Port the `auths-scim` crate as-is (RFC 7643/7644 types, filter parser, PATCH ops, discovery endpoints, SCIM errors — already separated from business logic). Rewrite `/Users` handlers off the agent-stored `capabilities` column onto the KEL-native `org::delegation` (`add_member`/`revoke_member`), add an `/Orgs/{id}/Members` route, replace bearer auth with KEL signatures. | [#215](https://github.com/auths-dev/auths/issues/215) |
| `auths-witness` | **Do not reuse — build fresh** | It is a **C2SP transparency-log checkpoint cosigner**, not a KERI event-receipt witness — **zero protocol overlap** with `WitnessAgreement`/`StoredReceipt`/`rct`. The repo already has the witness primitives + an HTTP client expecting `/witness/{prefix}/event`; a fresh ~500-line server against those is cheaper than retrofitting. | [#221](https://github.com/auths-dev/auths/issues/221), [#202](https://github.com/auths-dev/auths/issues/202) |
| `auths-registry-server` (~18.5k LOC) | **Rewrite, salvage HTTP scaffold** | Reusable plumbing only: error→RFC 9457 mapping, middleware/rate-limit/CORS, pairing-store ports, multi-tenant resolver, Stripe billing glue. Rewrite all org/device/verify/artifact routes to call the SDK credential domain (they embed business logic + the old attestation model); auth → KEL signatures; the 2.5k-LOC sequencer belongs in `auths-transparency`. Reference, not a drop-in. | (no dedicated issue — credential-server work) |

[`auths-oidc-port`]: ../../../crates/auths-oidc-port

## References

- `docs/architecture/keri-only-roadmap.md` §"Epic F"
- `docs/getting-started/credentials.md` (issue / verify / present / revoke guide)
- `docs/getting-started/delegation.md` (the Epic-E advisory scope seal this upgrades)
- `docs/architecture/cryptography.md` → "Wire-format Curve Tagging" (D8 in-band tagging)
- `docs/architecture/multi_device_accepted_risks.md` (`kt=1`, no-witness baseline)
- ADR 006 (witness receipting & duplicity — the Epic-D substrate the composed claim rests on)
- ADR 007 (agent identity via delegation — the advisory scope seal; same deferral convention)
- ACDC spec (ToIP): <https://trustoverip.github.io/kswg-acdc-specification/>
- PTEL (Public TEL) spec: <https://trustoverip.github.io/tswg-ptel-specification/draft-pfeairheller-ptel.html>
- Code anchors: `auths-keri/src/{acdc.rs,tel.rs,said.rs}`;
  `auths-id/src/keri/credential_registry.rs`, `auths-id/src/policy/mod.rs`
  (`context_from_credential`, `CapsSource`); `auths-verifier/src/{credential.rs,presentation.rs}`;
  `auths-sdk/src/domains/credentials/` (issue/revoke/list/verify/present).
