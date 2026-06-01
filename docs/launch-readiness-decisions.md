# Launch-Readiness: What Needs You (critical-path unblock)

Every task left in epics B–H (`fn-136..142`) is blocked on one of three things below.
None is blocked on implementation effort. This is the list to clear so the rest can be
finished — most of it can't be done unattended without either corrupting an in-flight
refactor, guessing consensus-critical semantics, or standing up external infra.

## Blocker 1 — your `DeviceDID → CanonicalDid` refactor (commit it to unblock ~20 tasks)

The refactor is dirty across **auths-id (24), auths-sdk (16), auths-cli (11),
auths-verifier (8), auths-core (7), auths-storage (6)** + the node/python/swift bindings.
Anything touching those can't be cleanly committed (a partial commit won't build; a full
one bundles your WIP). **Committing or finishing this refactor is the single biggest
unblock.** Once it lands, these become straightforward:

- **B.1–B.6** (dual-index sigs): B.1 adds a `prior_index` field to `IndexedSignature`,
  which forces edits at ~10 construction sites in `auths-id` (inception/rotate/anchor/
  rotation/initialize) and `auths-sdk` (multi_sig) — all dirty today.
- **D.1/D.2** (wire receipts + KAWA into the verifier): lands in `verify.rs`, your most-
  edited file (~50 WIP lines).
- **D.6** (first-seen replay tests), **E.1** (route P-256 keygen through `CryptoProvider`),
  **F.1/F.3/F.4** (backup/sync/escrow — SDK/CLI), **G.1–G.4** (delegation — verifier/CLI).
- **D.4** is already done and green **in your working tree** (typed `Receipt.t`); commit it
  alongside the refactor — it touches verify.rs/server.rs/policy.rs which carry your WIP.
- **A.5 / A.14** (mobile-ffi dedup; KeyState accessor sweep) — same entanglement.

## Blocker 2 — design decisions (yours to make; I won't guess in crypto code)

| Decision | Where it gates | Options / recommendation |
|----------|----------------|--------------------------|
| **A.3** — may a KEL event deserialize without an inline `d`? | unblocks A.7 → A.16; B | `#[serde(default)]` on event `d:Said` is load-bearing today (SAID verified out-of-band). Keep it and drop `Default` only behind a custom deserializer, **or** require `d` inline. Recommend: keep serde-default, seal `Said`/`Prefix` against *empty-string* forgery instead (narrower fix). |
| **A.7** — pre-rotation commitment domain | A.16 fixtures; SPEC §3.2 | Resolved target = hash the **CESR-qualified qb64** verkey, not raw bytes. It changes on-disk digests → needs fixture regen + ideally a KERIox vector. Recommend: do it with H.3 so the change is cross-validated. |
| **A.13-DID** — `DelegateIsDelegator` semantics | finishes A.13 | Non-standard, never-consumed trait. A seal-waiver is a delegation-authorization bypass if wrong. Recommend: define it as "delegate inherits delegator authority **only when** its key state equals the delegator's," or drop the trait. Until decided, `validate_delegation` keeps requiring the seal (fail-closed). |
| **C.4 / m,n** — default multisig threshold | C.1–C.6, F.* | Pick the default `m`-of-`n` for shared-KEL inception (e.g. 2-of-3). Everything in Epic C and the kt-upgrade migration (C.6) keys off this. |
| **B wire-format gating** | B.2–B.4 | Confirm: dual-index is emitted **only** for key-removal rotations (prior_index=Some); normal rotations stay single-index. This keeps existing KELs byte-stable. Recommend: yes. |
| **A.5** — keep vs quarantine mobile-ffi | A.5, H.2 | Recommend KEEP + reroute to `auths_keri` types (per the dormant-crate audit), executed once the mobile WIP settles. |

## Blocker 3 — external infra / outward actions (need your hands or a machine I can't reach)

- **D.5** — stand up a single Auths-operated witness server + minimal OOBI.
- **H.3** — KERIox cross-impl CI gate. SPEC.md + `interop_vectors.rs` are the oracle/seed;
  this needs a `keriox` toolchain to generate `.cesr` vectors.
- **H.6** — live Rekor demo. The code is **done** (`auths-infra-rekor` is implemented, see
  the dormant-crate audit) — this is an end-to-end run against a real Rekor instance.
- **H.5** — file the deferred post-launch GitHub issues (the rows above + full RB/NRB
  accounting + scim/radicle keep-vs-archive). Needs `gh` auth; I didn't open public issues
  unattended. Draft bodies are this document's rows.
- **H.1 / H.4** — optional crate relocation + the doc sync that follows it. No crate moved,
  so H.4 is a no-op until H.1 is chosen.

## Fastest path to "done"

1. Commit/settle the CanonicalDid refactor → unblocks B, D.1/2/6, E.1, F, G, A.5, A.14, and lets D.4 commit.
2. Answer the six decisions above (≈20 min) → unblocks B emission/validation, C, A.7/A.16, A.13.
3. The three infra items (D.5, H.3, H.6) and H.5 issue-filing are yours; the code they depend on is in place.
