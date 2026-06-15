# PRD: The Agent That Wouldn't Die — fleet-wide, mid-flight, sub-second revocation

> **One line:** an autonomous agent goes rogue 40 minutes into a multi-server task;
> an operator hits revoke, and the agent's **very next tool call on ANY server in
> the fleet** is rejected in **under a second** — no token-expiry to wait out, no
> CRL to push, and a presentation captured before the revoke **cannot be replayed**
> after it.
>
> **Scope:** an auths **agent demo** in the lineage of `death-of-the-api-key`
> (evocative narrative · a recurve `gaps.yaml` of falsifiable claims that sculpt
> `../auths` · behavioral probes with accept + adversarial paths · a staged
> `run.sh` dramaturgy). This one is **distinct**: where death-of-the-api-key kills
> **one** agent at **one** server, this kills a **fleet** of verifiers
> **mid-flight** and proves it with a **measured sub-second SLO** and a
> **replay-resistant** capture. It is the demo body of aspirational claim **OPS-1**
> ("global revocation propagates to active verifiers in <1s p99, measured") — and
> it must **build the missing surface** that claim's baseline flagged: today an
> independent verifier that does not share the issuer's store gets `RESOLVE_FAIL`,
> so the **global** SLO is unmeasurable.
>
> **Honesty:** the kill switch and the per-RP pull cadence already EXIST
> (`auths-rp` `RegistrySync`/`RegistryWatcher`/`GitRegistrySync`, proven by
> `DOTAK-4` closed). What does NOT yet exist is a **global resolution/propagation
> surface** an arbitrary independent verifier can use to learn an issuer's
> credential at all (OPS-1 baseline: `RESOLVE_FAIL`). That gap is this demo's
> headline build. Where a beat is spiked (designed, not cold-sculpted) it says so.

---

## 1. One line + the scenario

**Actors.** `acme-corp` (the org root). `dev-mara` (a developer, delegated by the
org). `ops-agent-7` (an autonomous ops/coding agent, delegated by `dev-mara`,
scope `{fs:read, fs:write, deploy:staging}`). The **fleet**: three independent
tool servers the agent is mid-task against — `mcp-files` (a workspace file
server), `mcp-ci` (a build/deploy server), `mcp-data` (a record store) — each a
separate process with its **own** registry replica, each **sharing nothing** with
the issuer but the wire.

**The moment.** `ops-agent-7` is **40 minutes into a multi-step migration**: it has
read 200 files on `mcp-files`, opened a build on `mcp-ci`, and is streaming rows
through `mcp-data`. A poisoned record it ingests on `mcp-data` contains a
**prompt injection**; the agent's plan is hijacked and it begins exfiltrating
secrets and issuing destructive writes **across all three servers at once**. An
on-call operator sees the anomaly and hits **one revoke**.

**How it breaks TODAY.**
- **Bearer tokens / API keys:** the agent holds a copyable secret accepted by all
  three servers. "Revoke" means rotate the key and **redeploy/restart every
  server** to reload it — minutes of propagation, and any in-flight request with
  the old key still succeeds. The stolen token works until every consumer is
  reconfigured.
- **OIDC:** the agent bears a JWT. Access tokens are **valid until expiry** (5–60
  min); revocation is an *introspection* call the RP must opt into, and downstream
  resource servers typically **don't** — so the agent keeps acting for the token's
  remaining lifetime. You cannot kill it mid-flight; you can only out-wait it.
- **Sigstore / short-lived certs:** identity is a **10-minute cert**. There is no
  revoke — the model *is* "wait for expiry." Mid-flight, the agent's cert is still
  valid; the only "kill" is to not re-issue, which does nothing to the live cert.

**What auths does.** The agent presents a **signed, single-use, audience-bound
proof** of a delegated `did:keri:` identity — never a bearer token. The operator
anchors **one `rev` event** in `acme-corp`'s KEL. Each server's verifier loop pulls
`refs/auths/*` over the wire; the agent's **next call on every server** re-verifies
against fresh key-state and is **rejected** — measured **<1s p99**. The injection's
captured pre-revoke presentation, replayed after, is **rejected** (single-use
challenge already consumed; revoked delegation no longer honored). No restart, no
expiry wait, no CRL push.

## 2. The property it proves

**Instant fleet-wide revocation with no propagation window, replay-resistant.** One
signed event at the issuer kills the agent at **every independent verifier in the
fleet**, on its **next call**, within a **measured** sub-second bound — and a
presentation captured before the revoke is dead after it.

Why incumbents **structurally cannot** match this:

| Incumbent | The structural reason it can't |
|---|---|
| **API keys / bearer tokens** | A secret is **valid by possession**. There is no per-request authority check to flip; "revoke" means re-key every consumer and redeploy. No mid-flight kill, and the stolen copy keeps working. |
| **OIDC / JWT** | Authority is **cached in a self-contained token until expiry**. Resource servers don't introspect per call; revocation is an opt-in side channel most downstreams ignore. The propagation window **is the token lifetime** — minutes, by design. |
| **Sigstore (Fulcio)** | The model is **short-lived certs with no revocation** — expiry *is* the safety mechanism. There is nothing to revoke mid-flight; you wait the cert out. |

auths re-derives authority **from the event log on every request**, so flipping one
event flips every verifier at the speed of a pull — and the verify is offline +
fail-closed, so a verifier that can't refresh **rejects** rather than fails open.

## 3. Goals — what makes this believable, not a toy

- **G1 — Real independent verifiers.** Three separate verifier processes, each with
  its **own** `AUTHS_HOME` / keychain / registry replica, **sharing nothing** with
  the issuer but the git wire — exactly the "shares nothing" discipline the OPS-1
  baseline harness already pins. No shared-filesystem stand-in for the kill.
- **G2 — A measured number, not a vibe.** revoke→first-reject latency at an
  **independent** verifier reported as **p99 over N≥1000 warm trials**, with
  **warmup**, **pinned-rig notes** (host/uname/cpu/bin-sha printed in the probe
  output), and **hysteresis** so the gate can't flap across machines. The headline
  is a recorded percentile, asserted **< 1s**.
- **G3 — Fleet-wide, not point.** The kill must land on **every** server's next
  call, not one — the claim is **reach**, measured as the **max** revoke→reject
  across the fleet, not the best case.
- **G4 — Mid-flight, not between-tasks.** The agent is in an active multi-server
  loop when revoked; the show proves a **live** call dies, not a fresh handshake
  refused.
- **G5 — Replay-resistant, captured live.** A real pre-revoke presentation is
  captured on screen and replayed post-revoke; rejection is shown, not asserted.
- **G6 — Fail-closed everywhere.** A verifier that cannot refresh, or that sees a
  rewound remote, **rejects**; a revoked-after-honored verdict is the catastrophe
  the whole demo guards against and is a permanent RED trap.

## 4. Functional requirements AS CLAIMS

Each FR names a probe-able **observable** (accept path) and its **adversarial twin**
(fail-closed path that must be rejected). Each maps to **OPS-1** and notes where it
**builds the missing global resolution/propagation surface**. Each is claimify-ready:
a recurve probe is writable directly from it.

- **FR-1 — Independent verifier resolves a live credential (the missing surface).**
  *Observable:* a verifier sharing **nothing** with the issuer (own HOME/keychain/
  store) resolves the issuer's currently-live credential to `status=valid` over a
  propagation surface. *Adversarial twin:* a verifier that resolves **only** via the
  issuer's own store, or that emits a phone-home signal to a third party, fails.
  *OPS-1 link:* this is the headline build — OPS-1's baseline RED is exactly
  `RESOLVE_FAIL` here; nothing in `../auths` yet lets an arbitrary verifier learn an
  issuer's credential. **BUILDS** the global resolution surface.

- **FR-2 — revoke→first-reject at an INDEPENDENT verifier, < 1s p99, measured.**
  *Observable:* from the instant `credential revoke` returns, an independent
  verifier's poll loop flips the credential to `revoked`; latency measured over
  **N≥1000** warm trials (25-run warmup discarded), **p99 reported and asserted
  < 1000 ms** with a hysteresis margin, under **pinned-rig** notes printed inline.
  *Adversarial twin:* a poll that still reports `valid` after revoke → immediate RED
  (fail-open is the forbidden state); a fixed-ms threshold that flaps cross-machine
  is BROKEN, not a verdict. *OPS-1 link:* this **is** OPS-1's measured SLO, lifted
  from same-storage (already PASS at baseline, p99≈21 ms) to the **independent**
  loop OPS-1 could not yet measure. **BUILDS + measures** the propagation surface.

- **FR-3 — Fleet-wide kill: the agent dies at EVERY server on its next call.**
  *Observable:* with N independent servers (≥3) each on its own replica, one revoke
  is followed by the agent's next call to **each** server being rejected; the
  reported metric is the **max** revoke→reject across the fleet, asserted < 1s p99.
  *Adversarial twin:* **any** server in the fleet honoring the credential after the
  revoke window → RED (a single straggler verifier breaks "fleet-wide"). *OPS-1
  link:* extends OPS-1 from one verifier to a **fleet**; the surface FR-1 builds
  must fan out to N replicas, not one.

- **FR-4 — In-flight call dies (mid-task, not between handshakes).**
  *Observable:* the agent is in a live request loop (one real call/second, all
  `200`); the revoke lands **during** the loop and the loop self-terminates on a
  real `401`/`revoked` without a restart or a new handshake. *Adversarial twin:* a
  show that revokes only between tasks and refuses a *fresh* handshake (never proves
  a live call dies) is not the claim — the probe must kill an **already-running**
  loop. *OPS-1 link:* OPS-1's "active verifier" made concrete as a live agent loop.

- **FR-5 — Pre-revoke presentation replayed post-revoke → REJECTED (replay-resistance).**
  *Observable:* a real presentation captured **before** the revoke is replayed
  **after** it and is rejected, for **two independent reasons** — the single-use
  challenge was consumed at first use **and** the underlying delegation/credential
  is now revoked. *Adversarial twin:* a replayed capture that verifies `valid` after
  revoke → RED (the exact theft this demo exists to defeat). *OPS-1 link:* the
  replay window is the "propagation window" restated as **time-travel resistance** —
  no captured proof survives the revoke.

- **FR-6 — Fail-closed under transport failure / rollback.**
  *Observable:* a verifier whose wire is cut (cannot refresh) **rejects** rather than
  serving stale-valid; a remote that **rewinds** its history to resurrect a revoked
  credential is refused (non-forced fetch) and the replica keeps the newest tip it
  saw. *Adversarial twin:* a verifier that fails **open** (honors the credential when
  it cannot confirm freshness), or accepts a rolled-back remote tip → RED. *OPS-1
  link:* the SLO is only meaningful if "can't refresh" means "reject"; this guards
  the surface FR-1/FR-2 build. Uses `auths-rp`'s existing non-forced refspec
  (already shipped — see §5), so this FR is near-term, a guard over existing code.

> **Quality bar (every perf FR):** pinned-rig notes recorded in output; warmup runs
> not counted; N≥1000; p99 reported and asserted; hysteresis band so the gate does
> not flap; BROKEN (not RED) on a missing tool; a revoked-as-valid result is RED
> immediately and unconditionally.

## 5. The auths surfaces it builds / exercises

Read from `../auths/crates`. **EXISTS** = real today; **BUILD** = this demo's net-new
surface.

**EXISTS (exercise + regression-guard):**
- `auths-cli` `credential` verbs — `issue` / `revoke` (anchors a `rev` in the issuer
  KEL, idempotent) / `present` / `verify` / `list`
  (`crates/auths-cli/src/commands/credential.rs:30-137`). The kill switch itself is
  done; `DOTAK-1` (flagship MCP-auth wiring) is **closed**.
- `auths-rp` registry sync — the propagation **cadence**: `RegistrySync` (port, one
  pull → typed `SyncOutcome`), `RegistryWatcher` (the interval loop on its own
  thread), `GitRegistrySync` (feature `git-sync`: a **non-forced** fetch of
  `refs/auths/*`, fail-closed against a rewound remote)
  (`crates/auths-rp/src/registry_sync.rs:1-30, 122, 160, 290`). `DOTAK-4` proved this
  is a real git-wire pull, not a shared-filesystem read.
- `auths-mcp-server` `keri_auth` — offline, fail-closed presentation verification +
  single-use challenge consumption (`verify` at
  `crates/auths-mcp-server/src/keri_auth.rs:135`), the per-RP verifier each fleet
  member runs. The challenge store backing FR-5's replay rejection lives here +
  `auths-rp/src/challenge.rs`.
- `auths-verifier` — `presentation.rs` (the offline `verify_presentation` path that
  must learn a revoked delegation), `credential.rs` (KEL/TEL replay → `status`),
  `software_verify.rs` (no-network verify, the PRV-3 no-phone-home guarantee FR-1's
  adversarial twin relies on).
- `auths-sdk` `domains/credentials` — `authenticate.rs` / `verify.rs` /
  `freshness.rs` (revocation freshness = the pull cadence) / `present.rs` / `issue.rs`.

**BUILD (the missing surface — OPS-1's `RESOLVE_FAIL`):**
- A **global resolution/propagation surface** an arbitrary independent verifier can
  point at to resolve an issuer it shares no store with — today
  `auths-storage/src/git/sync.rs:204` `pull_registry` returns merged KELs only and
  no live wire delivers an issuer's credential to a stranger verifier
  (OPS-1 evidence). Smallest honest form: stand each fleet verifier on its own
  `GitRegistrySync` replica seeded from the issuer's published `refs/auths/*` remote
  (the same machinery `DOTAK-4` shipped, generalized from one RP to N), so "resolve
  a stranger's credential" stops returning `RESOLVE_FAIL`. This is the seam OPS-1
  named; the demo's job is to make it real and **measured** at fleet scale.
- A **fleet perf harness** — pinned-rig, warmup, N≥1000, hysteresis — that times
  revoke→first-reject at the **independent** loop (FR-2) and across N servers (FR-3),
  reusing the OPS-1 rig discipline (`roadmap/aspirational_claims/probes/ops-revocation-slo.sh`)
  rather than inventing a second timing methodology.
- *(Optional, spiked)* a **delegator-revocation** verdict on the presentation path,
  so revoking the **delegation** (not only the leaf credential) also kills the agent
  — `DOTAK-3` is the open precedent (`PresentationVerdict` has no
  `DelegationRevoked` variant today). Mark spiked; the leaf-credential revoke is the
  near-term kill.

## 6. Non-goals

- **Not a live LLM mid-show.** The injection and the agent's intents are **scripted**
  (offline-first, same as DOTAK-9); every challenge, signature, HTTP status, revoke
  event, and latency is **real and live**. Disclosed on screen.
- **Not literal N physical machines.** The fleet is N processes on one box, each with
  its own HOME/keychain/replica pulling over a `file://` git remote (real ref
  negotiation + object transfer). A literal fleet swaps only the URL scheme — the
  transport machinery is identical (DOTAK-4 precedent).
- **Not a new revocation mechanism.** Reuse `credential revoke` (the anchored `rev`);
  this demo proves **reach + speed + replay-resistance**, not a new kill primitive.
- **Not the deep-chain/scale claims.** OPS-2 (10-deep verify latency) and OPS-3
  (10⁶-registry bound) are separate claims; cite, don't re-prove.
- **Not did:webs/DNS resolution or OOBI discovery.** The propagation surface here is
  the git-wire replica; universal resolution (`RES-*` in the missing-layer PRD) is a
  larger, separate rung.

## 7. The narrative / run.sh dramaturgy

Staged like death-of-the-api-key's `run.sh` (acts, pledge-before-proof, a live
server-log tail, a `gate` for the revoke, `DEMO_AUTO`/non-TTY plays the operator
itself). Setup (build + bootstrap the org→dev→agent delegation + start the **three**
servers, each on its own replica) is explicitly "not the show yet."

- **Act 1 — The old world.** Show the agent holds **no bearer secret** a server would
  accept (`env | grep` finds no api_key/token/secret); name what OIDC/Sigstore would
  do here (wait out a token; wait out a cert). Disclose: intents scripted, crypto live.
- **Act 2 — The delegation.** `org → dev-mara → ops-agent-7`, all signed, all in git;
  scope `{fs:read, fs:write, deploy:staging}`. Show the three servers each on a
  **separate** replica (`rev-parse` three distinct tips; none is the issuer's store).
- **Act 3 — The agent works, mid-flight.** The agent runs a real multi-server loop —
  reads on `mcp-files`, a build on `mcp-ci`, rows on `mcp-data` — every call a live
  `200` with the verified `did:keri:` principal in three server logs. **Capture one
  successful presentation** on screen (we need its bytes for Act 6).
- **Act 4 — The injection.** `mcp-data` returns a poisoned record; the agent's plan
  is hijacked and it starts destructive writes + exfil **across all three servers**.
  The loop is live and damaging — `200`s still streaming.
- **Act 5 — The kill shot (the unsee-able moment).** Pledge: "one signed event in the
  org's KEL; it must travel the wire to three independent replicas before the agent's
  next call on any of them." `gate` → **revoke**. The fleet loop self-terminates on
  real `401`/`revoked`. Show the **measured** number live: revoke→first-reject p99
  across the fleet (pinned-rig line printed), asserted **< 1s**. Show three replica
  tips advance to match the issuer's — the kill traveled a **git wire**, not a shared
  read. *"That was not a cache purge, a redeploy, or a call to three vendors."*
- **Act 6 — Dessert: the captured proof is worthless.** Replay Act 3's captured
  presentation **verbatim** → `401`. Show **both** reasons: single-use challenge
  consumed, and the delegation/credential now revoked. *"A proof captured before the
  revoke cannot be replayed after it — the window other systems make you wait out
  does not exist here."* End on the line Sigstore (wait for expiry) and OIDC (token
  lifetime) **cannot** say: **the agent died fleet-wide, mid-flight, in under a
  second, and its stolen proof died with it.**

## 8. Success metrics

- **The number:** revoke→first-reject at an **independent** verifier, **p99 < 1000 ms**
  over **N≥1000** warm trials, pinned-rig notes recorded — the headline procurement
  line. (Baseline reference: OPS-1's same-storage loop already measures p99≈21 ms;
  the open work is reproducing this at the **independent** + **fleet** loop.)
- **The reach:** **max** revoke→reject across **≥3** independent servers is < 1s p99;
  **zero** stragglers honor the credential after the window.
- **The verdict:** the in-flight loop self-terminates on a real `401`/`revoked` with
  **no** restart and **no** fresh handshake.
- **The dead replay:** the pre-revoke captured presentation, replayed post-revoke, is
  **REJECTED** — and the adversarial trap (replay verifies `valid`) stays RED forever.
- **Fail-closed:** a wire-cut verifier **rejects**; a rewound remote is refused; a
  revoked-as-valid result is an immediate, unconditional RED.

## 9. Recurve gap sketch

Draft claims to `recurve init --from-prd` (riclib gap style: id, one-line, class,
covers OPS-1, proposed probe, accept + adversarial). `status: open` ⇒ probe RED at
baseline; `closed` ⇒ GREEN regression guard.

```yaml
- id: AGENT-KILL-1
  title: "Independent verifier resolves a live credential — the global propagation surface exists"
  class: missing-surface         # OPS-1 baseline RED is exactly RESOLVE_FAIL here
  status: open
  covers: ["OPS"]
  probe: probes/agent-kill-resolve.sh
  accept: >
    a verifier sharing nothing with the issuer (own HOME/keychain/store) resolves
    the issuer's currently-live credential to status=valid over a propagation surface.
  adversarial: >
    a verifier that resolves only via the issuer's own store, or that emits a
    phone-home signal to a third party, fails — RESOLVE_FAIL is not GREEN.

- id: AGENT-KILL-2
  title: "revoke->first-reject at an INDEPENDENT verifier < 1s p99, measured"
  class: friction                # measured SLO; the OPS-1 number lifted off shared storage
  status: open
  covers: ["OPS"]
  probe: probes/agent-kill-slo.sh
  accept: >
    from credential revoke returning, an independent verifier's poll loop flips to
    revoked; p99 over N>=1000 warm trials (25 discarded), asserted <1000ms with a
    hysteresis margin, pinned-rig notes printed inline.
  adversarial: >
    a poll that still reports valid after revoke -> immediate RED; a fixed-ms gate
    that flaps cross-machine is BROKEN, not a verdict.

- id: AGENT-KILL-3
  title: "Fleet-wide kill: the agent dies at EVERY server (>=3 replicas) on its next call"
  class: friction
  status: open
  covers: ["OPS"]
  probe: probes/agent-kill-fleet.sh
  accept: >
    one revoke; the agent's next call to each of N>=3 independent servers is
    rejected; reported metric is the MAX revoke->reject across the fleet, <1s p99.
  adversarial: >
    any single server honoring the credential after the window -> RED (a straggler
    breaks fleet-wide).

- id: AGENT-KILL-4
  title: "In-flight call dies — an already-running loop is killed mid-task, no restart"
  class: missing-surface
  status: open
  covers: ["OPS", "AGT"]
  probe: probes/agent-kill-inflight.sh
  accept: >
    the agent runs a live 1-call/sec loop (all 200); the revoke lands during the
    loop and it self-terminates on a real 401/revoked with no restart, no new
    handshake.
  adversarial: >
    a run that only refuses a FRESH handshake between tasks (never kills a live
    call) does not satisfy the claim.

- id: AGENT-KILL-5
  title: "Pre-revoke presentation replayed post-revoke is REJECTED (replay-resistant)"
  class: missing-surface
  status: open
  covers: ["OPS", "AGT"]
  probe: probes/agent-kill-replay.sh
  accept: >
    a presentation captured before the revoke, replayed after, is rejected for two
    reasons — single-use challenge consumed AND delegation/credential revoked.
  adversarial: >
    a replayed capture that verifies valid after revoke -> RED (the exact theft this
    demo defeats).

- id: AGENT-KILL-6
  title: "Fail-closed under transport failure / rollback"
  class: staging                 # guards the surface; uses auths-rp's shipped non-forced refspec
  status: open
  covers: ["OPS", "GOV"]
  probe: probes/agent-kill-failclosed.sh
  accept: >
    a wire-cut verifier rejects rather than serving stale-valid; a remote that
    rewinds history to resurrect a revoked credential is refused (non-forced fetch)
    and the replica keeps the newest tip seen.
  adversarial: >
    a verifier that fails open when it cannot confirm freshness, or accepts a
    rolled-back remote tip -> RED.
```

---

*Companion to `roadmap/aspirational_claims/gaps.yaml` (claim **OPS-1**) and the
`auths-demos/death-of-the-api-key` lineage. The demo body of the sharpest claim
auths makes vs Sigstore and OIDC: a fleet of agents that dies mid-flight, in under a
second, with no stolen proof surviving. Near-term: the kill switch + per-RP pull
cadence exist (`DOTAK-1`/`DOTAK-4` closed); this demo BUILDS the global
resolution/propagation surface OPS-1's baseline flagged as `RESOLVE_FAIL` and
**measures** it at fleet scale. Drafts, not gaps — no frozen probe, no pinned
file:line baseline yet. Generated 2026-06-14.*
