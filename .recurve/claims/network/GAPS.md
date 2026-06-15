# network — claims decomposed from PRD.md

> **Reader:** the human who owns this spec. Skim every section (the
> quotes are evidence, never instructions), answer ADJUDICATE.md with
> one sentence per fork, then `recurve baseline network`. With no code
> yet, every baseline will be RED or BROKEN — that is correct: the
> burndown is the build, and the BOOT-* gaps order the bootstrap.

## Conventions

- Severity maps from the spec's own modality: must/shall → feature
  (headline if marked critical), should → friction, could/may → cosmetic.
- Anything security-relevant starts review-gated (`security-tradeoff`)
  until a human downgrades it. Default-closed is the safe direction.
  The WIT-T block sits there pending ADJUDICATE-3.
- WIT-B (repo boundary) claims are source-structure guards — `reads:
  none` greps are legitimate there because the claims are about source
  (the same license WIT-N5's leak-gate uses).
- Cross-ledger rule: prerequisites owned elsewhere are referenced, never
  duplicated. This suite depends on interop IOP-L3b (non-transferable
  witness verkeys) and IOP-L3c (key-state wire shape), and provides the
  *mechanism* for lost-the-laptop LTL-1/LTL-2 and verify-the-world V1 —
  whose promotions remain with their own review protocols.

## BOOT-1 — the harness exists  *(closed · probe GREEN 2026-06-13)*

The scaffolding every later probe stands on is built, wired, and proven by a
live fixture: `harness/up.sh` boots three real witness nodes with three distinct
identities, the kill-node lever injects a recoverable failure, and the oracle is
pinned and installed.

- `harness/env.sh` — paths + the fixed-seed 3-node roster (distinct
  `AUTHS_WITNESS_SEED` ⇒ distinct advertised AID) + health helpers.
- `harness/compose/docker-compose.yml` — three witness services (`wit1/2/3`),
  one shared image, distinct seeds + host ports. The node image is the
  platform's hardened `auths-witness` binary built from its canonical
  deployment Dockerfile — the fixture boots what the platform ships, not a fork.
- `harness/up.sh` / `down.sh` — idempotent bring-up (one image build, shared
  by all three nodes) and teardown.
- `harness/kill-node.sh` — failure injection: stop node N, peers survive,
  restart recovers (the FR-13 lever).
- `harness/versions.lock` — the keripy oracle pinned at **1.3.4**, identical to
  `interop/peers/versions.lock` (one oracle, one version, no cross-suite skew).
- `probes/boot-1.sh` + `probes/boot-1.trap/cloned-identity/` — the behavioral
  probe (three healthy nodes, three DISTINCT identities, kill-node proven,
  oracle pinned AND installed) plus its permanent counterexample (three clones
  of one operator are not a network).

**Closed (GREEN, 2026-06-13):** `bash probes/boot-1.sh` →
`harness GREEN: 3 distinct witness nodes healthy (did:key:z6MktUL… z6MkqGC…
z6Mkg49…), kill-node lever proven, oracle keripy=1.3.4 pinned and installed`
(exit 0); the cloned-identity trap stays RED (`ours=1-distinct oracle=3-distinct
— roster is not 3 independent identities …`, exit 1). The shared witness image
is cached, so bring-up just starts three nodes on ports 3331/3332/3333, each
advertising a distinct seed-derived AID, and a 2-of-3 set survives killing one.

**The fix was real, not cosmetic.** The bare `tmpfs: - /data` receipts mount was
root-owned, but the runtime image is distroless `nonroot` (uid 65532). That uid
could write `/data/receipts.db` on the FIRST `up` (Docker seeds the declared
`VOLUME`'s perms onto the tmpfs at create) but NOT after a `docker compose
stop`/`start`, where the tmpfs re-mounts fresh as root — the node then died with
`SQLITE_CANTOPEN` (code 14). So the standup was healthy but the kill-node lever's
"restart recovers" half was silently broken — exactly the FR-13 behavior under
test. Pinning the tmpfs to `uid=65532,gid=65532,mode=0700` makes `/data` writable
on every (re)start, so a stopped node truly recovers. The earlier same-day RED
(`no 3-witness fixture standing on ports 3331 3332 3333 …`) was the standup's
absence before bring-up; it was RED not BROKEN because the keripy oracle was
already present. (The historical Docker-engine corruption that stalled the first
cycle — VM disk overrun on a build before `auths/.dockerignore` landed — was an
environment fault, since recovered; `auths/.dockerignore` keeps the build context
source-only.)

## BOOT-2 — the skeleton builds  *(closed · probe GREEN 2026-06-13)*

The rebuild produces every artifact the probes read, and that artifact is the
FEATURE-ENABLED `auths` build:

- **`auths/crates/auths-witness-node`** — a new crate behind the additive
  `witness-node` workspace feature. It COMPOSES the platform's public crate APIs
  (`auths-witness`, `auths-keri`, `auths-verifier`) — it reimplements no
  protocol (WIT-B1). It owns the *operation*: the parsed standup intent
  (`StandupRequest`), the embedded node+monitor Compose manifest (released image
  only, never a source build), the key-custody policy (`KeyCustody` —
  managed-by-default, file is an acknowledged downgrade), and the operator-facing
  health URL. The protocol types it renders (`KeyStateNotice`, `WitnessQuorum`,
  the KSN wire version, the server's body-size cap) are re-exported from the
  platform, never redeclared.
- **`auths witness up|down|status|register|logs`** — the operator verb set, added
  to `auths-cli`. The clap *surface* always compiles in (thin defs, no heavy
  deps), so `auths witness --help` is identical in every build. The *handler* is
  feature-split: a `--features witness-node` build runs the node via
  `auths-witness-node`; a lean default build returns one actionable line
  (`… needs the witness build; install it with cargo install auths --features
  witness-node`) and pulls none of the node's dependencies.
- **Additive feature (WIT-B2)** — `cargo tree -p auths-cli` on the default build
  shows NO `auths-witness-node`; `--features witness-node` shows it. The
  dependency arrow is one-way (node → core, never core → node); the lean install
  stays lean.
- **recurve wiring** — `[suites.network] rebuild` runs `harness/rebuild.sh`,
  which builds the feature-enabled `auths` into its OWN target dir
  (`target/witness-node`, so the lean `target/release/auths` the demos read is
  never clobbered) and copies it to `bin/auths`. `[reads.cli]` content-hashes
  `bin/auths` against that build output, so a `reads: cli` probe refuses to run
  stale. (Dashboard lives in the web tier, not here.)

**Baseline (RED, 2026-06-13):** `bash probes/boot-2.sh` →
`no bin/auths — the suite rebuild has not run (recurve rebuild network →
harness/rebuild.sh)` (exit 1), before the crate/feature/CLI/rebuild existed.
The `node-in-default-tree` trap (a default `cargo tree` that pulls
`auths-witness-node`) is RED — the additivity guard rejects its own
counterexample. Now GREEN: `bin/auths` is the feature-enabled build with all
operator verbs; the node crate composes the platform crates and is additive.

## BOOT-3 — every authored probe can run  *(closed · probe GREEN 2026-06-13)*

The full authored probe set runs on the built tree and every verdict is a
DECISION — RED or GREEN — never BROKEN. A baseline with a BROKEN in it is not a
baseline: "is this behavior present?" has no answer there, so the burndown
cannot start.

- `probes/boot-3.sh` — the meta-probe: it runs every sibling probe
  (`probes/*.sh`, minus itself and the sourced `_contract.sh`) on the built
  tree and is RED if any exits ≠ 0,1 (BROKEN / timeout / crash). GREEN means the
  whole set decided.
- `probes/boot-3.trap/broken-sibling/` — the permanent counterexample: a sibling
  that exits 2 (BROKEN). The meta-probe MUST turn RED on it; a baseline that
  swallowed a could-not-measure sibling would be clean-on-a-lie.

**Baseline (RED, 2026-06-13):** `bash probes/boot-3.sh` →
`ours=BROKEN baseline expected=all-decide — 1 authored probe(s) could not
measure on the built tree (exit≠0,1): wit-n1.sh:exit=2 …` (exit 1). The BROKEN
sibling was WIT-N1: against the **skeleton** `auths witness up` — which exited 0
and printed a health URL while standing nothing up — the WIT-N1 probe could not
decide whether the standup capability was real or faked (`up` claimed a success
reality contradicted), so it returned BROKEN.

**The fix was real, not cosmetic.** `auths witness up` now performs a genuine
embedded-Compose standup: it brings the node + monitor sidecar up, waits until
the node answers its health endpoint, prints that URL, and exits 0 — and,
crucially, **fails honestly** (non-zero exit, one actionable line, nothing left
half-standing) when it cannot stand a node up, instead of claiming success. With
`up` no longer lying, WIT-N1 *decides* (RED on this box, where no node image is
obtainable; GREEN where one is), so the meta-probe sees zero BROKEN and goes
GREEN. The clean baseline is earned by removing the lie, not by lowering the
bar.

## WIT-N1 — one command, one witness  *(closed · probe GREEN 2026-06-13)*

`auths witness up` takes a box to a HEALTHY witness node in one command, zero
protocol vocabulary — and tells the truth about the result. The load-bearing
rule, now enforced behaviorally: `up` exiting 0 is not success; a node answering
its health URL is.

- **Standup runtime (`auths-witness-node`):** `up` renders the embedded Compose
  manifest (the *released* witness node — `image:`, never `build:`), mints the
  node's stable signing identity at first boot (an OS-CSPRNG 32-byte seed pinned
  in a `.env` beside the manifest and injected into the node, never a key file
  baked into the image), brings the project up via a `ContainerEngine` port (the
  shipped `DockerEngine` adapter), then polls the health endpoint through a
  `HealthCheck` port until the node answers. Success returns the proven-live URL;
  any failure tears down what started and surfaces one actionable line.
  Ports/adapters: the orchestration never shells out directly.
- **The image is obtained, not built by `up`.** Standup runs a released image;
  on a clean VPS the operator pulls the published image, and on a dev/CI box the
  harness builds it ONCE from the platform's canonical deployment Dockerfile
  (`harness/ensure-image.sh` → `auths-witness:net-fixture`) and `up --image`
  runs that. The source build stays out of the standup path (WIT-B4).
- **Two real platform fixes unblocked the GREEN.** (1) The canonical witness
  deployment Dockerfile was genuinely broken — it added the musl target to a
  different toolchain than `rust-toolchain.toml` selects and hardcoded x86_64 on
  an arm64 host (E0463 "can't find crate for `core`"); it now resolves the static
  target from `TARGETARCH` after the source copy, so the released image builds
  natively on both arches. (2) The embedded manifest carried a transparency-log
  `monitor` sidecar pinned to an unshippable image that blocked the whole
  `compose up`; that mis-scoped daemon was removed (the node-health collector the
  standup *should* run is WIT-O2's `auths-monitor`, filed as the integration
  point), leaving a manifest that actually comes up healthy.
- **Adversarial twin:** no container engine → a single actionable refusal,
  non-zero exit, nothing stood up. Occupied port → the engine's failure is
  surfaced as one line and the partial bring-up is torn down. File-key custody is
  a deliberate downgrade gated behind `--accept-file-key` (managed is the
  default).
- `probes/wit-n1.sh` ensures the released image is present (via the harness),
  drives `up --image` against a throwaway port + data dir, and asserts a real
  node answers the printed URL with zero protocol vocabulary; with no engine it
  asserts the clean refusal instead. `probes/wit-n1.trap/occupied-port/` — an
  `up` that exited 0 on an occupied port (partial-state lie) — stays RED.

**Closed (GREEN, 2026-06-13):** `bash probes/wit-n1.sh` →
`one command stood up a healthy witness: \`witness up\` exited 0, printed
http://127.0.0.1:3340/health, the node answers there, and the happy path carries
zero protocol vocabulary` (exit 0); the occupied-port trap is RED. The earlier
same-day RED (`ours=exit1 expected=exit0 — \`witness up\` did not complete a
standup …`) was the honest-failure half of the same claim, observed before an
obtainable node image existed — exactly the prerequisite BOOT-1's 3-node fixture
also waits on, now satisfied by `harness/ensure-image.sh`.

## WIT-N2 — receipts verify offline on a stranger's machine  *(closed · probe GREEN 2026-06-13)*

A witness receipt plus the witness's published identity verifies on a clean
machine with no network and no registry — and a tampered receipt fails closed
with a distinct reason. A receipt is only corroboration if a third party who
does not trust the node can check it alone; now they can.

- **Why it verifies alone.** A witness's published identity is a `did:key` that
  *embeds* its verification key. So `{receipt, signature, identity}` is
  self-contained: a holder recovers the key straight from the identity and checks
  the signature over the canonical receipt bytes — no directory lookup, no
  second party. The receipt body names only the *controller* it attests
  (`receipt.i`), never the witness, so the bundle cannot self-attest; the
  published identity is the single trust input.
- **The offline verify is platform (protocol), composed by the node (operation).**
  Per the repo boundary, "must be correct for strangers" is `../auths`: the
  self-contained check now lives in the PUBLIC verifier,
  `auths_verifier::verify_receipt_offline`, returning a parsed
  `Verified` / `SignatureFailed` / `UnreadableIdentity` verdict (the only success
  arm is `Verified`, so a receipt that did not check can never be mistaken for
  one that did). The witness-node crate composes it as a `ReceiptBundle` (signed
  receipt + published identity); the operator/stranger surface is
  `auths witness verify-receipt --receipt <file>` (`-` reads stdin). The decision
  was not re-implemented in the node crate — it is one verifier, shared with WASM
  and FFI (WIT-B1/WIT-B3).
- **Distinct rejection.** A bit-flipped signature, a tampered receipt body, or a
  foreign identity all land on `SignatureFailed` and exit non-zero with a
  reason a verifier can act on ("rejected: this receipt does not verify against
  <identity> — it was altered or was not issued by that node"); an unreadable
  identity string is a distinct `UnreadableIdentity` so "the wrong string was
  carried" is never confused with "the signature failed".
- `probes/wit-n2.sh` stands up the 3-witness fixture, has a node receipt a valid
  inception event (a real `SignedReceipt` comes back), reads the node's published
  `did:key` from `/health`, assembles the bundle, and runs the offline verify in
  an isolated empty-home context (`HOME`+`AUTHS_HOME` → an empty dir: no registry,
  no pinned witnesses; the command is handed only a file and reaches no network).
  It leaves the shared fixture standing — the harness owns up/down, the probe
  only READS. It asserts the genuine bundle verifies, then flips one signature
  byte and asserts a distinct rejection. `probes/wit-n2.trap/forged-signature/` —
  a genuine receipt with one signature byte flipped — stays RED.

**Closed (GREEN, 2026-06-13):** `bash probes/wit-n2.sh` → `receipts verify
offline on a stranger's machine: a real witness receipt + the node's published
identity verified with no network and no registry … and a bit-flipped receipt
was rejected with a distinct reason — the corroboration claim holds end to end`
(exit 0); the forged-signature trap is RED. The earlier same-day RED
(`ours=exit2 … error: unrecognized subcommand 'verify-receipt'`) was the
missing-surface baseline: the platform shipped the self-contained verify only
deep in `auths-core` (not the public `auths-verifier`), and no `auths witness`
verb exposed it — the receipt half existed, the third-party-checks-it-alone half
did not.

## WIT-N3 — the node serves conformant key-state notices  *(closed · probe GREEN 2026-06-13)*

A running witness, having corroborated an identity's events, serves that
identity's current key-state at a stable endpoint as a **KERI-conformant
key-state notice** — the wire record a keripy/keriox peer reads. The notice
reconstructs byte-for-byte inside the pinned reference implementation
(node → oracle), a record the oracle publishes ingests on the node
(oracle → node), and a stale notice is detected as stale, never silently
accepted. This carries interop's IOP-L3c (the KSN *wire shape*, owned and
cross-verified there) to the **running node**: a thin client can trust an
identity's current keys from one notice instead of replaying its whole log.

- **The witness retains what it witnessed.** A witness server stored receipts and
  first-seen SAIDs but discarded the event bodies — so it could not speak to a
  key-state (keys, thresholds, next-commitment). It now retains each verified
  event body (`auths-core` witness storage `events` table, first-seen-wins) so it
  can replay an identity's KEL into the current key-state it serves. The notice
  describes exactly the history *this* witness saw — built from
  signature-verified events, never asserted.
- **The wire shape and replay are platform (protocol), the endpoint is operation.**
  Per the repo boundary, the byte a stranger verifies is `../auths`: the served
  record is `auths_keri::KeyStateRecord`, built only via its own
  `from_kel` after a `TrustedKel::replay` — the witness reaches for the trust
  kernel's emitter, never a hand-rolled serializer. The node merely serves it at
  `GET /witness/{prefix}/key-state` (404 when it has corroborated no events for the
  prefix — it cannot notice a key-state it never saw). The fields and order are the
  canonical KERI ksn record `{vn,i,s,p,d,f,dt,et,kt,k,nt,n,bt,b,c,ee,di}` (WIT-B1).
- **Cross-verified both directions against the same oracle interop pins.**
  `harness/ksn_oracle.py` reconstructs the node's served record inside keripy
  1.3.4 (`eventing.state(...)`) and asserts field-for-field equality (ignoring
  `dt`, the controller's own clock) → `ORACLE-OK`. The reverse direction,
  `harness/ksn_emit.py` emits a notice the way keripy publishes one and
  `auths key-state --ingest` consumes it — the wire shape is bidirectionally
  interoperable, not just emittable. One oracle, one `versions.lock` pin, shared
  with interop (no skew between the suites).
- **Stale is detected, not trusted.** A key-state notice is a snapshot; a verifier
  already holding a newer state must refuse to rewind to an older one.
  `auths_keri::KeyStateRecord` gained `sequence()` / `check_not_stale(last_seen)`
  (returning the existing `KsnError::Stale`), exposed as
  `auths key-state --ingest --reject-stale-below <hex>`, which fails closed with a
  distinct reason ("rejected: stale key-state notice — KSN is stale: seq 0 <
  last-seen 1; a verifier holding a newer state refuses to rewind").
- `probes/wit-n3.sh` stands up the 3-witness fixture, has wit1 witness a full
  conformant inception (`probes/fixtures/keri-icp.json` — a real auths-signed
  `icp`), then `GET …/key-state`, runs the served record through the oracle
  (node → oracle), ingests an oracle-published notice (oracle → node), and detects
  a stale (lower-seq) notice. It leaves the shared fixture standing — the harness
  owns up/down, the probe only READS. `probes/wit-n3.trap/stale-ksn/` — a genuine
  seq-0 oracle notice presented to a verifier that already trusts seq 1 — stays
  RED.

**Closed (GREEN, 2026-06-13):** `bash probes/wit-n3.sh` → `the node serves a
conformant key-state notice: a live node witnessed a real inception and served a
KERI ksn wire record that the keripy oracle (1.3.4) reconstructs byte-for-byte
(node→oracle), the node ingests a notice the oracle publishes (oracle→node), and a
stale notice is detected as stale — IOP-L3c's wire conformance now holds against
the running node` (exit 0); the stale-ksn trap is RED. The earlier same-day RED
(`ours=no-ksn-endpoint … the node did not serve a key-state notice at
/witness/<prefix>/key-state`) was the missing-endpoint baseline: the running node
had no key-state surface at all before this cycle.

## WIT-N4 — the node proves what binary it runs  *(closed · probe GREEN 2026-06-14)*

An operator vouches for the network; the operator must in turn be **vouchable** —
a relying party has to confirm the node runs the binary the platform shipped, not
a silently-swapped one. A running node exposes a **signed version+digest build
attestation** that pairs the binary's own self-measurement with the operator's
`auths artifact sign --ci` document, and `auths witness status` verifies it. A
forged attestation — perfectly signed, but over a **different** binary — is
rejected. The node dogfoods the platform's own CI artifact signer to prove
itself.

- **The node measures its own binary.** At startup the witness binary computes the
  SHA-256 of the executable it is running (`/proc/self/exe`) — its self-measurement
  is a number it derives, not one it is handed. It pairs that with the signed build
  attestation (read from `AUTHS_WITNESS_BUILD_ATTESTATION`) and serves both as a
  `BuildProof` at `GET /build` (`auths-core` witness server). The server interprets
  none of it; a node started without an attestation serves **404** there — a node
  that cannot prove its binary says so plainly, never an unprovable green.
- **The signature check is platform (protocol); the self-measurement + serving is
  operation.** Per the repo boundary, the byte a stranger verifies is `../auths`:
  the offline check is `auths_verifier::verify_build_attestation_offline`, a
  **two-leg, fail-closed** verdict — the attestation's signature verifies against
  the key its self-describing `did:key` issuer embeds (composing the existing
  attestation verifier, the same path as `artifact verify --signature-only`), AND
  the attested digest equals the node's self-measured running digest. A valid
  signature over the WRONG binary lands on `DigestMismatch`, never `Verified`
  (WIT-B1 — no protocol re-implemented in the node crate). The node crate composes
  it as `BuildAttestation::verify → NodeBuildVerdict`; `auths witness status`
  fetches `/build`, renders the verdict, and fails closed on a forged or absent
  build.
- **Standup deploys the attested released binary (WIT-B4).** `auths witness up
  --build-attestation <path>` mounts the operator's attestation read-only into the
  node and points the binary at it (the standup compose), so a stood-up node serves
  its build proof from first boot. The attestation is produced over the **released
  image's** binary, not a source build — the harness extracts
  `/usr/local/bin/auths-witness` from the image and dogfoods `auths artifact sign
  --ci` over it (`harness/ensure-build-attestation.sh`), exactly as it owns image
  acquisition for WIT-N1.
- **The forgery the claim exists to catch.** A relying party cannot be fooled by a
  correctly-signed attestation for a different binary: the digest leg fails because
  the node measured what it actually runs. This is what converts "the operator
  signed *something*" into "the node provably runs *this*".
- `probes/wit-n4.sh` stands up its OWN throwaway node with the genuine attestation
  injected, GETs `/build`, asserts `auths witness status` verifies it, then stands a
  SECOND node up with an attestation signed over a DIFFERENT artifact and asserts
  `status` refuses with a distinct reason. It tears its own nodes down on exit
  (hermetic — the shared fixture is untouched). `probes/wit-n4.trap/wrong-digest/` —
  a genuinely-signed attestation whose attested digest is not the node's running
  binary — stays RED.

**Closed (GREEN, 2026-06-14):** `bash probes/wit-n4.sh` → `the node proves which
binary it runs: a live node served a signed version+digest build attestation,
`witness status` verified it against the node's own self-measurement of the running
binary, and a forged attestation (valid signature over a different binary) was
rejected with a distinct reason — an operator vouching for the network is itself
vouchable` (exit 0); the wrong-digest forged-attestation trap is RED (`rejected:
the attestation is for a different binary (attested 296078e6…, running 7ce84d53…) —
this node is not running what it attests`). The earlier same-day RED
(`ours=no-build-endpoint … the node did not serve a build attestation at /build`)
was the missing-surface baseline: the running node had no build-proof surface and
`status` had no build leg before this cycle.

## WIT-N5 — zero protocol vocabulary in the operator happy path  *(closed · probe GREEN 2026-06-14)*

An operator stands a witness up, checks on it, registers it, reads its logs, and
tears it down — and never needs the trust kernel's **vocabulary** to do any of
it. The words a relying party's *verifier* speaks (key event logs, key-state
notices, self-addressing identifiers, the CESR wire, signing thresholds, and the
rest) are correct and load-bearing *inside* the kernel; in an operator's face they
are pure friction. This claim makes the vocabulary-invisible rule a **guarantee
with one owner**, not a hope spread across ad-hoc test lists.

- **One source of truth (quality §3/§4).** Before this cycle the rule was three
  divergent, hand-maintained jargon lists — one in `lib.rs`'s health-URL test, one
  in `build.rs`'s verdict-summary test, one in the WIT-N1 probe — each a partial
  (6-term) copy that could drift from the surface it guarded. The rule now lives in
  exactly one place: `auths-witness-node/src/vocabulary.rs` owns the canonical
  `PROTOCOL_VOCABULARY` denylist (the kernel's wire/ceremony vocabulary an operator
  must never see) and `scan_for_protocol_vocabulary`. The crate's own happy-path
  tests consume it; their divergent inline copies were **deleted**.
- **Whole-word, case-insensitive matching.** The scanner flags a denylisted term
  only when it stands as its own word, so benign operator strings that merely
  *contain* the letters — `prefixed`, `did:key:…`, `received`, `unsaid` — are not
  false positives. A leak is a bare jargon word, cased however it likes.
- **Full coverage, not a subset.** The canonical list covers the load-bearing
  vocabulary the spec names — `keri kel ksn said cesr oobi acdc tel verkey prefix
  threshold` (and more: `kerl icp rot ixn drt saider cigar tholder diger`) — where
  the earlier ad-hoc checks covered only six. `threshold` matters specifically: an
  operator *runs a node*; M-of-N is the **verifier's** language, never standup's.
- **The probe scans the LIVE happy path against the PRODUCT's own list.** A green is
  only real if the words it forbids are the words the product forbids — a probe with
  a private copy could bless a leak it never thought to name. So `probes/wit-n5.sh`
  stands up its OWN throwaway attested node, captures every line `witness
  up|status|register|logs|down` prints (attested standup included, since `status`
  renders the build verdict — the surface most likely to reach for protocol words),
  and scans it against the denylist **extracted from `vocabulary.rs`**. It also
  asserts the rule has a single owner (the canonical file exists, the list is
  non-empty and covers the kernel vocabulary) and that no divergent jargon copy
  survives in the node crate. Hermetic — it tears its own node down on exit.
- `probes/wit-n5.trap/jargon-leak/` — a captured happy-path transcript where one
  line leaked `KEL`, `threshold`, `verkey`, `prefix` among otherwise-clean lines —
  stays RED. The trap is scanned against the same product-owned denylist, so it
  forbids precisely the words the surface forbids.

**Closed (GREEN, 2026-06-14):** `bash probes/wit-n5.sh` → `the operator happy path
carries zero protocol vocabulary: every line `witness up|status|register|logs|down`
printed (attested standup included) passed a whole-word, case-insensitive scan
against the product's own canonical denylist (covering
keri/kel/ksn/said/cesr/oobi/acdc/tel/verkey/prefix/threshold and more), and that
denylist lives in exactly one place — the vocabulary-invisible rule is a guarantee
with one owner, not a hope spread across ad-hoc lists` (exit 0); the jargon-leak
trap is RED (`ours=trap:kel expected=RED`). The earlier baseline RED
(`ours=no-canonical-denylist expected=one-owner — the product exposes no single
source of truth for the operator-vocabulary rule … a rule with no owner is a hope,
not a guarantee`) was the real state before this cycle: the happy-path output
itself was already clean, but the rule it was held to had no owner the probe could
anchor to — three partial, drifting copies. The cycle converted that into one
enforced guarantee.

## WIT-I1 — cloud standup is one idempotent command

`up --cloud <provider>` via embedded OpenTofu: plan→apply→boot→health,
re-run is a no-op. **Adversarial:** invalid credentials abort before any
resource is created (provider inventory diff in the harness). First
provider only; the rest are follow-on gaps.

## WIT-I2 — teardown leaves nothing billable behind

`down --cloud` destroys everything (inventory-diff verified); `up` after
`down` is clean. **Adversarial:** an orphaned resource is reported, never
silently ignored.

## WIT-D1 — the directory is a signed artifact, verified client-side

The public directory is a git repo of org-signed entries; the dashboard
verifies in-browser and renders only what verifies. **Adversarial:** a
tampered entry renders as a visible verification failure, never as data.
The network's front door is proof, not assertion.

## WIT-D2 — registration is a signed admission, not a form

`register` emits a signed candidate entry; admission follows the
adjudicated policy (ADJUDICATE-2) and is itself signed. **Adversarial:**
an entry whose operator identity fails verification cannot be admitted.

## WIT-D3 — stats are reproducible by an outside observer

Uptime/receipt numbers come from an open prober whose signed results
anyone can re-run. **Adversarial:** a node lying about uptime disagrees
with the prober — and the directory shows the prober's number.

## WIT-T1 — witness sets are designated in the org's own log

`org witness set <ids> --threshold M` anchors the designation as a signed
event; set rotation is provable at a log position. **Adversarial:**
receipts from outside the designated set never count toward M.

## WIT-T2 — M-of-N enforced; M−1 is insufficient

Ordering-sensitive verdicts require M valid receipts from the designated
set. **Adversarial:** M−1 receipts fail closed. This is G3: forged
ordering requires collusion, not theft.

## WIT-T3 — diversity is the default

Receipts counting toward M must come from distinct operators (by
directory identity); jurisdiction-strict optional. **Adversarial:** a
threshold met by one operator's three nodes fails. The anti-oligopoly
guard, default-closed (PRD FR-9).

## WIT-T4 — unreceipted is not invalid

Distinct verdicts: `InsufficientReceipts` (operational) vs invalid
(attack). Below threshold, ordering-sensitive verdicts fail closed;
non-ordering verdicts proceed and say so (PRD FR-10). **Adversarial:**
a silent downgrade is the RED line.

## WIT-T5 — the forged-ordering fixture dies under threshold

The flagship trap: the signer-stamped low anchor-seq forgery (the LTL-2
fixture) must FAIL under active threshold policy. Kept forever; this
going green-on-forgery is a gate failure of the highest order. Provides
the mechanism LTL-1/LTL-2/V1 require — their promotion still goes
through their own adversarial review.

## WIT-T6 — threshold checking costs ≤50ms p99

Perf probe, pinned rig, warmup, N≥1000, p99 with hysteresis.
Verify-on-every-request must survive the corroboration upgrade.

## WIT-O1 — the console is never stale-green

A dead node shows DOWN within 60 seconds. **Adversarial:** cached green
against a dead node is the RED line. Operators must be able to trust
their own dashboard before anyone else trusts the network.

## WIT-O2 — node metrics are complete

The monitor daemon (currently a framework with incomplete handlers)
becomes the collector: health, receipts/day, identities served,
key-state request rate, last-seen-by-peers — Prometheus-compatible.
**Adversarial:** a console-rendered metric absent from the endpoint is RED.

## WIT-O3 — unhealthy fires a webhook, without flap-spam

Webhook on unhealthy > N minutes, signed payload, probed debounce window.

## WIT-B1 — the witness-node crate reimplements zero protocol logic

The boundary, enforced in-workspace: `auths-witness-node` composes the
platform crates' **public** APIs (`auths-witness`, `auths-keri`,
`auths-verifier`) — depending on them is the integration, and correct. What's
forbidden is re-implementing protocol: needing a message the platform doesn't
expose means a platform API is missing — add the public surface, never inline
the bytes in the node crate.
**Adversarial:** any hand-rolled receipt / key-state / CESR / SAID parsing
inside `auths-witness-node` is RED.

## WIT-B2 — the witness-node feature is purely additive

The dependency arrow is one-way: `auths-witness-node` → core, never core →
node. The `witness-node` cargo feature is additive only, so a default `auths`
build stays lean (none of the node's heavy deps); the `auths witness`
subcommand surface compiles in always (thin), but its handler and the crate
are feature-gated. The trust kernel stays witness-network-agnostic.
**Adversarial:** a core crate with a non-optional dep on `auths-witness-node`,
or a default-feature `cargo tree` pulling the node's heavy deps, is RED.

## WIT-B3 — the dashboard verifies only through the published verifier

One verdict source of truth: browser, FFI, and CLI verification are one
implementation, reached here via the published WASM package. The dashboard
renders verdicts; it never computes them.
**Adversarial:** verification or threshold logic in dashboard code outside
the published verifier package is RED — a forked verdict path is the one in
the screenshot.

## WIT-B4 — standup deploys released, attested binaries

Operators run what the platform shipped, provably: standup manifests pin
released artifact versions and verify the signed build attestation before
boot. Never a source build in the deploy path.
**Adversarial:** an IaC/compose path that builds from source, or boots a
binary whose attestation fails to verify, is RED.
