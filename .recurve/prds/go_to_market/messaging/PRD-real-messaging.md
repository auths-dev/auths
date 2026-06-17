# PRD — Real, Working Messaging (close every stub)

> **Durable plan.** Self-contained so it survives a fresh session / context loss.
> If you are picking this up cold: read §0 (Reality), §1 (Architecture), §2
> (Resume protocol), then the epic whose claim is RED. Every claim is gated by a
> recurve probe (`recurve --config .recurve/murmur.toml matrix --gate`) — ground
> truth is the gate, not prose.

- **Repo (engine):** `/Users/bordumb/workspace/repositories/auths-base/auths`
- **Repo (app):** `/Users/bordumb/workspace/repositories/auths-base/murmur`
- **Suite:** `.recurve/murmur.toml` (claims under `.recurve/claims/murmur/`)
- **Owner intent (verbatim):** *"close out all stubs for real, working application
  code … technically sound, simple, powerful … a durable plan that can survive
  different sessions and running out of context."*

---

## 0. Reality — what is and is NOT built (READ THIS FIRST)

An earlier status report called the engine "a skeleton, weeks of crypto." **That
was wrong** and this section corrects it. The cryptographic core is essentially
complete and tested; the gap is **integration** (FFI surface), **transport**
(a network server), and **app wiring** — not crypto.

### Built and tested (do NOT rebuild)
| Capability | Where | Evidence |
|---|---|---|
| Identity / AID (Ed25519, self-certifying) | `murmur-core/src/identity.rs`, `address.rs` | `Identity::from_seed/sign`, `verify_sender` |
| AEAD session (ChaCha20-Poly1305 + HKDF, per-msg nonce) | `session.rs` | `Session::seal/open`, zeroized, fresh-nonce test |
| Forward-secret ratchet | `ratchet.rs` | `Ratchet::seal/open`, in-order, zeroize-on-advance |
| X3DH prekey agreement | `prekey.rs` | `PrekeyBundle::publish/verify_rooted`, `x3dh_initiator/responder` |
| Audited Double Ratchet (vodozemac/Olm) | `olm_backend.rs` (feature `olm`) | `OlmChannel::encrypt/decrypt`, MAC-v2, pickle |
| **`Endpoint::seal_to` / `Endpoint::open`** | `lib.rs:248` / `lib.rs:288` | signs inner, AEAD-seals, AAD binds `sender‖recipient‖mailbox`; open authenticates or **rejects** |
| **Relay store-and-forward** | `relay.rs` `MailboxStore` | `deposit` (quota + bounded dedup, fail-closed) / `drain`, `RelayRequest::{Deposit,Drain}` |
| Directory trait + in-mem impl | `lib.rs:134` `Directory`, `lib.rs:143` `ContactDirectory` | `resolve(aid)->key`, `admit(aid,key)` |
| Device pairing (ECDH + SAS) | `murmur-ffi/src/pairing.rs` | FFI test `full_qr_handshake_derives_matching_sas` |
| Trust evaluation | `murmur-core/src/trust.rs` | `trust::evaluate` (FFI `evaluate_trust` wired) |
| Hermetic 13-leg proof | `murmur-relay` `serve`, `proofs.rs` (feature `proofs`) | drives every leg green |
| Device pairing UI, contact scan/paste/verify, QR scanner | `murmur/.../Pairing/*`, `Contacts/ContactCode.swift` | macOS build **SUCCEEDED** (this session) |

### NotBuilt — the actual gap (what this PRD closes)
| Stub | Where | Why it's a stub |
|---|---|---|
| FFI `seal()` / `open()` (stateless) | `murmur-core/src/lib.rs:317` / `:327` | carry only addresses+body; no session/identity — fail closed |
| FFI `seal_message` | `murmur-ffi/src/lib.rs:95` | returns `NotBuilt` — app's send seam |
| No network transport | relay has **no HTTP/WS server** (`murmur-relay` is an in-process self-test) | `MailboxStore` never reachable off-box |
| No prekey **directory service** | `ContactDirectory` is in-memory only | a sender can't fetch a never-met recipient's bundle |
| App has **zero networking** | `murmur/` (0 `URLSession`/`NWConnection`) | every "send" is mock |
| App `send()` is mock | `ThreadView.swift:225` → `appendMessage` + `advanceStatus` fakes sending→sent→delivered | no engine, no relay |
| Identity is hardcoded | `OnboardingView.swift` 1.4s fake pulse; `DemoData.me.identity` constant | never minted |
| Conversations/contacts are seed mock | `DemoData.swift` `DemoStore` | no persistence keyed to a real AID |
| Settings/recovery/call are decorative | see Epic G | toggles persist in-session only; call timer is fake |

**One-line summary:** the engine can already seal an authenticated, forward-secret
message and a relay can already store-and-forward it; nothing has ever connected
the two over a wire or called them from the app. Build the wire and the wiring.

---

## 1. Architecture — the real end-to-end path

```
 iPhone (Sam)                      Relay (HTTP, untrusted)                 Mac (Sam / Alice)
 ┌──────────────┐                  ┌───────────────────────┐              ┌──────────────┐
 │ Identity     │  PUT /prekey ───▶│ prekey directory       │◀── GET ─────│ resolve peer │
 │ (SE/keychain)│                  │  (aid → signed bundle) │              │ bundle       │
 │ X3DH+ratchet │                  │                        │              │ X3DH+ratchet │
 │ Endpoint     │  POST /deposit ─▶│ MailboxStore (opaque)  │── drain ────▶│ Endpoint     │
 │ seal_to ─────┼─ OuterEnvelope ─▶│  per-mailbox FIFO,     │  GET /drain  │ open → verify│
 │              │                  │  quota + dedup         │              │ or REJECT    │
 └──────────────┘                  └───────────────────────┘              └──────────────┘
   the relay sees only { to_mailbox, ciphertext } — never plaintext, sender, or keys
```

**Bootstrap a conversation (first contact):**
1. Each device **mints** an `Identity` (seed in Keychain/SE) → AID. *(Epic A)*
2. Each device **publishes** a signed prekey bundle to the relay directory. *(Epic B2, C2)*
3. Sender **scans/pastes** the recipient's contact code (already real) → AID. *(done)*
4. Sender **fetches** the recipient bundle, `verify_rooted` → `x3dh_initiator` →
   seed ratchet → `Session` → `Endpoint`. Persist the session. *(Epic B, D4)*
5. Sender `Endpoint::seal_to` → `POST /deposit`. *(Epic B, C, D2)*
6. Recipient `GET /drain` → `Endpoint::open` (authenticate-or-reject) → display. *(Epic D3)*
7. Both devices of one identity receive (mailbox fan-out across paired devices). *(Epic E)*

**Mailbox id:** pairwise/rotating handle, derived from the session — never the AID,
never a phone number (the whole point). `MailboxId` already exists (`relay.rs`).

---

## 2. Resume protocol (durable — for a cold session)

1. `cd auths && cargo build -p murmur-core -p murmur-relay -p murmur-ffi` — must be clean.
2. `recurve --config .recurve/murmur.toml matrix --gate` — note which MSG-* / NET-* claims are RED.
3. Pick the **lowest-numbered RED claim**; its epic below says exactly what to build.
4. Build → `cargo test` the new crate/leg → rebuild bindings if FFI changed →
   `xcodebuild ... -scheme Murmur-macOS` (see `xcode-build-path` memory) → re-gate.
5. Commit per piece, unsigned, no attribution, no push (AGENTS.md). One claim per cycle.
6. **Never** weaken a probe to make it pass. Park (don't fake) anything that won't green in ~3 attempts; record it in §6.
7. Honest-absent rule: any app action that isn't wired yet must surface the engine's
   `NotBuilt`/absent state — **never** a fake success. (This is already the shell's contract.)

---

## 3. Epics & subtasks (one epic ≈ one stub cluster)

Each epic: **Goal · Closes (stub file:line) · Subtasks (acceptance + verify) · Gate (claim)**.
Build order is the dependency order in §5.

### EPIC A — Real identity (mint + persist)
**Goal:** the app's identity is a real minted AID that survives relaunch, not a constant.
**Closes:** `OnboardingView.swift` fake 1.4s mint pulse; `DemoData.me.identity` constant; `MurmurEngine` has no mint.
**Subtasks:**
- **A1** FFI `mint_identity(seed?) -> { aid, public_key }` wrapping `Identity::from_seed`; generate a 32-byte seed from OS CSPRNG when none supplied. *Verify:* `cargo test` round-trips seed→aid; bindings regenerate.
- **A2** Swift `IdentityStore`: persist the seed in Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; SE-wrapped where available). Mint on first launch, reload after. *Verify:* relaunch macOS app → same AID (logged), not the DemoData constant.
- **A3** `OnboardingView.startMint` calls A2 (remove the `asyncAfter` pulse); identicon + `store.me.identity` derive from the real AID. *Verify:* xcodebuild; onboarding shows the minted AID.
**Gate:** `MSG-IDENTITY` — probe asserts a freshly minted AID is well-formed and stable across two mints from the same persisted seed.

### EPIC B — The session FFI (real seal/open over a stateful endpoint)
**Goal:** replace stateless `seal()`/`open()`/`seal_message` with an `Endpoint`-backed
UniFFI object the app drives.
**Closes:** `lib.rs:317/327` (`seal`/`open` NotBuilt), `murmur-ffi/src/lib.rs:95` (`seal_message` NotBuilt).
**Design:** a UniFFI `interface MurmurSession` (Rust `Arc<Mutex<…>>` object) holding
`Endpoint` (+ a `ContactDirectory` for the peer). Methods:
- **B1** `establish_initiator(my_seed, peer_aid, peer_bundle_bytes) -> MurmurSession` — `verify_rooted` → `x3dh_initiator` → seed `Session`/`Ratchet` → `Endpoint::new`; admit peer key into the directory. *Verify:* `cargo test` two FFI sessions (initiator+responder) seal/open a round-trip.
- **B2** `publish_prekey(my_seed) -> bundle_bytes` wrapping `PrekeyBundle::publish` (+ `PrekeySecrets` persisted alongside the identity). *Verify:* bundle `verify_rooted`s under the AID.
- **B3** `establish_responder(my_seed, peer_aid, first_envelope) -> MurmurSession` (X3DH responder side). *Verify:* responder opens initiator's first message.
- **B4** `seal(body) -> Vec<u8>` (CBOR `OuterEnvelope`) and `open(bytes) -> { from, body }` on the session, calling `Endpoint::seal_to`/`open`. Reject (not plaintext) on bad sig. *Verify:* tamper a byte → `open` errors; good path returns body.
- **B5** Session persistence: `to_pickle()/from_pickle(key)` (Olm pickle or serialize `Session`+ratchet counters) so a session survives relaunch; caller stores the pickle in Keychain with anti-rollback note. *Verify:* pickle→unpickle continues the ratchet in order.
- **B6** Decide backend: **use `olm` (vodozemac, audited) when the feature builds for the Apple slices; else in-tree `Ratchet`.** Record the choice in `murmur_vodozemac_integration.md`. *Verify:* `cargo test -p murmur-core --features olm` green.
**Gate:** `MSG-SEAL` — FFI initiator seals, FFI responder opens, body matches, tamper rejected. `MSG-1` (`aid-authenticated-number-free`) flips GREEN when the real seal/open path runs.

### EPIC C — The relay is a real server (network transport)
**Goal:** `MailboxStore` reachable over HTTP so two devices exchange envelopes off-box.
**Closes:** "no network transport" — `murmur-relay` is only an in-process self-test.
**Design:** add a `serve-http <addr>` mode to `murmur-relay` (deps already vendored:
`tokio`, `axum`, `ciborium`). Keep the legacy hermetic `serve` as the proof gate.
- **C1** `POST /deposit` (body = CBOR `OuterEnvelope`) → `MailboxStore::deposit` → returns `DepositOutcome` (`Queued`/`DedupedReplay`/`QuotaExceeded`). *Verify:* curl deposits, second identical deposit → `DedupedReplay`.
- **C2** `GET /drain/{mailbox}` → CBOR `[OuterEnvelope]` (FIFO, drains). *Verify:* curl drains what was deposited; second drain empty.
- **C3** Prekey directory: `PUT /prekey/{aid}` (store signed bundle bytes) + `GET /prekey/{aid}` (fetch). Store keeps bundles in memory (later: persistent). The relay does **not** verify the bundle (the *recipient* does, `verify_rooted`) but rejects an AID/bundle mismatch in size sanity. *Verify:* publish then fetch returns identical bytes.
- **C4** Bind the `MailboxStore` behind a `Mutex`/actor; quotas already enforced. Health `GET /` → version. *Verify:* `cargo test` integration: spawn server on `127.0.0.1:0`, full deposit→drain→open round-trip over real TCP.
- **C5** (later, NOT overnight) TLS + cert-pinning + persistent store. Note in §6.
**Gate:** `NET-RELAY` — integration test drives a real localhost relay end-to-end; `MSG-3` (`forward-secret`/`ciphertext-queued`) holds over the HTTP path; relay-visible bytes are mailbox-id + ciphertext only (reuse `prove_relay_queue` invariant).

### EPIC D — The app talks to the relay (networking + wiring)
**Goal:** replace mock `send()`/receive with real seal→deposit / drain→open.
**Closes:** `ThreadView.swift:225` mock send + `advanceStatus`; app has 0 networking; `DemoStore` mock seed.
- **D1** Swift `RelayClient` (URLSession): `deposit(env)`, `drain(mailbox)`, `publishPrekey`, `fetchPrekey(aid)`, base URL from the relay setting (Epic G). *Verify:* unit-point against the localhost relay.
- **D2** `ThreadView.send()` → `MurmurSession.seal` → `RelayClient.deposit`; status from the **real** `DepositOutcome` (`Queued`→sent; network fail→failed; remove the faked `.delivered/.read` timers). *Verify:* xcodebuild; message to a real peer deposits.
- **D3** Receive loop: a `MessagePump` (poll `drain` on a timer / on foreground; WebSocket later) → `MurmurSession.open` → `store.appendMessage` on the real conversation. Delivery receipt = a sealed control message back (optional, behind read-receipt setting). *Verify:* two app instances (macOS + iOS sim) exchange a real message.
- **D4** First-contact bootstrap: starting a conversation with a scanned/pasted AID → `RelayClient.fetchPrekey(aid)` → `MurmurSession.establish_initiator` → persist session; if no bundle yet, surface "waiting for {name} to come online" (honest-absent), not a fake send. *Verify:* fresh contact → real session established.
- **D5** Real persistence: a `ConversationStore` keyed to the local AID (SwiftData/SQLite/file) replacing the `DemoData` seed; keep the model types (`Conversation`/`Message`/`Contact`). Migration: seed empty, not demo people. *Verify:* relaunch → messages persist; no demo contacts unless explicitly added.
**Gate:** `MSG-APP` — a headless/integration check that the app's send path produces a real `OuterEnvelope` accepted by the relay (driver beacon, like the launch-smoke first-frame). Manual: iPhone→Mac real message (the owner's original failing flow).

### EPIC E — Paired-device fan-out
**Goal:** iPhone + Mac under one identity both send and receive.
**Closes:** pairing produces a device set but messages don't fan out.
- **E1** On send, deposit to **each** of the recipient identity's device mailboxes (and to the sender's other devices for self-sync). Device set comes from the pairing anchor (already built). *Verify:* a message to Alice reaches both her devices.
- **E2** Per-device session state (each device its own ratchet) or shared via the pairing channel; pick the simpler correct option and record it. *Verify:* revoking a device stops its delivery (reuse `prove_delegated_device`/revocation legs).
**Gate:** `MSG-MULTIDEVICE` — fan-out leg: one identity, two devices, both drain the same message; revoked device is clawed back.

### EPIC F — Trust is real (key-change warning from the engine)
**Goal:** trust badges + the key-change pause come from `evaluate_trust`, not hardcoded demo state.
**Closes:** `DemoData` hardcoded `trust`/`keyHistory`; Carol's `.nonContinuationWarning`; verify-in-person string-match.
- **F1** Confirm FFI `evaluate_trust` (`murmur-ffi/src/lib.rs:109`) is wired to `trust::evaluate` (it is) and the app calls it on each observed key event. *Verify:* garbage keystate → `Malformed`; real rotation → `verified-continuation`.
- **F2** Verify-in-person (the real QR scan I built) clears a warning **only** via the engine's trust state, bound to the scanned AID == contact AID. *Verify:* scanning a non-matching code does not clear the warning.
**Gate:** `MSG-2` (`verified-continuation`/`session-rekeyed`/`prekey-reverified`) — already a claim; ensure it stays green through the app wiring.

### EPIC G — Settings & actions do something (or honestly don't)
**Goal:** no decorative toggle; every control either takes effect or is honestly absent.
**Closes:** read-receipts/typing/presence/app-lock/disappearing toggles (in-session only); relay/witness pickers (no effect); fake call timer; group create (local only).
- **G1** Relay setting actually sets `RelayClient` base URL; "self-host" validates a reachable URL. *Verify:* changing relay routes traffic there.
- **G2** Read-receipts: when off, suppress the sealed read-receipt control message (D3). Disappearing: a real local expiry timer that purges on both sides. *Verify:* off → no receipt sent; timer purges.
- **G3** Honest-absent for not-yet-built: the **call** screen (no media stack) shows "Calls aren't built yet," not a fake elapsed timer; group creation either mints a real group AID (if time) or is gated behind honest-absent. *Verify:* no fake success states remain (grep for `asyncAfter` fakes).
- **G4** App-lock = real biometric gate; screenshot-block where the OS allows; else honest-absent. *Verify:* toggling app-lock requires Face/Touch ID on next foreground.
**Gate:** `MSG-HONEST` — a probe/grep asserting no `advanceStatus`-style fake progression remains for unbuilt features (the shell's honest-absent contract).

### EPIC H — The gate (durable verification)
**Goal:** the new work is claim-gated so a future session knows what's real.
- **H1** Add claims + probes under `.recurve/claims/murmur/`: `MSG-IDENTITY`, `MSG-SEAL`, `NET-RELAY`, `MSG-APP`, `MSG-MULTIDEVICE`, `MSG-HONEST` (MSG-1/2/3 exist). Each probe drives the real path and has a trap (negative) variant. *Verify:* `recurve --config .recurve/murmur.toml matrix --gate` lists them.
- **H2** Wire `murmur.toml` `[target]` to rebuild `murmur-relay` with the HTTP server and run the integration legs. *Verify:* gate rebuilds + runs them.
- **H3** Keep leakcheck green (no loop-vocab in `crates/`). *Verify:* leakcheck passes.

---

## 4. Functional requirements (numbered, unambiguous)
- **FR-1** A device mints exactly one identity; the AID is stable across relaunch.
- **FR-2** A sender can establish a session with a recipient it has only a contact code for, by fetching the recipient's published prekey bundle.
- **FR-3** Every message leaving a device is `Endpoint::seal_to`-sealed; the relay never receives plaintext, sender AID, or keys.
- **FR-4** A received envelope is `Endpoint::open`-authenticated; a bad signature or unresolved sender is **rejected**, never shown as plaintext.
- **FR-5** The relay stores-and-forwards over HTTP with quota + bounded dedup (fail-closed); a byte-identical replay is dropped.
- **FR-6** Message status reflects real outcomes (`Queued`/network-fail), never a timed animation.
- **FR-7** Both devices of one identity receive every message addressed to that identity.
- **FR-8** No control in the app reports success for an action it did not perform.
- **FR-9** Conversations/contacts/messages persist locally keyed to the real AID; first launch has no demo people.
- **FR-10** Every epic's claim is green under `recurve … matrix --gate`, with traps RED.

## 5. Sequencing (dependency order)
```
A (identity) ─▶ B (session FFI) ─▶ C (relay HTTP) ─▶ D (app wiring) ─▶ E (fan-out)
                         └─────────────────────────────▶ F (trust, parallel to D)
D ─▶ G (settings real) ;  every epic ─▶ H (gate)
```
**Overnight priority (highest value, most verifiable first):** C (relay HTTP, pure
Rust + integration test) → B (session FFI, cargo-testable) → A (mint) → D (app
wiring, xcodebuild + manual round-trip). E/F/G/H as time allows. Rationale: a
verified Rust round-trip over a real relay proves the whole spine before the
app — and is provable here without a device.

## 6. Non-goals (this PRD) & parked
- **Non-goals:** voice/video calls (media stack); push notifications (APNs); group
  messaging beyond a real group AID stub; federation/multi-relay routing; the
  libsignal migration (separate doc); production TLS/persistent relay at scale.
- **Parked (record reason + attempt count here as you go):**
  - C5 relay TLS/cert-pinning/persistence — overnight target is localhost/LAN plaintext-HTTP for the verified round-trip; production hardening is follow-up.
  - vodozemac M5–M7 (parity gate, cutover, external audit) — held per existing tasks; B6 picks the backend that builds without blocking on the audit.

## 7. Success metrics
- A real ChaCha20-Poly1305-sealed message travels iPhone→relay→Mac and decrypts,
  with the relay log showing only `{mailbox, ciphertext}`.
- `recurve … matrix --gate` shows MSG-IDENTITY/MSG-SEAL/NET-RELAY/MSG-APP green, traps RED.
- The owner's original failing flow (send from iPhone, receive on Mac) works.
- Zero fake-success code paths remain for unbuilt features (honest-absent only).

---

## 8. Adversarial review — UX (adopted into the plan)

A skeptical messenger-shipping designer reviewed this plan. Verdict: *"the PRD proves
the spine (seal → relay → open) and mistakes that for the product. It has no model for
**asynchronous rendezvous between two strangers who are never online at the same time** —
that single omission produces the dead empty state, the lost first message, the
never-delivered status, the silent identity loss, and constant key-change scares."*
The findings below are **adopted** and have added Epics **D6, I, J** and amended D/F/G.

**P0 — blockers (fixed in-plan):**
- **P0-1 No inbound first-contact path.** Deleting the demo seed leaves the Requests
  shelf (the opt-in firewall) never populated; a drained envelope from an unknown AID
  has no conversation to land in → dropped/crash. **→ New Epic D6:** unknown-sender
  envelope → `establish_responder` → a `ContactRequest` (not a conversation), accept
  promotes it. Gated `MSG-INBOUND`.
- **P0-2 Contact code carries no home relay.** With no federation (non-goal), a sender
  fetches the recipient's bundle from the *sender's* relay → 404 for anyone who swapped
  relays. **→ Amend D1/D4 + Epic J:** `ContactCode` carries the recipient's **home-relay
  URL**; `RelayClient` targets *the recipient's* relay for `fetchPrekey`/`deposit`. If
  cross-relay isn't done for v1, **lock the relay picker** (see G1) — never ship a picker
  that silently breaks first contact.
- **P0-3 No outbox → typed-before-session messages are lost.** "waiting for {name}"
  describes the UI but not the message. **→ Amend D2/D4 (Epic I, outbox):** pre-session
  messages persist `.pending`, `MessagePump` retries `fetchPrekey` on backoff, flushes
  in order when the bundle resolves. The bubble (not the thread) shows "Will send when
  {name} joins."
- **P0-4 Status model now dishonest the other way.** Mapping only `Queued→sent` leaves
  `.delivered`/`.read` never firing, so a permanent single-check reads as *broken*.
  **→ Epic I status model:** `.pending → .sent (relay Queued) → .delivered (sealed
  delivery-ack auto-sent by recipient's pump on drain — NOT behind read-receipt setting)
  → .read (behind setting) / .failed`. **Build the delivery-ack** — it's the difference
  between "feels broken" and "feels real." Don't render 5 glyphs where 2 fire.
- **P0-5 Identity loss is total, silent, and onboarding lies about it.** Seed is
  `...ThisDeviceOnly` with no backup, behind a guardian UI that does nothing →
  reinstall mints a *new* AID, every contact lost, and every friend sees a scary
  key-change. **→ Epic A amended + Epic G3:** either build real seed backup (encrypted
  iCloud-Keychain item or a written recovery phrase, explicit onboarding step) **or**
  honest-absent the entire `RecoveryView`/guardian flow and the "friends help you back
  in" copy. No fake guardians. (Also fixes P1-1 at the root.)

**P1 — severe (amended in-plan):**
- **P1-1 Reinstall → scary red wall for all your contacts.** Root cause is P0-5 (fresh
  AID). **→ Epic F amended:** a key change is an **inline dismissible advisory** by
  default; only escalate to the thread-pause wall for an engine-named anomaly. "Accept &
  continue" is the friendly primary action; in-person verify is secondary.
- **P1-2 Real relay-swap & disappearing become footguns.** Relay swap silently breaks
  first contact (P0-2) and can lose queued messages; disappearing "both sides" can't be
  guaranteed over a lossy poll relay. **→ G1/G2 amended:** lock/advanced-gate the relay
  picker until federation; reframe disappearing as **"disappears from this device after
  {time}"** with an explicit best-effort caveat — never imply guaranteed remote deletion.
- **P1-3 Multi-device sync gaps.** E2's "per-device or shared session" coin-flip has huge
  UX stakes (history gaps, unread/delete divergence, no backfill on new device). **→ Epic
  E amended:** separate per-device mailboxes; sender self-deposits to its own other
  devices; read/delete/unread are **sealed control messages** that fan out the same way;
  **state plainly: no history backfill on new-device pairing in v1** (honest-absent line).
- **P1-4 No notifications = "only works while you stare at it."** Push is a non-goal but
  the consequence was buried. **→ Epic I:** add `BGAppRefreshTask` background poll, an
  honest onboarding/settings line ("Murmur checks for messages when you open it"),
  and a defined poll cadence (foreground immediate + every N s).
- **P1-5 Ordering/dedup on a FIFO poll relay.** Retries (different nonce → different
  bytes) defeat byte-dedup; sender clock skew scrambles order. **→ Epic B4 amended:**
  sealed inner header carries a **per-session monotonic sequence** (expose the ratchet
  counter) and a stable **message-id**; thread orders by `(sender-seq, receive-time)`;
  dedup on message-id, not ciphertext bytes.

**P2 — polish (tracked in Epic G3 decorative-control audit):** remove vs. honest-absent
the dead call button + voice mic, the attachment `+` (v1 is text-only — a faked photo
"send" violates FR-8), typing/presence toggles, "claim a handle," and **delete-for-everyone**
(today it only deletes locally — a privacy lie over a real relay; build a tombstone
control message or relabel "Delete for me"). The `MSG-HONEST` grep only catches
`asyncAfter` fakes — **add a decorative-control audit table**, not just a grep. Also: keep a
deliberate min-duration on the now-instant mint animation; specify blocked-AID drop in the
receive loop (block is best-effort client-side — the relay can't enforce it without learning
the sender).

**Top 3 plan changes adopted:** (1) inbound first-contact path + outbox (Epics D6, I);
(2) identity persistence + recovery honesty (Epic A + G3); (3) honest status model +
notifications reality written into UX, not footnotes (Epic I).

## 9. Adversarial review — Security (non-negotiables adopted)

A protocol auditor reviewed the plan against the built engine. Verdict: *"The engine is
sound and even ships the exact mechanisms that close the worst holes. The PRD's failure is
that it describes the integration in prose an implementer can satisfy while **bypassing**
those mechanisms — most dangerously by letting the untrusted relay supply the key that
`verify_rooted` checks against."* The **key fact the plan must state:** `Aid::from_public_key`
(address.rs:40) = `SHA256(pubkey)` rendered `did:keri:<hex>`, and `verify_sender`
(identity.rs:83) **re-derives the AID from the resolved key and rejects on mismatch** — so
**the scanned AID IS a cryptographic commitment to the signing key.** Whether first contact
is safe depends entirely on the app deriving the verifying key *from the AID*, never from the
relay. The 9 non-negotiables below are **adopted as build requirements** (a probe enforces each).

1. **[P0 MITM] Directory/root-key provenance.** `establish_initiator` MUST check
   `Aid::from_public_key(bundle.signing_key) == scanned_aid` **before** X3DH, and
   `verify_rooted` MUST run against that AID-derived key. A relay-served `(aid, key)` binding
   is **forbidden** as an authentication source. *(Engine already supports this — `prekey.rs:168`,
   `identity.rs:83`, `address.rs:40`. Build: B1 takes the scanned AID and rejects any bundle
   whose signing key doesn't hash to it.)* This is THE hole — without it the relay MITMs first
   contact. → amends **B1**.
2. **[P0 TOFU] First contact is trust-on-first-use; in-person SAS is the only strong defense.**
   No "Verified" badge for a pasted/linked AID until in-person SAS (`pairing.rs:15-17`, already
   built). The AID↔human binding rests entirely on the out-of-band channel that delivered the
   code. → amends **F2**, **D4** (unverified-until-SAS rendering).
3. **[P0 rollback] Versioned, generation-bound, per-session pickle keys.** B5 MUST use
   `to_versioned_pickle`/`from_versioned_pickle` with a monotonic `min_generation` in
   rollback-protected storage and a **distinct pickle key per session** (`olm_backend.rs:429-469,
   400-401`). A restored old pickle = nonce/counter reuse = catastrophic. No bare
   `to_encrypted_pickle`; no flat serialize of the in-tree `Session`. → amends **B5**.
4. **[P1 key-exfil] No raw seed across the FFI on the shipping path.** `MurmurSession` takes an
   SE/keychain **signing handle** (callback), matching the FFI's stated invariant
   (`murmur-ffi/src/lib.rs:4-8`: "every private-key op lives off-Rust"). Seed-in-FFI is confined
   to an explicitly-labeled **non-SE demo build** and the identity-protection claim is downgraded
   there. → amends **A1, B1, B2**.
5. **[P1 oracle] Uniform open-failure + authenticated `from`.** B4 calls the **full**
   `Endpoint::open` (never a partial AEAD-open that returns body pre-`verify_sender`); all open
   failures (tamper / wrong key / unresolved sender / bad sig / malformed) collapse to **one**
   rejection across the FFI (no decryption oracle, `olm_backend.rs:483-488`). `from` is the
   authenticated sender. → amends **B4**.
6. **[P1 downgrade] Fixed backend, MAC-v2 pinned, no negotiation.** Olm v2 full-MAC is the
   shipping wire; the in-tree `Ratchet` is dev/test-only and **non-interoperable** (a peer
   expecting Olm cannot be downgraded to it). End-to-end probe: a v1 first message is rejected
   (`olm_backend.rs:312-351`). → amends **B6**.
7. **[P1 metadata] Metadata-leak section + specified `MailboxId` derivation.** The claim "the
   relay sees only {mailbox, ciphertext}" is **incomplete** — the relay also learns deposit/drain
   **timing**, **source IP**, drain cadence (a presence beacon), and **`GET /prekey/{aid}` =
   the social graph** in cleartext AID, plus quota/dedup **oracles**. `MailboxId` MUST be a **PRF
   of the pairwise session, AID-unlinkable and rotating** — today `MailboxId::new` takes an
   arbitrary string (`relay.rs:29`); nothing stops an implementer setting it to the AID and
   destroying unlinkability. → new **Epic K** (metadata) + amends **C3** (blinded prekey fetch),
   **B**/§1 (define `MailboxId` derivation).
8. **[P1 replay] Idempotent deposit + open-layer dedup.** `POST /deposit` carries an
   idempotency/message-id; `DedupedReplay` is a **success** to the client; the app dedups
   received messages by stable message-id rather than trusting the relay's bounded fingerprint
   window (`relay.rs:86`). (Dovetails with I3.) → amends **C1**, **I3**.
9. **[P1 transport] Plaintext-HTTP is demo/localhost-only, never claimed secure.** With C5
   parked, the §7 success metric must NOT assert "secure" over plaintext; the digest-binding (#1)
   is what stops content-MITM even on a hostile transport, but metadata leaks and a LAN/Internet
   listener needs a **pinned relay key** minimum. → amends **C5, §7**.

**Bottom line adopted:** fix the provenance of the verifying key (#1) and the persistence
anti-rollback (#3), keep the seed out of the FFI (#4), uniform-error open (#5) — then the rest
is hardening. The build sequence below bakes #1, #5, and the `MailboxId` derivation (#7) into
the spine from the first commit (they are correctness, not polish).

### EPIC K — Metadata minimization (relay learns as little as possible)
**Goal:** make true the "the relay can't build the social graph" promise.
- **K1** Define + implement `MailboxId = PRF(pairwise-session-secret, counter)` — AID-unlinkable,
  rotating. *Verify:* a probe asserts the mailbox id is not derivable from / equal to either AID.
- **K2** Prekey fetch not keyed on requester identity (blinded handle or fetch-by-mailbox).
  *Verify:* relay log of a prekey GET does not reveal the requester AID.
- **K3** Document the residual leaks (timing, IP) and the accepted v1 boundary. *Verify:* §1/§7
  no longer overclaim.
**Gate:** `MSG-METADATA` — mailbox-id unlinkability + the corrected relay-visibility invariant.

## 10. New/amended epics from the reviews

### EPIC I — Asynchronous rendezvous (outbox, status, notifications)
**Goal:** the app behaves like a messenger when the two parties are never online together.
- **I1 Outbox:** pre-session / offline messages persist `.pending`; a backoff retry
  resolves the session and flushes in compose order. *Verify:* compose before peer has a
  bundle → message auto-sends when the bundle appears.
- **I2 Honest status model:** `.pending→.sent→.delivered→.read/.failed` as in §8 P0-4;
  delivery-ack is a sealed control message auto-sent on drain. *Verify:* recipient drains
  → sender shows `.delivered` without a read-receipt setting; glyphs only fire when real.
- **I3 Sequence + message-id** in the sealed inner header (§8 P1-5). *Verify:* retried
  message appears once; out-of-order drains render in compose order.
- **I4 Background poll:** `BGAppRefreshTask` + defined foreground cadence + honest "checks
  when you open it" disclosure. *Verify:* backgrounded app surfaces a message on next
  refresh; copy present.
**Gate:** `MSG-ASYNC` — outbox flush + delivery-ack + single-delivery under retry.

### EPIC J — Relay addressing (home-relay in the contact code)
**Goal:** first contact works without federation by routing to the recipient's relay.
- **J1** `ContactCode` payload carries `{ did, name?, relay_url }`. *Verify:* parse/round-trip.
- **J2** `RelayClient.fetchPrekey/deposit` target the AID's home relay (from the code / a
  per-contact field), not the local setting. *Verify:* two relays, cross-relay first
  contact succeeds; same-relay still works.
**Gate:** folded into `MSG-INBOUND`/`MSG-APP`.

### EPIC D6 — Inbound first-contact → Request (the opt-in firewall, made real)
**Goal:** receiving a stranger's first message creates a reviewable Request, not a silent
conversation. **Closes:** Requests shelf seeded only from `DemoData`; no real inbound path.
- **D6.1** `MessagePump` drains an envelope whose sender AID has no conversation →
  `establish_responder` → create `ContactRequest{ aid, name(from sealed header), note(first
  body) }` in `store.requests`. *Verify:* stranger's first message appears as a Request.
- **D6.2** Accept promotes Request→conversation (existing `accept()`); decline/block drops
  and the receive loop **drops** future envelopes from a blocked AID before surfacing.
  *Verify:* blocked AID's later messages never re-create a request.
**Gate:** `MSG-INBOUND` — unknown sender → Request; accept → conversation; blocked → dropped.
