# Murmur — Wiring the App to the Audited Engine (vodozemac/Olm + KERI)

> Companion to `messaging/vodozemac_migration.md` (the **engine** — done, red-teamed) and
> `messaging/murmur.md` (the product). **This plan turns the SwiftUI shell into a fully working app:**
> every surface backed by the real `murmur-core` engine (the Olm backend) through the FFI, the FFI
> built with `--features olm`, a real relay transport, and keys held in the Secure Enclave / Keychain.
> **Definition of done:** no `DemoStore` stub data on any identity / message / key / trust path; a
> message composed on one device is sealed, store-and-forwarded through an untrusted relay, and opened
> — authenticated as an AID — on another; trust badges and key-change warnings come from real KEL
> replay; onboarding mints a real Secure-Enclave identity. (Groups and calls are explicitly v2 — honest
> placeholders, §11.)

---

## 1. Where we are (the gap to close)

| Layer | State today | Evidence |
| --- | --- | --- |
| **App (SwiftUI)** | Fully built — ~25 screens — but **every surface is backed by `DemoStore`** (in-memory stub data). Only FFI used: `coreVersion()` / `addressCanonical()` (real) and `sealMessage()` / `evaluateTrust()` (both return `NotBuilt`). | `murmur/Murmur/Sources/Shared/**`; `ContentView.swift:38` |
| **Engine (`murmur-core`)** | **Real** identity / prekey / session / `Endpoint` seal-open / relay `MailboxStore` / rotation / trust / KEL / delegation, **plus** the audited **Olm backend** behind `--features olm` (`OlmIdentity`/`OlmChannel`/`verify_rooted`). 123 tests green. | `crates/murmur-core/src/**`; `olm_backend.rs` |
| **FFI (`murmur-ffi`)** | Exposes **4 functions** only; the entire stateful engine surface (identity mint, prekey lifecycle, session establish, seal/open, relay, trust, KEL, delegation, the Olm backend) is **unexposed**. | `crates/murmur-ffi/src/lib.rs` |
| **Build** | `murmur/scripts/build-ffi.sh` builds `murmur-ffi` **without** `--features olm`; produces `Vendor/MurmurFFI.xcframework` (ios-arm64, ios-arm64-sim, macos-arm64). | `scripts/build-ffi.sh` |
| **Transport** | **None.** `murmur-relay` is a self-test binary; the app has no network layer to reach a relay. | `crates/murmur-relay/src/main.rs` |

So three things must be built: **(A) a real FFI surface**, **(B) a relay network transport**, and **(C)
an engine-backed data/store layer** that the views bind to instead of `DemoStore` — plus the build flag
and Secure-Enclave key storage.

---

## 2. Target architecture

```
SwiftUI views ─▶ @Observable MessageStore (Swift actor, replaces DemoStore)
                     │  owns engine handles, local DB, sync
                     ├─▶ MurmurEngine (Swift wrapper over UniFFI)
                     │       └─▶ murmur-ffi (Rust, handle-based)  ─▶ murmur-core (--features olm)
                     ├─▶ KeyStore (Secure Enclave P-256 AID root + Keychain pickle keys)
                     └─▶ RelayTransport (Swift, HTTPS/WebSocket) ◀──▶ murmur-relay (server)
```

**Trust boundary recap:** the SE holds the **P-256 AID root** (signs bundles + the inner per-message
signature); **Olm Curve25519 keys are software**, pickled (generation-bound, anti-rollback) under a
Keychain key; the **relay is untrusted** (sees only a pairwise mailbox id + opaque ciphertext). Olm
authenticates the *channel*; the **inner signature** authenticates the message *as an AID* (this is the
JN-5 binding from the red-team — it MUST be wired and mandatory in this layer).

---

## 3. The identity-curve bridge (do this first — it gates everything)

**The one real reconciliation.** `murmur-core::Identity` signs **Ed25519** (from a 32-byte seed);
the app's AID root must be **P-256 in the Secure Enclave** (auths' platform default, and the only curve
the SE supports). These cannot both be true unspecified. Resolution, in priority order:

1. **Make the engine's signer curve-agnostic over `auths-crypto`.** `auths-crypto` already provides
   P-256 (the rest of auths signs P-256). Route `Identity::sign` / `verify_sender` /
   `bundle_signing_bytes` verification through `auths-crypto`'s algorithm-tagged keys so a P-256 AID key
   signs and verifies bundles. The Olm join is unaffected (it signs *bytes*; the curve of the signer is
   independent).
2. **The FFI never holds the private AID key.** `LocalIdentity` in the FFI takes a **sign callback**
   (or the raw public key + a detached signature produced by the app), so the actual signing happens in
   the Secure Enclave (`SecKeyCreateSignature`) and the private key never crosses the FFI. The engine
   gets `(public_key, signature)` and verifies.

**Spike P0a:** confirm `auths-crypto` P-256 sign/verify is usable from `murmur-core`, and prototype the
SE-sign-callback shape. This is the highest-risk unknown; everything downstream assumes it. (Risk RI-1.)

---

## 4. The FFI surface to build (`murmur-ffi`, UniFFI, handle-based)

The engine is **stateful**, so the FFI is **handle-based objects** (UniFFI `interface`/`Arc`), not free
functions. Sensitive bytes (seeds, private keys) **never cross** the boundary. Build with `--features
olm`. Proposed surface (each maps 1:1 to a tested `murmur-core` item):

| FFI object / method | Wraps | Purpose |
| --- | --- | --- |
| `Engine.version() -> String` | `VERSION` | already real |
| `Engine.newIdentity(sign_cb) / loadIdentity(pickle, key) -> LocalIdentity` | `OlmIdentity::new(Identity)` | mint/restore; signing via SE callback (§3) |
| `LocalIdentity.aid() / publicKey()` | `Identity::aid/public_key` | the address |
| `LocalIdentity.publishPrekeyBundle() -> bytes` | `OlmIdentity::publish_bundle` | OTK + fallback, AID-signed |
| `PrekeyBundle.verifyRooted(aidKey) -> RootedBundle` | `OlmPrekeyBundle::verify_rooted` | the join (verify-then-use) |
| `LocalIdentity.establishOutbound(rooted) / onFallback(rooted) -> Channel` | `establish_outbound[_on_fallback]` | initiator session |
| `LocalIdentity.establishInbound(senderKey, firstWire) -> (Channel, bytes)` | `establish_inbound` | responder session (+ first plaintext) |
| `Channel.encrypt(pt) -> wire / decrypt(wire) -> pt` | `SecureChannel` on `OlmChannel` | per-message seal/open |
| `Channel.sessionId()` | `session_id` | pair binding (relocation defense) |
| `Channel.toVersionedPickle(key, gen) / fromVersionedPickle(rec, key, min) -> (Channel, gen)` | the R10 API | anti-rollback persistence |
| `InnerSignature.sign(senderAid, recipientAid, body, sign_cb) -> sig` / `verify(...)` | `InnerEnvelope::signing_bytes` + `verify_sender` | **the AID authentication (JN-5)** — bind sender's Olm key into the signed bytes |
| `TrustEvaluator.evaluate(prior, current) -> TrustBadge` | `trust::evaluate` | trust state (already half-wired) |
| `KeyState.resolve(kelJson) -> KeyState` | `Kel::replay` | current key from witnessed KEL |

**What stays Swift-side, not FFI:** the **relay transport** (network), the **local DB**, the **mailbox
id derivation** for routing, and the **SE signing** (the FFI calls *out* to it). The FFI deals only in
identities, channels, bundles, ciphertext bytes, and verdicts.

**Acceptance for the FFI layer:** a Rust integration test (in `murmur-ffi`) that does the whole loop —
two identities, publish→verify→establish, seal an inner-signed message through a `Channel`, open it,
verify the AID — with **no stub**, plus a Swift `MurmurEngineTests` that drives the generated bindings
for the same loop on the macOS host (no simulator).

---

## 5. Persistence & key storage (Swift `KeyStore` + local DB)

- **AID root:** P-256 keypair in the **Secure Enclave** (`kSecAttrTokenIDSecureEnclave`,
  `kSecAttrAccessControlUserPresence` optional). Signs via `SecKeyCreateSignature`; never exported.
- **Olm pickle key:** 32 bytes in the **Keychain** (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  SE-wrapped). One **distinct key per stored session** (CR-2). Sessions persisted via
  `Channel.toVersionedPickle` with a **monotonic generation** kept in the Keychain (R10 anti-rollback).
- **Account + contacts + messages + KELs:** a local store (SQLite via GRDB, or SwiftData). Session
  pickles and the account pickle are the only secret-bearing rows; everything else is metadata. Message
  bodies are stored decrypted locally (like every messenger) but the DB file is OS-encrypted at rest.
- **Multi-device:** each device has its **own** Olm account + a **delegated sub-identity** anchored by
  the root AID (`DelegatedDevice`/`DelegationAnchor`), so a device speaks *as* the root but holds its
  own keys; revocation (`DeviceRevocation`) cuts it off (the lost-laptop story).

---

## 6. Transport — the relay network layer

The relay is **store-and-forward, untrusted**. Two pieces:

**6.1 `murmur-relay` server front-end.** Today `murmur-relay` is a self-test binary wrapping
`MailboxStore`. Add a network front-end: `POST /deposit {mailbox, ciphertext}` →
`MailboxStore::deposit` (returns `Queued`/`DedupedReplay`/`QuotaExceeded`); `GET /drain?mailbox` or a
**WebSocket subscription** → `MailboxStore::handle(Drain)`. The relay authenticates **nothing about the
sender** (that's the point) — it rate-limits per mailbox/IP and enforces the existing quotas. TLS +
SPKI pinning on the client. (Self-host first; the protocol is the contract.)

**6.2 Swift `RelayTransport`.** Derives the **pairwise mailbox id** (from the session — never the AID),
deposits outgoing `OuterEnvelope.ciphertext`, and subscribes for incoming. Offline → outbox queue +
retry; the `OfflineBanner` reflects real connectivity. The mailbox id must be **unlinkable** to the AID
(a per-pair handle); document the derivation and that the relay can only correlate per-mailbox traffic.

**6.3 The envelope split.** Send path: app builds the `InnerEnvelope` (sender‖recipient‖body, **inner
signature via SE**), `Channel.encrypt`s it → ciphertext, wraps as `{mailbox, ciphertext}`, deposits.
Receive path: drain → `Channel.decrypt` → parse inner → **verify the inner signature against the
sender's resolved AID key** (KEL/Directory) before surfacing. This is where JN-5 is enforced.

---

## 7. Surface-by-surface integration (the 100% inventory)

Every app surface, its stub today, and the engine wiring that makes it real. (Screens per the app map.)

| Surface | Stub today | Engine wiring |
| --- | --- | --- |
| **Onboarding ▸ Mint** (`OnboardingView` step 1) | 1.4s timer, `DemoData.me.identity` | `KeyStore` mints SE P-256 → `Engine.newIdentity` → AID; persist |
| **Onboarding ▸ You're You** (step 2) | local identicon + name | identicon from real AID; name stored locally (not on the relay) |
| **Onboarding ▸ Connect / Scanner** (step 3) | "Simulate a scan" → fake Jamie | real QR decode → parse AID + bundle → `verifyRooted` → `establishOutbound` |
| **Share my code** (`ShareCodeSheet`) | invite link from id suffix | QR encodes AID + signed prekey bundle; deep link `murmur.im/i/<bundle>` |
| **ChatsList** | `store.conversations` demo data | `MessageStore` conversations from local DB + relay sync; trust per contact from KEL |
| **Requests (opt-in firewall)** | `store.requests` demo | inbound first-contact prekey messages held as requests until accepted |
| **NewMessage ▸ Pick / Paste / Scan** | 3 hardcoded contacts | real contact list (from DB); paste invite → verify bundle; scan → §3 |
| **Thread ▸ send** | `Message(status:.sending)`, `advanceStatus()` timer | build inner envelope → SE-sign → `Channel.encrypt` → `RelayTransport.deposit`; status from relay `DepositOutcome` + receipts |
| **Thread ▸ receive** | none (demo messages exist) | `RelayTransport` drain → `Channel.decrypt` → verify inner sig → insert message |
| **Thread ▸ edit / delete-for-everyone** | local-only mutation | tombstone/edit control messages sealed through the channel to all recipients |
| **Thread ▸ reactions / read receipts / typing** | local/mocked | small sealed control messages (or deferred to v2 — mark honestly) |
| **Thread ▸ attachments / voice** | demo `Attachment` | sealed blob upload to relay/blob store + a sealed pointer message (P4) |
| **Thread ▸ disappearing timer** | label only | a sealed timer policy + local expiry job |
| **Thread ▸ trust pause** (`TrustPausePrompt`) | toggles `contact.trust` | driven by `TrustEvaluator` on a detected key change; "Accept" records a continuation, "Verify" → SAS |
| **TrustIndicator** (silent/loud) | `contact.trust` enum | `TrustBadge` from `evaluate(prior, current)` over witnessed KELs |
| **PartnerProfile ▸ AID / KeyHistory** | demo `keyEvents` | `AIDView` from real AID; `KeyHistoryView` from `Kel::replay` event timeline |
| **VerifyInPerson** | "Simulate scan" → `verified=true` | real QR scan + **SAS / safety-number** compare; record a signed in-person attestation |
| **PersonalProfile** | local `me` | real AID, engine version, device list (delegated devices), export/backup |
| **Settings** (privacy/notifications/etc.) | `@AppStorage` | wired to real policies where they affect the engine (e.g. read-receipts on/off = send receipts or not) |
| **NewGroup / GroupInfo** | demo `GroupMember`s | **v2 (Megolm)** — honest "groups coming" placeholder; do not fake E2E group crypto |
| **CallView** | timer + toggles | **v2** — placeholder; no fake "encrypted call" |
| **Multi-device / pairing** | none | `DelegatedDevice` + pairing flow (QR/relay) → admit device; revoke from PersonalProfile (P4) |

**Rule:** any surface that cannot be made real in its milestone ships a **labelled placeholder** ("coming
in v2"), never simulated crypto. Faking an "encrypted call" or a green trust badge is the exact
green-while-false trap the engine work exists to avoid.

---

## 8. The data layer — replacing `DemoStore`

`DemoStore` becomes `MessageStore`: a Swift actor that **owns the engine handles + the local DB +
the relay subscription**, and publishes `@Observable` state the views already bind to. Keep the view
models (`Conversation`, `Contact`, `Message`, `TrustLevel`, `KeyEvent`) — they're good — but populate
them from the engine + DB, not literals. Migration is mechanical per view: swap the `DemoData.*` source
for a `MessageStore` query; the binding surface barely changes (the app was built model-first, which
pays off here).

---

## 9. Milestones (phased; each ships something demoable + recurve claims)

- **P0 — FFI foundation + curve bridge.** §3 spike; expose identity / channel / bundle / inner-sig /
  trust through `murmur-ffi`; build `--features olm`; regen xcframework; Swift `MurmurEngine` wrapper.
  *Done when:* a host test mints two identities and seals→opens an AID-authenticated message with no
  stub. **Claims:** `APP-FFI-1` (loop green), `APP-FFI-2` (olm feature in the shipped slice).
- **P1 — Onboarding + identity.** SE P-256 mint, publish bundle, persist; onboarding wired. **Claim:**
  `APP-ONBOARD-1` (a real AID is minted in the SE and survives relaunch).
- **P2 — 1:1 messaging end to end.** Establish session (verify→channel), seal/open, `RelayTransport`
  deposit/drain, Thread + ChatsList live. **Claims:** `APP-MSG-1` (Mac→iPhone real delivery, the DEV-1
  analog over the real engine), `APP-RELAY-1` (relay sees only mailbox+ciphertext — a leakcheck on the
  wire), `APP-SESSION-1` (anti-rollback persistence across relaunch).
- **P3 — Trust & keys.** KEL replay, trust evaluation, key-change pause, `KeyHistoryView`, verify-in-
  person SAS. **Claims:** `APP-TRUST-1` (a non-pre-committed key change loudens the badge + pauses),
  `APP-TRUST-2` (a pre-committed rotation stays silent/continuation).
- **P4 — Multi-device, requests, profile, attachments.** Delegated devices + revocation; opt-in request
  firewall; sealed attachments. **Claims:** `APP-DEV-1` (revoked device's next message rejected).
- **P5 — Groups (Megolm) + calls.** v2; placeholders until built. **Claims:** `GRP-1` (later).

**Each milestone gates on `recurve --config .recurve/murmur.toml matrix --gate` staying green**, with new
`APP-*` probes added per the project's probe contract (driving the built app/engine, with traps).

---

## 10. Build & CI changes

- `scripts/build-ffi.sh`: add `--features olm` to each `cargo build --target …`; regen UniFFI bindings;
  rebuild the xcframework. (The slices already match what M1 proved cross-compiles.)
- `project.yml`: no target change; the xcframework just gets the new (larger) binding surface.
- The federated gate's `[target] rebuild` may need `--features olm` once P0 lands so the gate exercises
  the real backend (this is also the engine-side **M5 gate-level parity** — the two converge here).
- CI: build all three slices + run `MurmurEngineTests` (host) + the FFI Rust integration test.

---

## 11. Explicitly deferred (honest placeholders, not fakes)

- **Groups** — Megolm exists in vodozemac; the group *join* + member management is real design work.
  Until then, the group UI is a labelled "coming soon," not simulated E2E.
- **Calls** — needs media (SRTP/ICE) + a signaling path; v2. No fake "encrypted call" screen.
- **Reactions / typing / read-receipts** — ship as sealed control messages where cheap; otherwise mark
  as cosmetic-only until the control-message channel exists.

---

## 12. Risks

| # | Risk | Sev | Mitigation |
| --- | --- | --- | --- |
| RI-1 | **Identity-curve bridge** (engine Ed25519 vs SE P-256) — the gating unknown | high | P0a spike (§3); route signing through `auths-crypto` P-256 + an SE sign-callback; the private key never crosses the FFI |
| RI-2 | Relay transport is new attack surface (DoS, linkability) | high | keep the relay untrusted + quota'd (existing `MailboxStore` limits); unlinkable pairwise mailbox ids; TLS+SPKI pinning; the §6 protocol is itself an ENC-7-class review item |
| RI-3 | **Inner-signature binding (JN-5)** must be mandatory or the channel is unauthenticated-as-AID | high | enforce inner-sig verify on every receive (§6.3); bind the sender's Olm key into the signed bytes; no surface path that skips it |
| RI-4 | Olm keys at rest / rollback (R10/R11) | med | versioned (anti-rollback) pickle + per-session Keychain key; OS at-rest encryption; FS/PCS bound the value |
| RI-5 | vodozemac `experimental-session-config` (v2 MAC) pin | med | `=0.10.0` pinned + `session_config_is_v2_full_mac`; track upstream stabilization |
| RI-6 | Out-of-order > 40 (R12) over an adversarial relay | med | best-effort relay ordering + client gap detection; documented bound |
| RI-7 | Scope: "100% of surfaces" is large; risk of faking to look done | med | the §7 rule — labelled placeholders, never simulated crypto; milestone gates on the real gate |
| RI-8 | Multi-device session/state sync | med | per-device accounts + delegated identities; sync is metadata + sealed control messages, not key sharing |

---

## 13. Success criteria (definition of "fully working app")

1. Onboarding mints a **real Secure-Enclave AID** that survives relaunch (`APP-ONBOARD-1`).
2. A message composed on one device is **sealed, relayed, and opened — authenticated as an AID — on
   another** (`APP-MSG-1`), with the relay provably seeing only mailbox + ciphertext (`APP-RELAY-1`).
3. **No `DemoStore` stub data** on any identity / message / key / trust path (grep the app — `DemoData.*`
   gone from those flows).
4. **Trust is real**: a non-pre-committed key change loudens the badge and pauses the thread; a
   pre-committed rotation stays a silent continuation (`APP-TRUST-1/2`), from witnessed KEL replay.
5. The FFI ships **`--features olm`**; the federated gate is green with `APP-*` claims + traps.
6. Deferred surfaces (groups, calls) are **labelled placeholders**, not simulated crypto.

---

## 14. Adversarial review

*(Filled in §15 after the review pass — the plan above is reviewed for the ways it could ship a
plausible-but-broken or secretly-faked "working app", and revised accordingly.)*
