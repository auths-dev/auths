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

## 3. P0 engine deliverable: the identity-curve bridge (gates everything; NOT a spike)

> **Adversarial review correction (PF-1/PC-2/PE-1):** the first draft called this a "spike." It is a
> real, invasive refactor of the **audited** `murmur-core` verify path, and it gates every downstream
> milestone. The current 123 green tests are **all Ed25519** and prove *nothing* about the P-256 path
> the shipped app runs — the exact green-while-false trap. Treat this as engine work with its own claim,
> done and gated **before P1**.

`murmur-core::Identity` signs **Ed25519** and the verify path is hardcoded to it; the app's AID root
must be **P-256 in the Secure Enclave** (auths' default, the only SE curve). The concrete, evidenced
work:

1. **Curve-dispatch `verify_sender`.** `identity.rs:88` calls `RingCryptoProvider::ed25519_verify`
   **unconditionally**; it is the verify chokepoint for **9 call sites** (prekey `prekey.rs:180`, Olm
   bundle `olm_backend.rs:152`, KEL events + witness receipts `kel.rs:138,436`, delegation anchors +
   revocations `delegation.rs:179,218`, inner envelope `lib.rs:296`). Replace the direct call with a
   `match key.curve()` dispatch to `auths-crypto`'s `verify_typed` (`p256_verify` exists,
   `ring_provider.rs:94`). **The claim "the Olm join is unaffected" was FALSE** — `verify_rooted` routes
   through `verify_sender` and inherits the lock.
2. **A seedless / typed `Identity`.** `Identity::from_seed` (`identity.rs:39`) hardcodes
   `TypedSeed::Ed25519`; `IDENTITY_CURVE` (`:98`) is a dead const. Add `Identity::from_public_key(curve,
   pubkey)` + a **sign callback** so the private key lives only in the SE — and refactor `Identity::sign`
   (used by `publish`/`incept`/`rotate`/`issue` and `OlmIdentity`, which holds an `Identity` by value)
   to delegate to it. This is structural, not a wrapper.
3. **AID canonicalization (the byte-width landmine).** `Aid::from_public_key` (`address.rs:40`) is
   `SHA-256(raw pubkey)`: Ed25519 = 32 bytes, P-256 compressed = **33**. So "the same" key on two curves
   yields unrelated AIDs, and the `verify_sender` AID-match guard recomputes and compares — any
   compressed/uncompressed SEC1 mismatch silently breaks the binding. **Decision: commit to compressed
   SEC1 for P-256 and normalize on every resolve** (`auths_crypto::normalize_verkey`).
4. **Audit `[u8;32]` AID-key assumptions.** AID public keys become `bytes`/`Vec<u8>` (33 bytes for
   P-256), never `[u8;32]` (which is reserved for Curve25519 Olm keys). The Olm hygiene compare
   (`olm_backend.rs:141`) is safe (unequal-length slices compare unequal) but the FFI typing must change.

**Claim `APP-CURVE-1` (P0):** a **P-256, SE-backed** AID signs its prekey bundle, a KEL event, a
delegation anchor, and an inner signature, and **each verifies through `verify_sender`** — with a
parametrized Ed25519-and-P256 matrix. Trap: a P-256 signature verified by the old Ed25519-only path is
RED. (Risk RI-1.)

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

**UniFFI realities & corrections (PE-2 / PC-5) — the table above is intent; the buildable surface is:**
- **No `[u8;N]` across the boundary** — UniFFI expresses only `bytes`/`Vec<u8>`; Rust re-validates length
  on entry. (AID public keys are `bytes`, 33-byte P-256 — §3.4.)
- **The SE signer is a `callback interface Signer { sign(bytes) -> bytes }`** (fallible, re-entrant,
  may cancel on user-presence). It requires the **seedless `Identity`** from §3.2; `OlmIdentity::new`
  today needs a seed-bearing `Identity`.
- **Stateful objects (`LocalIdentity`, `OlmChannel`/`OlmEndpoint`) are `Arc<Mutex<…>>` interfaces** —
  UniFFI methods are `&self`, but `establish_inbound`/`encrypt`/`decrypt` are `&mut self`, so they need
  interior mutability.
- **`Directory` (`&dyn`) does not cross UniFFI.** AID→key resolution is Swift-side; the FFI verify
  methods are pure `(key_bytes, sig, msg) -> verdict`. `Kel`/`KelEvent`/`WitnessReceipt`/`WitnessPolicy`/
  `KeyState` become explicit UniFFI **records**.
- **Trust is ONE call (PC-5):** `Trust.evaluateKel(kelJson, witnessPolicy) -> TrustBadge` that does
  `Kel::replay → verify_continuation` **internally**. Do **not** expose `evaluate(prior, current)` over
  caller-supplied key-states as the app path (the relay could then choose both states and manufacture a
  `VerifiedContinuation`). The directory/`evaluate` seam stays test-only.
- **No raw `Channel.decrypt -> bytes` in the app surface (PC-1)** — replaced by `OlmEndpoint.open`
  (decrypt+verify atomic, §6.3).

**What stays Swift-side, not FFI:** the **relay transport** (network), the **local DB**, and the **SE
signing** (the FFI calls *out* via the `Signer` callback). The **mailbox-id derivation is in the ENGINE**
(§6.2 — it's a cryptographic primitive, not a Swift detail), exposed as an FFI method. The FFI deals
only in identities, channels, bundles, ciphertext bytes, verdicts, and the derived mailbox id.

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

**6.1 `murmur-relay` server front-end — its own milestone (P2.5), not a wrapper (PE-6).** Today
`murmur-relay` has **no async runtime, no HTTP, no TLS** and an **in-memory `MailboxStore` that drops
every undelivered message on restart** (`relay.rs:170`), and the quotas are per-mailbox/global-byte
only — **no per-IP limiter**. The real work: pick an async stack (tokio + axum); implement
`POST /deposit {mailbox, ciphertext}` → `MailboxStore::deposit` and a **WebSocket subscription** for
drain with backpressure; **durable storage** (a relay restart must not lose queued messages); **per-IP
rate limiting** + connection anti-abuse; TLS + SPKI pinning; deployment/operations/cost. The relay
authenticates **nothing about the sender** (that's the point) — which means **anyone who learns a
mailbox id can flood it to `QuotaExceeded` and censor the victim** (PC-6); rotating mailbox ids (§6.2)
plus an optional deposit capability token mitigate. Add a per-session **sender sequence number** the
relay cannot forge so the client detects reorder/loss past Olm's 40-key window (R12/PC-6).

**6.2 The mailbox id is a cryptographic primitive in the ENGINE (PC-3), not a Swift string.** Today
every `MailboxId` is a literal (`relay.rs:30`) and the draft's "unlinkable" claim had **no derivation**.
Specify it in `murmur-core` so it is testable: a **rotating** id
`mailbox = HKDF(pairwise_secret, "murmur/mailbox/v1" ‖ epoch)`, where `pairwise_secret` is **independent
of any public key** (NOT `session_id()`, which is public-key-derived, stable, and recomputable by anyone
who learns both Olm identity keys — a permanent linkable fingerprint). Both peers derive the same id for
an epoch without revealing it to the relay; rotation per epoch denies the relay a stable per-pair graph.
**Claim `APP-RELAY-2`:** two epochs produce unlinkable ids, and neither AID nor the Olm identity keys
recompute the id (a leakcheck trap). The Swift `RelayTransport` then deposits/subscribes on the
engine-derived id; offline → outbox + retry; `OfflineBanner` reflects real connectivity.

**6.3 The envelope split + the JN-5 binding (a P0 engine deliverable, not "above the FFI").**

> **Adversarial review correction (PC-1):** the draft claimed the inner signature "binds the sender's
> Olm key" and that this happens above the FFI. **Both are false today.** `InnerEnvelope::signing_bytes`
> (`envelope.rs:64-77`) signs only `context ‖ sender ‖ recipient ‖ body` — **no Olm key, no session
> id** — and the only inner-signature enforcement, `Endpoint::open` (`lib.rs:288`), runs on the in-tree
> `Session`, **not** `OlmChannel`. `OlmChannel` carries **no AAD** at all. So nothing cross-binds the
> Olm channel to the signed AID; a future caller that attributes an AID from "whose channel this is"
> instead of purely from the inner signature is forgeable.

Two engine changes (in `murmur-core`, before any P2 "message arrives" claim):
1. **Bind the channel into the signature.** Extend `InnerEnvelope::signing_bytes` to
   `context ‖ sender_aid ‖ sender_olm_identity_key ‖ recipient_aid ‖ session_id ‖ body`, so a valid
   inner envelope is cryptographically pinned to *this* Olm session and the sender's Olm key — not
   replayable into another session.
2. **Build `OlmEndpoint` — atomic decrypt-then-verify.** There must be **no** FFI path that returns Olm
   plaintext without verifying the inner signature. `OlmEndpoint.open(wire, sender_key)` does
   `OlmChannel::decrypt` → parse inner → **`verify_sender` against the sender's witness-resolved AID
   key** → return the message, or reject. The FFI exposes `OlmEndpoint.open`, **not** a raw
   `Channel.decrypt -> bytes` (that standalone method is removed from the app-facing surface — §4).

Send path: app builds the inner envelope, **signs it in the SE** (binding now includes the Olm key +
session id), `OlmEndpoint.seal` encrypts it → `{mailbox, ciphertext}`, deposits. **Claim `APP-AUTH-1`
(P2 precondition):** a peer that establishes a valid Olm channel as the *wrong* AID is rejected on open;
trap = a missing/forged inner signature is RED.

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
| **Multi-device / pairing** (`AddDeviceView`) | `asyncAfter(1.2s)` → "Device added"; QR is a random UUID | real OOB pairing: new device's key → root device signs a `DelegationAnchor` → travels back; admit; revoke from PersonalProfile (P4). **Until built: disabled, not faked** |
| **Recovery / guardians** (`RecoveryView`, `PersonalProfileView`) | "pick 3, any 2 restore you" — pure local list, **no SSS/threshold, no engine** | **EXISTENTIAL** for an SE-rooted AID (lose the device → lose the AID forever). M-of-N guardian recovery is real design (Shamir / social-recovery KEL). Until built, the UI must show **"recovery not yet set up — your identity is not backed up,"** never a green "Recovery is set up" |
| **Claim a handle** (`ClaimHandleView`) | sets a string `you@murmur.im`, no proof | `did:webs` domain verification — real proof or a disabled placeholder |
| **Relays & witnesses** (`AboutView`) | 3 witnesses hardcoded "online"; "swap relay" sets a label | real witness-health from KEL `WitnessPolicy`; relay config actually re-points the transport |
| **Block / Report, Archive, Note-to-Self** | local store mutations shown as privacy features | wire to real policy (block = stop accepting that AID's mailbox; note-to-self = a real self-session) or label honestly |
| **Calls** (`CallView`) | **renders a literal `Label("End-to-end encrypted")` over a fake timer** | **TEAR DOWN now:** delete the "End-to-end encrypted" label and disable the live Call/Video buttons → "Calls coming in v2." A real call needs SRTP/ICE (v2) |
| **Delete-for-everyone / disappearing / read-receipt-off** | `deleteForEveryone` calls `deleteForMe`; disappearing is a label; receipts faked on timers | **false privacy promises** — each must be a real sealed control message (peer actually drops it / receipt actually suppressed, with a trap) **or the affordance is removed**. No button that lies |

**Rule (hardened — PF-2/PF-3/PF-6/PF-9): the placeholder rule applies to the fakes ALREADY in the app,
as teardown, not just to future surfaces.** Before any milestone ships, every surface is **real (engine-
or relay-backed, with a trap)** or **visibly disabled** — there is no third "live button that lies"
state. Specifically torn down or wired before claiming done: the CallView "End-to-end encrypted" label,
delete-for-everyone, disappearing timers, the read-receipt-off toggle, the onboarding "Verified on this
device" / "Identity ready" shown on a 1.4s timer (PF-9), and the guardian-recovery "Recovery is set up"
green state. Add **`APP-NOFAKE-1` traps** (e.g. the string "End-to-end encrypted" must not ship on the
call surface without a real media path; a "Delete for everyone" that only deletes locally is RED). §7 is
re-derived from `grep -rE "struct [A-Za-z]+View"` over the app — **all 27 Views** are accounted for as
real / disabled / explicitly-cut.

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

- **P0 — Engine bridge + FFI foundation (the real gate).** **(a)** the curve bridge (§3) — *engine
  refactor*, not a spike; **(b)** the inner-signature Olm binding + `OlmEndpoint` atomic decrypt-verify
  (§6.3) — *engine*; **(c)** the mailbox-id derivation (§6.2) — *engine*; **(d)** `murmur-ffi` feature
  passthrough (§10) + the UniFFI-real surface (§4); **(e)** Swift `MurmurEngine` wrapper. *Done when:* a
  host test mints **P-256 SE-backed** identities and seals→opens an **AID-authenticated** message with
  no stub. **Claims:** `APP-CURVE-1` (P-256 verifies through `verify_sender`), `APP-AUTH-1` (wrong-AID
  channel rejected on open), `APP-FFI-1` (loop green), `APP-FFI-2` (olm in the **committed** slice).
- **P1 — Onboarding + identity** *(depends on the **completed** P0 bridge, not a spike — PE-8).* SE
  P-256 mint, publish bundle, persist; onboarding wired (tear down the 1.4s "Verified" theatre).
  **Claim:** `APP-ONBOARD-1` (SE custody: non-exportable key, AID derives from it; not a persisted
  string).
- **P2 — 1:1 messaging end to end.** Establish (verify→channel), `OlmEndpoint` seal/open (inner-sig
  enforced — hard precondition), `RelayTransport` over the engine-derived mailbox id; Thread + ChatsList
  + deep-link receive live. **Claims:** `APP-MSG-1a` (hermetic Olm self-test, gateable, with a
  **malicious-relay trap**: tamper/substitute-key/relocate all rejected), `APP-MSG-1b` (live two-device
  sim + separate-process relay — operator demo, **not** the hermetic gate), `APP-RELAY-1` (wire is
  mailbox+ciphertext only), `APP-RELAY-2` (mailbox id unlinkable across epochs), `APP-SESSION-1` (engine
  anti-rollback round-trip; app-side enforcement is an operator check — PE-9).
- **P2.5 — Relay server (its own project — §6.1).** async stack, durable storage (no drop-on-restart),
  per-IP limit, TLS+pinning, sender sequence numbers. **Claim:** `APP-RELAY-3` (a restart loses no queued
  message; a flood is rate-limited, not a global DoS).
- **P3 — Trust & keys.** Witnessed `Kel::replay` resolution (NOT a relay-controlled directory),
  `Trust.evaluateKel`, key-change pause on a **relayed** substitution, `KeyHistoryView`, **SAS engine
  primitive** + verify-in-person. **Claims:** `APP-TRUST-1` (relayed non-pre-committed change loudens +
  pauses the live thread; a fork/sub-threshold/swapped-prior must NOT yield continuation),
  `APP-TRUST-2` (pre-committed rotation stays silent), `APP-SAS-1` (the safety number derives from both
  witnessed keys).
- **P3.5 — Push + background sync (§11).** APNs + metadata-blind push service + NSE decrypt; `BGTask`
  drain. **Claim:** `APP-PUSH-1` (a backgrounded device receives + decrypts without leaking metadata to
  the push path).
- **P4 — Multi-device, requests, profile, recovery.** OOB device pairing (root signs the anchor) +
  revocation; opt-in request firewall; **guardian/social recovery (existential — RI-13)**; sealed
  attachments; OTK replenishment (RI-11). **Claims:** `APP-DEV-1` (the **app's** revoke → `DeviceRevocation`
  → a separate-process peer rejects the revoked device's next message), `APP-RECOVER-1` (M-of-N restores
  the AID; until built the UI says "not backed up").
- **P5 — Groups (Megolm) + calls.** v2; placeholders until built (the fake call screen torn down in §7).

**Each milestone gates on `recurve --config .recurve/murmur.toml matrix --gate` staying green**, with new
`APP-*` probes per the probe contract (`probes/_contract.sh` + the `msg-1.sh` marker pattern — single
masked marker line, trap that goes RED; PE-10). **Every `APP-*` claim binds to the running UI action over
a separate-process relay with witnessed resolution and SE P-256 keys — never to an engine unit test in
isolation** (the central review lesson: the engine is strong; the trap is greening it in isolation while
the app stays theatrical).

---

## 10. Build & CI changes

- **`murmur-ffi/Cargo.toml` needs a feature passthrough first (PE-3):** it has **no `[features]`**
  section today, so `--features olm` fails outright. Add `olm = ["murmur-core/olm"]`. (The
  `olm_backend` re-exports are `#[cfg(feature = "olm")]`, so the FFI can only `use` those types with the
  feature on.)
- `scripts/build-ffi.sh`: add `--features olm` to **each** `cargo build --target …` **and** to the
  `uniffi-bindgen generate --library` step (the bindgen library must be the *same* feature set or the
  generated Swift omits the new objects).
- `project.yml`: no target change; the xcframework gets the larger binding surface.
- **The federated gate does NOT exercise Olm by flipping this flag (PE-4 correction).** The gate probes
  drive **`murmur-relay serve`**, and `murmur-relay` **never references Olm** — `serve` runs the in-tree
  path. Turning on `--features olm` in the *FFI* build changes the *app's* engine, not the gate's relay
  binary. So **M5 gate-level parity does NOT converge here for free**: either (a) route the relay (or a
  new probe driver) through the Olm backend behind the feature, or (b) scope `APP-FFI-2` to a
  **slice-inspection** probe (the committed xcframework exports an Olm-only symbol). The gate must also
  check the **committed** xcframework (not a local rebuild) so a stale vendored binary fails (PF-10).
- CI: build all three slices + run `MurmurEngineTests` (host) + the FFI Rust integration test; rebuild +
  diff the xcframework so a stale `Vendor/MurmurFFI.xcframework` fails the gate.

---

## 11. Subsystems — required-but-omitted vs genuinely deferred

**Required for "fully working," but missing from the first draft (PE-7) — add as milestones:**
- **Push / APNs (P3.5).** A store-and-forward messenger with no push only receives while foregrounded.
  Needs APNs + a push service that learns no metadata + a Notification-Service-Extension that decrypts.
  Hard, but non-optional for a usable app. (Grep confirms zero `UNUserNotification` today.)
- **Background sync / `BGTask` (P3.5).** Without background drain, delivery/read status never settle.
- **Deep-link receive (P2).** The invite link `murmur.im/i/<bundle>` has a *share* half but **no
  `onOpenURL` receive half** — universal-link parse → verify bundle → start request.
- **Guardian / social recovery (P4, EXISTENTIAL).** The UI already advertises it; an SE-rooted AID with
  no recovery means **device loss = identity loss forever**. M-of-N guardian recovery (the product's
  "friends are your backup" promise, and the auths platform's guardian recovery) must be real or the
  surface must say "not backed up." Not optional for launch.
- **Multi-device state sync (P4).** Contacts / read-state / conversation sync across a user's own devices
  (delegated sub-identities) — sealed control messages, not key sharing.
- **App lifecycle / state restoration (P2).** `scenePhase`, secure background snapshot.

**Genuinely v2-deferred (honest placeholders, never simulated crypto):**
- **Groups** — Megolm exists; the group join + membership is real design. Labelled "coming soon."
- **Calls** — SRTP/ICE + signaling; v2. **The existing fake "End-to-end encrypted" call screen is torn
  down now** (§7), not shipped as-is.
- **Reactions / typing** — sealed control messages where cheap, else cosmetic-only and labelled.

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
| RI-9 | **[PC-4]** SE sign-callback is a blind signing oracle — a malicious FFI caller has the SE sign a forged KEL rotation / delegation anchor / revocation | high | constrain the callback to **allowlisted domain-separation context prefixes** (or pass a *typed* sign request the host validates); require **user-presence** on rotation/delegation/revocation signs |
| RI-10 | **[PC-4]** Anti-rollback defeated by a full-device **backup restore** (rolls back blob *and* the Keychain generation together) | high | hardware-monotonic anchor (SE counter), not a plain Keychain item; document that backup-restore resurrects pre-backup sessions; per-session counter for multi-device |
| RI-11 | **[PC-6]** First-message FS silently degrades to the reusable fallback after the first contact (one OTK per publish, no replenishment) | high | OTK **batch publish + relay-served one-per-fetch + replenishment**; bundle freshness/expiry; the relay must not serve a stale bundle indefinitely |
| RI-12 | **[PC-6]** No safety-number / SAS primitive exists, yet VerifyInPerson + trust-pause promise one | high | named **engine** deliverable: a domain-separated hash over the sorted pair of **witnessed current keys** (not app-layer hand-rolled crypto) |
| RI-13 | **[PE-7]** Guardian/social recovery is advertised but absent → SE-rooted device loss = permanent identity loss | high | real M-of-N recovery before launch, or the UI shows "not backed up"; existential, not deferrable to a silent v2 |
| RI-14 | **[PC-6]** Unauthenticated deposit + shared mailbox id → anyone who learns the id floods it to `QuotaExceeded` (censorship) | med | rotating mailbox ids (§6.2) + optional deposit capability token; per-IP limit |

---

## 13. Success criteria (definition of "fully working app")

1. Onboarding mints a **real Secure-Enclave AID** (`APP-ONBOARD-1`) — proven by **SE custody**, not a
   persisted string: a `SecKey` with `kSecAttrTokenIDSecureEnclave` exists, the private key is
   **non-exportable** (export fails), the displayed AID derives from its public part, and a signature it
   produces verifies through the engine (PF-9).
2. A message composed on one device is **sealed, relayed, and opened — AID-authenticated — on another**,
   split into a **gateable** hermetic Olm self-test (`APP-MSG-1a`) **and** a **live two-device sim +
   separate-process relay** operator demo (`APP-MSG-1b`, explicitly *not* the hermetic gate — matching
   the DEV-1 pattern; PE-5). The gate proves it over the Olm path with a **malicious-relay trap**
   (tamper → AEAD reject, directory-key substitution → `verify_sender` reject, mailbox relocation →
   reject), and the relay provably sees only mailbox + ciphertext (`APP-RELAY-1`).
3. **No `DemoStore`/`DemoData` linked in the shipped target** (a CI symbol check — delete the type,
   don't just stop calling it). Every identity / message / key / trust surface has a **per-flow
   real-source assertion**: the trust badge traces to `Trust.evaluateKel`, the AID to
   `LocalIdentity.aid()`, a message body to `OlmEndpoint.open` — not a stub (replaces the gameable
   `DemoData.*` grep; PF-8).
4. **Trust is real, over witnessed KEL replay**: a non-pre-committed key change *delivered via the
   relay-resolved KEL* loudens the badge and pauses the **live** thread; a pre-committed rotation stays a
   silent continuation (`APP-TRUST-1/2`). A relay that serves a fork, a sub-threshold tip, or a swapped
   prior-state must **not** produce `VerifiedContinuation` (PF-4/PC-5).
5. **Sender authentication is mandatory**: no FFI path returns Olm plaintext without inner-signature
   verification (`OlmEndpoint.open`); a channel established as the wrong AID is rejected (`APP-AUTH-1`).
6. The FFI ships **`--features olm`** (committed xcframework symbol-checked); the federated gate is green
   with `APP-*` claims + traps.
7. Every app surface is **real or visibly disabled** — the §7 teardown rule holds; **no live button that
   lies** (call "E2E encrypted" label gone, delete-for-everyone real-or-removed, recovery shows
   "not backed up" until built; PF-2/PF-3/PF-6).

---

## 14. Adversarial review — findings & resolutions

Three parallel specialists reviewed the draft against the real app, engine, and FFI, told to falsify
"100% of surfaces" and "fully working app": a **claims-auditor** (where could it ship a faked secure
messenger), a **crypto/protocol** lens, and a **staff-engineer feasibility** lens. **Verdict: the draft
would have shipped a plausible-but-broken app.** The engine (`murmur-core`) is genuinely strong; the
trap was that **every `APP-*` claim could be greened by exercising the engine in isolation (Ed25519
seeds, in-proc relay, in-memory directory) while the app surfaces stayed theatrical.** Two load-bearing
claims were outright false against the code. The plan above (§3–§13) is **revised** to absorb all of it.

**Findings register (raised → confirmed; all confirmed are resolved in the plan):**

| ID | Sev | Finding | Resolution in this plan |
| --- | --- | --- | --- |
| PF-1 / PC-2 / PE-1 | **Crit** | The "curve bridge" is an **engine refactor**, not a spike: `verify_sender` hardcodes Ed25519 (`identity.rs:88`, 9 call sites), AID = `SHA-256(raw pk)` so P-256's 33 bytes change the AID; "Olm join unaffected" was false; 123 green tests are all-Ed25519 | §3 rewritten as a **P0 engine deliverable** (curve-dispatch verify, seedless/typed `Identity`, SEC1 canonicalization, `[u8;32]`→`bytes`, P-256 test matrix); `APP-CURVE-1` |
| PC-1 / PE-8 | **Crit** | The inner signature **binds no Olm key** (`envelope.rs:64`) and **no engine path enforces it on an Olm receive** (`Endpoint::open` is in-tree `Session`, not `OlmChannel`; `OlmChannel` has no AAD) | §6.3 rewritten: extend `signing_bytes` to bind `sender_olm_identity_key ‖ session_id`; build **`OlmEndpoint` (atomic decrypt-verify)**; no raw `Channel.decrypt` in the app surface; `APP-AUTH-1` |
| PF-2/3/6/9 | **High** | Surfaces **already faked in the app** (CallView "End-to-end encrypted" over a timer; delete-for-everyone = deleteForMe; disappearing/read-receipt-off; onboarding "Verified" on 1.4s; guardian recovery) — the §7 rule wasn't applied to them | §7 **teardown rule** + new rows for every faked surface; `APP-NOFAKE-1` traps; "real or visibly disabled — no live button that lies" |
| PF-3 / PE-7 | **High** | "100% of surfaces" was false by enumeration — Recovery/guardians, Claim-handle, Add-device, Witness-health, Block/Archive/Note-to-Self **absent**; push/background-sync/deep-link/lifecycle missing; **guardian recovery existential** for an SE-rooted AID | §7 re-derived from all 27 Views; §11 split into **required-but-omitted** (push P3.5, recovery P4, deep-link/lifecycle P2) vs v2-deferred; RI-13 |
| PF-4/5 / PE-5 | **High** | `APP-MSG-1`/`APP-TRUST-1` could pass on **in-proc relay + in-memory directory + Ed25519 seeds + a UI enum** — none of the hard properties exercised; the hermetic gate can't boot 2 apps + a network relay | §9: claims **bind to the running UI over a separate-process relay + witnessed resolution + SE keys**; `APP-MSG-1` split into gateable **1a** (Olm self-test + malicious-relay trap) and non-gate **1b** (live sim demo) |
| PC-3 / PE-6 | **High** | Mailbox-id **unlinkability had no derivation** (all literals; `session_id` is a stable public-key fingerprint); the relay front-end is a **project** (no async/TLS/persistence/per-IP limit; drops messages on restart) | §6.2: rotating `HKDF(pairwise_secret, epoch)` **in the engine** + `APP-RELAY-2` leakcheck; §6.1 + **P2.5** milestone for the relay server; RI-14 |
| PC-5 | **High** | Trust could run on **relay-supplied key-states** (`trust::evaluate` does no replay) and the **directory fallback** (no witness check) is the live resolver | §4: expose **one** `Trust.evaluateKel(kel, policy)` doing `replay→verify_continuation`; §13.4: a fork/sub-threshold/swapped-prior must not yield continuation; resolver is witnessed |
| PC-4 | **High** | Anti-rollback defeated by **backup-restore** (rolls back blob+counter together); the **SE sign-callback is a blind signing oracle** (forge KEL/delegation/revocation) | RI-9 (allowlist context prefixes + user-presence on rotation/delegation/revocation), RI-10 (hardware-monotonic anchor, per-session counter) |
| PE-2 | **High** | §4 FFI types **not UniFFI-expressible**: `[u8;N]`, `&dyn Directory`, `&mut self` objects; SE callback needs a **callback interface + seedless `Identity`** | §4 "UniFFI realities" block: `bytes`, `Arc<Mutex>`, `callback interface Signer`, records; seedless `Identity` (ties to §3.2) |
| PE-3 | **High** | `murmur-ffi` has **no `[features] olm`** → `--features olm` fails | §10: add `olm = ["murmur-core/olm"]`; build slices + bindgen with the feature |
| PE-4 / PF-10 | **High** | Flipping `--features olm` does **not** make the **gate** exercise Olm (the relay binary never references it); the gate links the **committed** xcframework | §10: route the relay/probe through Olm **or** scope `APP-FFI-2` to a committed-slice symbol check; CI diffs the xcframework |
| PC-6 | **Med-High** | **OTK degradation** (1 OTK/publish → fallback for everyone after first contact); **no SAS primitive** exists; device-pairing OOB channel undesigned; relay has no ordering/deposit-auth | RI-11 (OTK batch + replenish), RI-12 (SAS as an **engine** primitive over witnessed keys), §9 P4 pairing, §6.1 sequence numbers |
| PF-8 | **Med** | `§13` grep proxy is gameable (most fakes don't reference `DemoData.*`) | §13.3: **per-flow real-source assertions** + a CI check that `DemoStore`/`DemoData` is **not linked** in the shipped target |
| PE-9 / PE-10 | **Low-Med** | Swift anti-rollback KeyStore unbudgeted; new markers must obey leakcheck/`_contract.sh` | §9 budgets it; §13.1 scopes `APP-SESSION-1` to what the gate proves; §9 points at the marker template |

**Cleared (raised, not a finding):** the engine primitives themselves — `Kel::replay` (fork +
sub-threshold rejection), `verify_continuation` (pre-commitment), delegation/revocation/corroboration,
the Olm backend — are sound. **Every failure was at an integration seam the plan owns**, which is exactly
where this review was aimed.

**Three structural lessons baked into the revision:**
1. **Promote the two gating engine changes** (curve bridge, inner-sig Olm binding) from "spike/contract"
   to **named P0 engine deliverables with claims** — they are false today and invisible to the
   all-Ed25519 test suite.
2. **Bind every `APP-*` claim to the running UI over a separate-process relay with witnessed resolution
   and SE keys** — not to an engine unit test. Tighten the FFI so the *secure* path is the *only*
   callable one (one trust call, no raw decrypt).
3. **Apply the "real or disabled, never a lying button" rule to the fakes already in the app**, and
   re-derive "100% of surfaces" from the actual 27 Views — including the existential omission (recovery).
