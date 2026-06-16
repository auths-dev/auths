# Murmur Encryption — Migrating to `vodozemac` (Olm / Megolm)

> Companion to `messaging/murmur.md` (messenger PRD), `auths/docs/plans/security/murmur-crypto-adversarial-review.md`
> (the adversarial review), and `messaging/libsignal-migration.md` (the considered-and-rejected
> alternative — see §11 for why). **Decision: `vodozemac`.** The per-finding hardening band-aids
> already landed (Commits A–E); this PRD is the *root fix* — replace the homegrown ratchet with an
> audited library.

---

## 1. Decision & context

The adversarial review confirmed Murmur's crypto is **real** but **homegrown**, and homegrown
crypto carried the bug classes the PRD predicted. We hardened it in place (7 highs + 2 mediums
fixed, each with an adversarial regression test, gate green). The review's root-cause recommendation
stands: **stop maintaining our own ratchet.** We replace `session.rs` / `ratchet.rs` /
`dh_ratchet.rs` / the X3DH in `prekey.rs` with **`vodozemac`** — Matrix's pure-Rust, Apache-2.0,
**Least-Authority-audited** implementation of the **Olm** (1:1 Double Ratchet) and **Megolm** (group
ratchet) protocols.

**Why vodozemac (decided):**
1. **Apache-2.0 — uniform with the auths workspace.** No copyleft, no second-license boundary to
   police in the monorepo, no App-Store/proprietary friction. (libsignal is AGPL-3.0 — see §11.)
2. **Audited.** Least Authority audited vodozemac (2022, public report) — the same "vetted, not
   self-rolled" property ENC-6 demands.
3. **Pure Rust, clean cross-compile** to the iOS/macOS slices the FFI xcframework needs (shares
   `x25519-dalek` / `ed25519-dalek` / `sha2` / `hmac` / `hkdf` with Murmur today → near-zero new
   transitive tree).
4. **Olm *and* Megolm.** Olm gives 1:1 forward-secrecy + post-compromise security (same family as
   Signal's Double Ratchet); **Megolm gives us the group ratchet for free** — a head start on the
   v2 group feature (`messaging/murmur.md` §11.3).
5. **Murmur doesn't need Signal *network* interop.** Our root of trust is the AID, not a phone
   number, so we structurally can't (and don't want to) join Signal's network — the one thing
   libsignal offered over vodozemac is unusable here. The ratchet choice is decoupled from
   adoption/exit; the moat is the identity layer (§11).

**Honest framing for claims/marketing:** vodozemac is **Olm**, a Double Ratchet in the *same family*
as Signal's, not Signal Protocol itself. We say "an **audited** Double Ratchet (Olm/vodozemac)," not
"Signal Protocol." Same forward-secrecy + post-compromise guarantees for 1:1.

---

## 2. Goals / non-goals

**Goals**
- Replace the homegrown ratchet + X3DH with `vodozemac::olm` behind a stable internal trait.
- Keep every closed claim (MSG-1..4, ENC-1..5, WIT-1, RVK-1, DEV-1) **green** through the swap.
- Re-arm **ENC-6** truthfully ("vodozemac-backed audited Olm").
- Leave the KERI↔Olm **join** as the only custom crypto seam, routed through **ENC-7** (external
  audit) before any real user.
- Position **Megolm** as the group-encryption path for v2 (not built in this migration).

**Non-goals**
- Signal *interop* (we use a Double Ratchet, not Signal's network/identifiers).
- Replacing the KERI identity layer, the relay, or the two-layer envelope.
- Eliminating the external audit — the **join** is still custom; vodozemac's audit covers Olm, not
  our wiring of it to a KERI root.
- Building Megolm groups in this PRD (scoped, not implemented here).

---

## 3. Scope — REPLACE / KEEP / JOIN

**REPLACE (the ratchet — delete the homegrown impl):**

| Murmur today | file:line | vodozemac equivalent |
| --- | --- | --- |
| `Session` (AEAD + per-msg key) | `crates/murmur-core/src/session.rs` | internal to `olm::Session` |
| `Session::seal` / `open` | `session.rs` (`pub(crate) seal`, `open`) | `olm::Session::encrypt` / `decrypt` |
| `Ratchet` (HMAC chain) | `ratchet.rs` | internal to `olm::Session` |
| `DhRatchet` (root advance) | `dh_ratchet.rs` | internal to `olm::Session` |
| X3DH (`derive_root`, `x3dh_initiator/responder`) | `prekey.rs` | `olm::Account::create_outbound_session` / `create_inbound_session` |
| our identity/one-time/signed prekeys | `prekey.rs` (`PrekeyBundle`) | `olm::Account` (Curve25519 identity + one-time keys + fallback key) |
| nonce / counter / zeroization | session/ratchet | internal to vodozemac (it owns nonce, counter, and zeroization) |
| out-of-order / skipped keys | n/a (strict in-order today) | internal to `olm::Session` (bounded skipped-message-key cache) |

**KEEP (not the ratchet's job — unchanged):** the KERI identity layer (`kel.rs`, `rotation.rs`,
`delegation.rs`, `corroboration.rs`, `identity.rs`/`Aid`), the relay (`relay.rs`/`MailboxStore`, now
quota-bounded), `number_free.rs`, `leakcheck.rs` (as a *tool*), the two-layer
`OuterEnvelope`/`InnerEnvelope`, and — critically — the **inner signature** (`Endpoint` signs
`sender‖recipient‖body`, verified before surfacing). The inner signature is what makes a message
authenticated *as an AID*; Olm does not provide it and never will.

**JOIN (the only custom crypto seam — externally audited):** how a KERI-authenticated prekey bundle
becomes an Olm session (§5).

---

## 4. vodozemac API mapping (detailed)

vodozemac's `olm` module is the 1:1 protocol. The two types that matter:

**`olm::Account`** — your long-term key material + prekeys.
- Identity keys: `curve25519_key()` (the DH identity key) and `ed25519_key()` (the signing key).
- `generate_one_time_keys(n)`, `one_time_keys()`, `mark_keys_as_published()` — the one-time prekeys
  a recipient publishes; consumed once per new inbound session.
- `generate_fallback_key()`, `fallback_key()` — the reusable fallback used when one-time keys are
  exhausted (degraded first-message FS — §7).
- `create_outbound_session(SessionConfig, their_curve25519_identity, their_one_time_key) -> Session`
  — the initiator handshake (Olm's triple-DH, the X3DH analog).
- `create_inbound_session(their_curve25519_identity, &PreKeyMessage) -> InboundCreationResult { session, plaintext }`
  — the responder handshake (also yields the first plaintext).
- `pickle()` / `from_pickle(pickle, pickle_key)` — encrypted serialization for persistence.

**`olm::Session`** — the established ratchet (opaque; owns the Double Ratchet).
- `encrypt(plaintext: &[u8]) -> OlmMessage` — seal (no caller nonce, no caller AAD — §7).
- `decrypt(&OlmMessage) -> Result<Vec<u8>>` — open (handles out-of-order internally).
- `session_id()` — a stable id derived from both identity keys (binds the pair — §7).
- `has_received_message()`, `pickle()` / `from_pickle()`.

**`OlmMessage`** — `PreKey(PreKeyMessage)` (the first message, carries handshake material) or
`Normal(Message)` (subsequent). Serializable to bytes for our `OuterEnvelope.ciphertext`.

**Groups (v2, not in scope here):** `megolm::GroupSession` (outbound) + `megolm::InboundGroupSession`
— forward-secret group messaging. Note: Megolm is a sender-key ratchet → **forward-secret but not
per-message post-compromise-secure** (inherent to group ratchets); design the group claim accordingly.

> Spike-confirm: exact method signatures and `SessionConfig` (v1 vs v2) shift across vodozemac
> versions — pin a version in M1 and lock the API surface against it.

---

## 5. The KERI↔Olm join (the audited seam — detailed)

This is the only crypto that stays custom and the entire scope of the ENC-7 audit.

**The prekey bundle, in Olm terms.** Murmur's published bundle becomes: the recipient's **Olm
Curve25519 identity key** + a **one-time key** (or the fallback key), with the whole bundle **signed
by the AID's current KERI key** (the existing `prekey.rs::verify_rooted` logic — KEPT).

**Outbound (initiator) flow:**
1. Resolve recipient AID → current KERI key via the directory (KEEP).
2. Verify the bundle's signature against that key; assert the Olm Curve25519 identity key **≠** the
   AID's Ed25519 signing key (the §3.1 hygiene rule — KEPT; note Olm naturally uses a *separate*
   Curve25519 identity key, so hygiene is structural, with the KERI signature binding it to the AID).
3. `account.create_outbound_session(cfg, their_curve25519_identity, their_one_time_key)` (REPLACE
   the X3DH). The first message is a `PreKey` `OlmMessage`.

**Inbound (responder) flow:**
1. Receive a `PreKey` `OlmMessage`; `account.create_inbound_session(their_curve25519_identity, &prekey_msg)`
   → `(Session, first_plaintext)`.
2. The sender's AID is authenticated by the **inner signature** (KEEP) — Olm authenticates the
   *channel*, KERI authenticates the *identity*.

**Rotation (re-pin):** on KERI rotation, re-verify the *republished* bundle against the **new**
current key, then `create_outbound_session` against the new keys → a fresh `Session`; tear down /
drop the old session (vodozemac zeroizes on drop). This is today's `verified_rotation_rekey`,
re-expressed.

**The audit (ENC-7) scopes exactly here:** KERI resolution, bundle-signature verification, the
Olm-identity-key↔AID binding + hygiene assertion, and the `create_*_session` hand-off. The Olm
ratchet itself rides vodozemac's Least Authority audit.

---

## 6. Persistence — `pickle` (simpler than libsignal's stores)

vodozemac persists via **`pickle()` → an encrypted, versioned blob**, and `from_pickle(blob, key)`.
There is **no store-trait soup** (unlike libsignal's `SessionStore`/`IdentityKeyStore`/…): Murmur
just pickles/unpickles.
- **Session store:** `session.pickle()` → keyed by **(peer AID, device id)** in Murmur's storage;
  unpickle on demand. (The device-id keying is also how delegated-device multi-device maps in.)
- **Account store:** `account.pickle()` for the local long-term keys + unpublished one-time/fallback
  keys.
- **Pickle key:** a local storage-encryption key, derivable from / held in the **Secure Enclave**
  (the app already mints SE keys). Spike item: where the pickle key lives and how it's rotated.

---

## 7. The AAD difference (important — H4 moves, doesn't disappear)

Our hardened `Session::seal` took an AAD (`sender‖recipient‖mailbox`) to defeat relay relocation
(H4). **Olm's `Session::encrypt(plaintext)` takes no AAD.** The relocation defense therefore moves
from "AEAD AAD" to two structural properties:
1. **Per-pair Olm sessions.** A `Session` (and its `session_id()`) is bound to **both identity
   keys**; a ciphertext from one pairwise session cannot be decrypted by a different peer's session.
   Relocation across peers fails at decrypt.
2. **The inner signature** (KEPT) already binds `sender‖recipient‖body`, so content can't be forged
   or re-attributed regardless of routing — the actual content-integrity guarantee (H4 was always
   *defense-in-depth*, per the review's honest correction).
If we want the routing context bound explicitly, it goes **inside the signed plaintext** (the
`InnerEnvelope` — which already carries sender/recipient + signature), not in an AEAD AAD. **Net: H4
is satisfied structurally; ENC-5's probe is reframed from "AAD-mismatch rejected" to "a ciphertext
does not decrypt under a different pairwise session."**

---

## 8. The load-bearing prerequisite — rewrite the probes black-box FIRST

Murmur's proofs **inspect internal ratchet state**, which the homegrown design exposed deliberately.
**vodozemac's `Session` is opaque** (`pickle()` is an encrypted blob, not the root/chain). So the
introspecting probes break and must be rewritten to test the property through **observable
behavior**, with **no state inspection** — done **first, against the existing homegrown impl,
keeping the gate green**, so the gate then survives any backend. Highest-leverage step; clean,
autonomous-safe recurve cycle.

| Claim | Inspects internal state at | Black-box rewrite |
| --- | --- | --- |
| **ENC-2** forward secrecy | `lib.rs:556` `recv_chain.counter()` | seal 0..N, capture msg-0 wire, advance the receiver by decrypting 1..N, prove msg-0 wire now fails — behavior only (Olm `decrypt` rejects the stale message) |
| **ENC-3** post-compromise | `lib.rs:683/695` `*sender_dh.root_state()` | build two sessions across a DH step (the post-step session vs a pre-step "compromised" one), prove the pre-step session cannot open a post-step ciphertext — no root snapshot |
| **ENC-4** metadata hygiene | `lib.rs:891/1014` `send_chain.chain_state()`; `leakcheck.rs:126,86` scans for the literal chain key | prove the captured wire decrypts **only** with the correct session and never equals plaintext; drop the literal chain-state scan (vodozemac never exposes the chain key — which is *itself* the stronger property) |
| **ENC-5** relocation (was H4 AAD) | — | reframe to **per-session binding** (§7): a ciphertext does not decrypt under a different pairwise Olm session |

Each rewrite keeps its adversarial trap RED.

---

## 9. Sequence (milestones) — which steps are recurve loops vs human-led

- **M1 — Spike (human + agent).** `cargo add vodozemac`; pin a version; lock the `olm` API surface;
  prove cross-compile to `aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
  `x86_64-apple-ios` (pure Rust, low risk); decide the pickle-key home (Secure Enclave); rewrite
  **one** probe (ENC-2) as the black-box template. *Human-led, agent-assisted.*
- **M2 — Black-box probes (clean recurve cycle).** Rewrite ENC-2/3/4 + reframe ENC-5 per §7–§8
  against the *homegrown* impl; gate stays green. ✅ autonomous-safe.
- **M3 — Trait seam (clean recurve cycle).** Introduce an internal `Ratchet`/`Session` trait;
  `Endpoint`/relay/probes depend on the interface, not the concrete type. ✅ autonomous-safe.
- **M4 — vodozemac backend, feature-flagged (agent + review).** Implement the trait over
  `olm::Account`/`Session` + the join (§5) + pickle persistence (§6), gated on a `vodozemac` feature;
  **both backends build**.
- **M5 — Parity gate (recurve as safety net).** Run the black-box gate against **both** backends;
  add **ENC-PARITY** (homegrown ⇄ vodozemac behave identically on the claim set). Prove the
  vodozemac-backed engine passes every MSG/ENC claim. *recurve loop + review.*
- **M6 — Cutover (human review).** Default to vodozemac, delete the homegrown ratchet, re-arm
  **ENC-6** truthfully.
- **M7 — External audit (human, ENC-7).** Audit the **join** (§5) — non-negotiable before any real
  user. ENC-7 stays open/review-gated until it passes.
- **M8 — (future) Megolm groups.** Out of scope here; recorded as the group-encryption path.

**Recurve's role:** the gate + the refactors (M2, M3, M5) are exactly what recurve is for —
autonomous-safe, with adversarial traps as acceptance criteria. The library integration, the
cutover, and the audit (M4, M6, M7) are human-led. **Recurve is the safety net, not the
unsupervised author of a crypto swap** — auto-greening our own probes is the exact trap the review
flagged.

---

## 10. Practicalities & dependency footprint

- **Crate:** `vodozemac` (crates.io, Apache-2.0, matrix-org). Pure Rust.
- **Deps:** `x25519-dalek`, `ed25519-dalek`, `curve25519-dalek`, `aes`, `hmac`, `sha2`, `hkdf`,
  `prost`/serialization — high overlap with Murmur's current Cargo.lock; minimal new transitive
  tree. (Confirm exact set in M1.)
- **Cross-compile:** pure Rust → all four Apple targets build with no C toolchain. The `murmur-ffi`
  xcframework build pattern (per-target `cargo build --target …` → combined xcframework) is
  unchanged; only the linked crate differs.
- **FFI:** wrap `olm::Session` in an opaque uniffi newtype exposing only encrypt/decrypt + pickle;
  never expose key bytes. App blast radius stays **zero** until the FFI seam is wired (the app
  currently calls only stubbed FFI).

---

## 11. License & strategic rationale (why vodozemac, not libsignal)

**License (the deciding factor).** vodozemac is **Apache-2.0** — permissive, uniform with the auths
workspace: mix freely, no copyleft, no second-license boundary to police, no App-Store/proprietary
friction. `libsignal-protocol` is **AGPL-3.0** — strong copyleft + a network clause (§13): the
engine, the **relay**, and the app linking it would become AGPL source-available (the relay's source
owed to anyone who connects), it's a one-way contamination you'd have to wall off from the rest of
the Apache platform, and AGPL is a *negative* in acquisition diligence. Both are open source; the
real axis is **permissive vs. copyleft + monorepo consistency**, and Apache wins it.

**The ratchet choice is decoupled from adoption/exit.**
- *Adoption bridge:* using libsignal (the library) is **not** the same as interoperating with Signal
  (the network). Signal's network is its servers + phone-number identity; Murmur's AID root
  precludes joining it. A real Signal bridge is a *separate gateway product* (which Signal fights),
  not a property of the ratchet crate. So libsignal would not bring Signal's users.
- *Exit:* Signal is a donation-funded nonprofit that doesn't acquire companies; and the acquirable
  IP here is the **identity layer (KERI/auths)**, not the ratchet (Signal already has a better one).
  Using their ratchet adds nothing to acquisition value and AGPL would narrow the buyer pool for any
  non-Signal exit.
- *Optionality preserved:* if a Signal bridge is ever wanted, build it as a **separate, optional
  AGPL component** (bridges to Signal are inherently Signal-protocol — AGPL lives naturally there,
  isolated) — keeping the core permissive today.

**Net:** vodozemac costs nothing strategic and saves the AGPL tax, while being an audited, real
Double Ratchet — and throws in Megolm for groups.

---

## 12. Risks & spikes

| # | Risk | Sev | Mitigation |
| --- | --- | --- | --- |
| R1 | Opaque-state probe rewrite (XL) | high | M1 template (ENC-2) first; M2 keeps homegrown green as the reference |
| R2 | KERI↔Olm identity-key binding in the join | high | the audited seam (§5); keep the hygiene assertion; ENC-7 |
| R3 | One-time-key exhaustion → fallback key (weaker first-message FS) | med | replenish one-time keys via the publish path; document the fallback degradation; rotate the fallback |
| R4 | No AEAD AAD in Olm (H4 reframed) | med | per-session binding + inner signature (§7); bind routing into the signed plaintext if needed |
| R5 | Pickle-key management (storage encryption) | med | derive/hold in Secure Enclave; define rotation in M1 |
| R6 | `SessionConfig` version (v1/v2) + API drift | low | pin a vodozemac version in M1; lock the surface |
| R7 | Megolm groups PCS limitation (future) | low | scope the future group claim to "forward-secret group," not per-message PCS |

---

## 13. Success criteria
- The black-box MSG/ENC claims are **green against both backends** (ENC-PARITY), traps still RED.
- `cargo test -p murmur-core` green; iOS cross-compile of the four slices succeeds.
- **ENC-6 re-armed** truthfully ("vodozemac-backed audited Olm Double Ratchet; the KERI join is the
  residual custom seam, audit-gated"); the homegrown ratchet deleted.
- **ENC-7 (external audit of the KERI join) passes** — the release gate for real users.
- One uniform license (Apache-2.0) across the workspace; no AGPL boundary.

---

## 14. Recurve claim sketch (delta)
- **ENC-2/3/4 → rewritten black-box** (behavioral; survive any backend) — M2.
- **ENC-5 → reframed** to per-session binding (Olm has no caller AAD) — M2.
- **ENC-PARITY (new)** — homegrown and vodozemac backends produce identical verdicts across the
  claim set (the migration safety net) — M5.
- **ENC-6 → re-armed** — "vodozemac-backed audited Olm; KERI join residual seam, audit-gated" — M6.
- **ENC-7** — external audit of the join; stays open/review-gated until it passes — M7.
- *(future)* **GRP-1** — Megolm forward-secret group messaging — M8, out of scope here.
