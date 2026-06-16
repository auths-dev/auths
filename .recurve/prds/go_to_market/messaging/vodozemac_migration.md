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

> **M1 spike result (2026-06-16): pinned `vodozemac v0.10.0`.** API map below is **compiler-verified**
> against that version (a throwaway crate did the real handshake + round-trip + out-of-order + replay).
> Corrections from the original draft are marked **[M1]**. Three load-bearing facts confirmed:
> (a) cross-compiles clean to `aarch64-apple-darwin` / `-ios` / `-ios-sim`, **zero `-sys`/C deps**
> (pure Rust, no toolchain); (b) genuinely-new transitive crates are `aes`+`cbc` (Olm's AES-256-**CBC**,
> not our ChaCha), `prost` (protobuf wire), `rand` — all pure Rust (so §10's "near-zero new tree" is
> *optimistic*: ~a dozen new pure-Rust crates, no C); (c) **the stronger full-MAC mode is feature-gated**
> (see the SessionConfig note).

vodozemac's `olm` module is the 1:1 protocol. The two types that matter:

**`olm::Account`** — your long-term key material + prekeys.
- Identity keys: `curve25519_key()` (the DH identity key) and `ed25519_key()` (the signing key).
- `generate_one_time_keys(n) -> OneTimeKeyGenerationResult`, `one_time_keys() -> HashMap<KeyId, Curve25519PublicKey>`,
  `mark_keys_as_published()` — the one-time prekeys a recipient publishes; consumed once per new inbound session.
- `generate_fallback_key() -> Option<Curve25519PublicKey>`, `fallback_key()` — the reusable fallback
  used when one-time keys are exhausted (degraded first-message FS — §7).
- **[M1]** `create_outbound_session(SessionConfig, their_curve25519_identity, their_one_time_key) -> Result<Session, SessionCreationError>`
  — the initiator handshake (Olm's triple-DH, the X3DH analog). **Fallible** (returns `Result`, not a
  bare `Session`: a non-contributory/low-order key is rejected — `NonContributoryKey`).
- **[M1]** `create_inbound_session(expected_config: SessionConfig, their_curve25519_identity, &PreKeyMessage) -> Result<InboundCreationResult, SessionCreationError>`
  where `InboundCreationResult { session: Session, plaintext: Vec<u8> }`. **Takes `expected_config` as
  the first arg** (a downgrade guard: rejects `MismatchedSessionConfig` if the inbound message's Olm
  version ≠ what we expect) **and asserts `their_identity_key == prekey.identity_key()`** (`MismatchedIdentityKey`)
  — a useful built-in binding the join (§5) leans on.
- `pickle()` / `from_pickle(pickle, pickle_key)` — encrypted serialization for persistence.

**`olm::Session`** — the established ratchet (opaque; owns the Double Ratchet).
- **[M1]** `encrypt(plaintext: impl AsRef<[u8]>) -> Result<OlmMessage, EncryptionError>` — seal (no
  caller nonce, no caller AAD — §7). **Fallible** (returns `Result`, not a bare `OlmMessage`).
- `decrypt(&OlmMessage) -> Result<Vec<u8>, DecryptionError>` — open (handles out-of-order internally).
- `session_id()` — a stable id derived from both identity keys (binds the pair — §7). **[M1] confirmed
  equal on both ends** of an established session.
- `has_received_message()`, `pickle()` / `from_pickle()`.

**[M1] `SessionConfig` — the MAC-strength decision.** `SessionConfig::version_1()` is the **default**
and uses AES-256 + HMAC **truncated to 8 bytes** (64-bit MAC — the historical libolm default).
`SessionConfig::version_2()` uses the **full (untruncated) MAC** but is **gated behind the
`experimental-session-config` cargo feature**. **Murmur ships v2** (a 64-bit MAC is too short for a
greenfield messenger) → enable `vodozemac/experimental-session-config`, and pass `version_2()` to
**both** `create_outbound_session` and the `expected_config` of `create_inbound_session` (the
downgrade guard then rejects any v1 peer). Recorded as risk R9 + an ENC-7 audit item.

**`OlmMessage`** — `PreKey(PreKeyMessage)` (the first message, carries handshake material) or
`Normal(Message)` (subsequent). Serializable to bytes for our `OuterEnvelope.ciphertext`.

**Groups (v2, not in scope here):** `megolm::GroupSession` (outbound) + `megolm::InboundGroupSession`
— forward-secret group messaging. Note: Megolm is a sender-key ratchet → **forward-secret but not
per-message post-compromise-secure** (inherent to group ratchets); design the group claim accordingly.

---

## 5. The KERI↔Olm join (the audited seam — detailed)

This is the only crypto that stays custom and the entire scope of the ENC-7 audit.

**The prekey bundle, in Olm terms.** Murmur's published bundle becomes: the recipient's **Olm
Curve25519 identity key** + a **one-time key** (or the fallback key), with the whole bundle **signed
by the AID's current KERI key** (the existing `prekey.rs::verify_rooted` logic — KEPT).

**Outbound (initiator) flow:**
1. Resolve recipient AID → current KERI key via the directory (KEEP).
2. Verify the bundle's signature against that key; assert the Olm Curve25519 identity key **≠** the
   AID's signing key. The AID key is **P-256** on iOS (Secure-Enclave-held) while Olm uses
   **Curve25519**, so the §3.1 hygiene rule is *structurally* satisfied across different curves, with
   the KERI signature binding the Olm key to the AID — see §6 for the storage/curve layering.
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

## 6. Secure Enclave, curves & key storage

iOS's Secure Enclave only supports **P-256** (NIST EC) keys; it does **not** support the
**Curve25519** keys (Ed25519 / X25519) that Olm — like Signal — is defined over. That is a fact
about the hardware, and it shapes the key layering. The resolution is the one Signal/WhatsApp/Matrix
all use: **the SE protects the identity *root*; the messaging ratchet lives in software.**

**Two keys, two layers (the whole point):**
- **AID / KERI identity key — P-256, in the Secure Enclave.** The root of trust: it signs the KEL,
  rotations, and the messaging prekey bundle, and it can never be extracted. This is auths's mobile
  default (P-256 / SE) — correct and unchanged.
- **Olm identity + one-time + ratchet keys — Curve25519, in software.** Olm's own keys, encrypted at
  rest (below). They **cannot** be SE-backed (curve mismatch), and that is normal — *no mainstream
  messenger SE-holds its ratchet keys*, because (a) the curve isn't supported and (b) a ratchet key
  changes every message, so a static hardware key can't hold an advancing ratchet anyway. Forward
  secrecy + post-compromise security bound the value of any one software-held key, and a lost device
  is clawed back through **KERI revocation** (the lost-laptop story) — so a leaked ratchet key is not
  a stolen *identity*.

**The binding (this IS part of the audited join, §5).** The **P-256 SE key *signs* the Curve25519
Olm prekey bundle** — a P-256 signature over bytes that happen to contain Curve25519 public keys,
which is completely standard (the signing curve is independent of the signed content). Two signature
systems coexist cleanly: the **outer** KERI root signature (P-256, SE) binds the bundle to the AID
(`verify_rooted`); the **inner** Olm signature (Ed25519, software) is protocol housekeeping. Useful
side effect: the §3.1 "messaging key ≠ AID signing key" hygiene rule is **trivially satisfied** —
they are different curves entirely.

**Protecting the software-held Olm keys (defense-in-depth):**
- vodozemac persists via **`pickle()` → an encrypted, versioned blob** + `from_pickle(blob, key)` —
  **no store-trait soup** (unlike libsignal's `SessionStore`/`IdentityKeyStore`/…). Murmur pickles
  the `Session` keyed by **(peer AID, device id)** (also how delegated-device multi-device maps in)
  and the `Account` for the local long-term + unpublished one-time/fallback keys.
- The **pickle key** lives in the **Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`**,
  which is itself **SE-wrapped** — so the Olm keys are encrypted at rest under an SE-backed key, even
  though they are not raw SE keys. Spike (M1): where the pickle key lives, how it rotates, and the
  accessibility class.

**What you do *not* get (and don't need):** the messaging ratchet key itself in the SE. That is
impossible with *any* Double Ratchet (Signal included) and unnecessary given FS/PCS + KERI
revocation. If a future requirement ever demanded a hardware-held *messaging* key, the only path is a
different protocol family (e.g. an MLS ciphersuite with a P-256 option) — explicitly out of scope
(we chose the Signal-family Double Ratchet).

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
| **ENC-2** forward secrecy | `lib.rs:556` `recv_chain.counter()` | **[M1-corrected]** the original "decrypt 1..N then prove msg-0 fails" is **wrong for Olm** — its bounded skipped-message-key cache means msg-0 *still* decrypts out of order (spike-confirmed). The correct behavioral FS proxy: **a consumed message's key is destroyed** — decrypt msg-0 once (ok), then a **replay of msg-0 is `Err`** (spike-confirmed), and a message older than the skipped-key window is unrecoverable. No state inspection |
| **ENC-3** post-compromise | `lib.rs:683/695` `*sender_dh.root_state()` | build two sessions across a DH step (the post-step session vs a pre-step "compromised" one), prove the pre-step session cannot open a post-step ciphertext — no root snapshot |
| **ENC-4** metadata hygiene | `lib.rs:891/1014` `send_chain.chain_state()`; `leakcheck.rs:126,86` scans for the literal chain key | prove the captured wire decrypts **only** with the correct session and never equals plaintext; drop the literal chain-state scan (vodozemac never exposes the chain key — which is *itself* the stronger property) |
| **ENC-5** relocation (was H4 AAD) | — | reframe to **per-session binding** (§7): a ciphertext does not decrypt under a different pairwise Olm session |

Each rewrite keeps its adversarial trap RED.

---

## 9. Execution model, trust boundary & sequencing (the build plan)

**What shape of work this is.** A migration is **not** a normal recurve burndown. A burndown turns a
**RED** claim **GREEN** by building a feature — an autonomous build loop is the right tool for that.
This is the opposite: every claim is already **GREEN**, and the job is to **swap the implementation
underneath while keeping every claim green** — a *refactor + parity* problem. recurve's **gate** (the
closed claims + their adversarial traps, used as acceptance criteria) is exactly right for it;
recurve's autonomous **build loop** is the wrong shape — there is no RED claim to chase, and pointing
one at the crypto integration would let it author *and* green its own crypto, the precise trap the
adversarial review caught.

**The hard rule (stated once).** *recurve is the regression **gate** for this migration — never the
unsupervised author-and-greener of the crypto integration.* A green gate after a crypto swap is
**necessary, not sufficient**; trust comes from layering **gate + supervised integration +
adversarial review + external audit**, with the authoring side and the verifying side deliberately
kept separate.

**Who drives each milestone (the trust boundary):**

| Milestone | Driver | Why |
| --- | --- | --- |
| **M1** spike | human + agent | environment / version-pin / API-surface decisions |
| **M2** black-box probes | **recurve cycle — autonomous-safe** | refactors the *tests*; gated on keeping today's claims green; authors no new crypto |
| **M3** trait seam | **recurve cycle — autonomous-safe** | refactor behind a stable interface; same keep-green gate |
| **M4** vodozemac backend + the KERI↔Olm join | **supervised + adversarial review** | *new crypto integration* — must NOT be auto-greened; built in the foreground, then the red-team fleet must pass before we trust it |
| **M5** parity gate | **recurve as the safety net** | both backends pass every claim; traps stay RED (ENC-PARITY) |
| **M6** cutover | **human review** | delete the homegrown ratchet, re-arm ENC-6 honestly |
| **M7** external audit | **external human** | audits the join (§5); the release gate for real users |

**M4 trust gate (explicit precondition, alongside ENC-7).** Before the vodozemac backend is trusted,
the neurotically-adversarial red-team fleet — the same "green is guilty until proven honest" review
that found the 7 highs (`auths/docs/prompts/red_team.md`) — must run **against the integration**,
aimed squarely at: did forward-secrecy / post-compromise security survive the swap, is the KERI↔Olm
join (§5) sound, was the vodozemac API misused. A green parity gate (M5) does **not** discharge this;
the adversarial pass is what turns "the gate is green" into "the integration is trustworthy."

**Autonomous-safe entry points:** **M2** and **M3** can start unsupervised today — they keep the gate
green, touch no new crypto, and de-risk the eventual vodozemac drop-in. Everything from **M4** on is
human-in-the-loop.

**The milestone detail:**

- **M1 — Spike (human + agent).** `cargo add vodozemac`; pin a version; lock the `olm` API surface;
  prove cross-compile to `aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
  `x86_64-apple-ios` (pure Rust, low risk); decide the pickle-key home (Secure Enclave); rewrite
  **one** probe (ENC-2) as the black-box template. *Human-led, agent-assisted.*
- **M2 — Black-box probes (clean recurve cycle).** Rewrite ENC-2/3/4 + reframe ENC-5 per §7–§8
  against the *homegrown* impl; gate stays green. ✅ autonomous-safe.
- **M3 — Trait seam (clean recurve cycle).** Introduce an internal `Ratchet`/`Session` trait;
  `Endpoint`/relay/probes depend on the interface, not the concrete type. ✅ autonomous-safe.
- **M4 — vodozemac backend, feature-flagged (supervised + adversarial review).** Implement the trait
  over `olm::Account`/`Session` + the join (§5) + pickle persistence (§6), gated on a `vodozemac`
  feature; **both backends build**. Then the **M4 trust gate** above (red-team fleet on the
  integration) must pass before cutover — not auto-greened.
- **M5 — Parity gate (recurve as safety net).** Run the black-box gate against **both** backends;
  add **ENC-PARITY** (homegrown ⇄ vodozemac behave identically on the claim set). Prove the
  vodozemac-backed engine passes every MSG/ENC claim. *recurve loop + review.*
- **M6 — Cutover (human review).** Default to vodozemac, delete the homegrown ratchet, re-arm
  **ENC-6** truthfully.
- **M7 — External audit (human, ENC-7).** Audit the **join** (§5) — non-negotiable before any real
  user. ENC-7 stays open/review-gated until it passes.
- **M8 — (future) Megolm groups.** Out of scope here; recorded as the group-encryption path.

*(Recurve's role is the trust boundary stated at the top of this section: the gate + the refactors
M2/M3/M5 are autonomous-safe; the integration, cutover, and audit M4/M6/M7 are human-led.)*

### 9.1 Status — living ledger (update + commit per milestone)

> The durable record of *where we are*. Post-compaction, recover the **plan** from §9 and the **place**
> from here + the recurve `gaps.yaml` claim state + per-milestone commits. Never leave progress in chat.

| Milestone | State | Notes / evidence |
| --- | --- | --- |
| **M1** spike | ✅ done | pinned `vodozemac v0.10.0`; 3 Apple slices cross-compile (pure Rust, no C); §4 API corrected (3 fixes); §8 ENC-2 corrected; v1/v2 MAC finding → R9. Evidence: spike crate /tmp/vodo-spike, 2/2 tests green |
| **M2** black-box probes | 🟢 achieved (new backend) | the black-box *properties* (FS, PCS, relocation, tamper, downgrade) are proven directly against the Olm backend with **no internal-state inspection** (`olm_backend.rs` tests). The homegrown relay-serve proofs are left **as the reference** (still introspect; not refactored — unnecessary once the backend-agnostic property tests exist). Default gate stays GREEN, 14/14 traps RED |
| **M3** trait seam | ✅ done | `channel.rs` `SecureChannel` (encrypt/decrypt); in-tree `RatchetChannel` + `OlmChannel` both implement it. Commit `173f3161` |
| **M4** Olm backend + join | ✅ done, red-team passed | `olm_backend.rs` (feature `olm`): OlmPrekeyBundle/verify_rooted (join), OlmIdentity, OlmChannel; v2 full-MAC pinned; fallback key; encrypted pickle. **M4 trust gate run**: 4 adversarial specialists (claims/crypto/join/supply-chain) — join sound (no forgery); fixes applied (R9/R10 + JN-3 fallback + CA-3/4/6 test strengthening). 121 tests, clippy clean. Commits `173f3161`, `38533a5f` |
| **M5** parity gate | 🟡 proven at test level | the Olm backend satisfies the same properties the homegrown probes assert (FS/PCS/join/tamper/relocation/downgrade — 11 olm tests). **Remaining for a gate-level ENC-PARITY:** wire the relay-serve self-test to run dual-backend (build `murmur-relay --features olm` + an `enc-parity` probe). Recorded; not auto-done to avoid risking the green gate |
| **M6** cutover | ⬜ held (human) | **intentionally not auto-done.** Flipping the default to Olm + re-arming ENC-6 as "audited" is only honest once the *gate* exercises Olm (M5 gate-wiring) + the FFI/relay use it; doing it before then would be a false green. Human-gated default change |
| **M7** external audit | ⬜ held (external) | audits the join (§5) + reconciles audit Issues I/J + R10–R12; release gate |
| **M8** Megolm groups | ⬜ future | out of scope here |

*Legend: ⬜ not started · 🟡 in progress · ✅ done · ⛔ parked/blocked · "held" = intentionally human-gated.*

---

## 10. Practicalities & dependency footprint

- **Crate:** `vodozemac` (crates.io, Apache-2.0, matrix-org). Pure Rust.
- **Deps [M1-measured, v0.10.0]:** **already in murmur-core** — `x25519-dalek`, `sha2`, `hkdf`,
  `hmac`, `zeroize`, `chacha20poly1305`, `getrandom`, `serde`/`serde_json`. **Genuinely new, all pure
  Rust** — `aes`+`cbc`+`block-padding`+`cipher` (Olm seals with **AES-256-CBC + HMAC**, not our
  ChaCha20-Poly1305), `prost`+`prost-derive` (protobuf message wire), `rand`+`rand_chacha`+`rand_core`,
  `curve25519-dalek` + `ed25519-dalek` (likely already transitive via the workspace). Honest read:
  **~a dozen new pure-Rust crates**, not "near-zero" — but **no C/`-sys`/`openssl`/`cc`** anywhere.
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
| R8 | Secure Enclave is P-256-only; Olm is Curve25519 | low | **expected, not a blocker** (§6): the SE holds the P-256 AID root and *signs* the Olm bundle; Olm keys are software, pickle-encrypted under a Keychain/SE-wrapped key; FS/PCS + KERI revocation bound the risk — same posture as Signal/WhatsApp/Matrix |
| R9 | **[M1]** Olm default (v1) truncates the MAC to **8 bytes** — this is **Least-Authority audit Issue J** (unresolved upstream: "64-bit MAC weakens authentication… home servers can perform such attacks"; in Murmur the **untrusted relay** is the analog) | med→**addressed** | ship `SessionConfig::version_2()` (full untruncated MAC) + enable `experimental-session-config`; pass v2 as the inbound `expected_config` so the downgrade guard rejects any v1 peer; pin `=0.10.0`; `session_config_is_v2_full_mac` test prevents silent regression. **v2 is the direct remediation of audit Issue J.** |
| R10 | **[red-team CR-1]** Encrypted pickle has no anti-rollback: a stale-but-valid at-rest blob restores and resurrects consumed message keys → forward secrecy defeated on the *persistence* path | med | documented contract on `to_encrypted_pickle`/`from_encrypted_pickle`: storage MUST be rollback-protected (monotonically versioned Keychain item); ENC-7 reviews the storage binding |
| R11 | **[audit Issue I, unresolved]** vodozemac keeps cleartext keys (identity/one-time/ratchet/MAC) in process memory, exposed to swap/side-channel extraction | med | industry-standard for any software ratchet (Signal/WhatsApp/Matrix); bounded by FS/PCS + KERI revocation; encrypted at rest (pickle, R10); on iOS app memory is not swapped to disk and the SE holds the AID root; ENC-7 records it as accepted |
| R12 | **[audit Suggestion 8, unresolved]** Olm caches at most **40** skipped message keys; an **untrusted relay can reorder/delay >40 messages** to force decryption failures (targeted message-loss DoS) — sharper for Murmur than Matrix because our transport is adversarial store-and-forward | med | relay preserves order best-effort + clients detect gaps; accept the 40-key bound (Matrix's reasoning: config increases misuse) but document it; ENC-7 item. (Note: audit **Issue G**, resolved upstream — an *undecryptable* prekey can no longer burn a one-time key — already shrinks the related OTK-exhaustion surface) |

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

---

## 15. Status & handoff (2026-06-16)

**Engine-side: complete and verified.** The audited Olm backend + KERI↔Olm join exists, is red-teamed,
and is hardened against every code-addressable finding:

- `crates/murmur-core/src/{channel.rs, olm_backend.rs}` — `SecureChannel` seam; `OlmIdentity` /
  `OlmChannel` / `OlmPrekeyBundle::verify_rooted` (the join); v2 full-MAC pinned (`=0.10.0`); signed
  fallback key; distinct inbound errors; encrypted + **generation-bound (anti-rollback)** pickle.
- **123 tests** pass under `--features olm` (FS, PCS, join-binding, downgrade-reject, tamper-reject,
  relocation-reject, OTK single-use + fallback, out-of-order, versioned-pickle rollback/tamper).
  clippy clean. The **default federated gate stays GREEN** (olm is cfg-gated off; 14/14 traps RED).
- The Least-Authority vodozemac audit is reconciled (Issue J ⇒ our v2 decision; Issues I/G + Suggestion
  8 ⇒ R11/R12 and the JN-3 disposition) — see `docs/plans/security/red_team_2026-06-16.md`.

**What remains (deliberately, not blockers to the engine):**
- **M5 gate-level parity** — wire the relay-serve self-test to run dual-backend so the *gate* (not just
  unit tests) exercises Olm. Recorded; held off to keep the green gate safe.
- **M6 cutover** — flip the default to Olm + re-arm ENC-6; human-gated (only honest once M5 lands).
- **M7 external audit** — the join + R10–R12 + Issues I/J; the release gate for real users.

**Next deliverable — the app.** Making Murmur *a fully working app* (every surface wired to this engine
through the FFI, the build passing `--features olm`, a real relay transport) is a separate, larger body
of work tracked in **`messaging/murmur_vodozemac_integration.md`** (the integration plan).
