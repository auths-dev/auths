# Murmur Encryption — Migrating to `libsignal-protocol`

> Companion to `messaging/murmur.md` (the messenger PRD) and
> `auths/docs/plans/security/murmur-crypto-adversarial-review.md` (the adversarial review).
> This PRD plans replacing Murmur's **homegrown ratchet** with **`libsignal-protocol`** (Signal's
> Rust crate). The per-finding band-aids are already landed (Commits A–E); this is the *root fix*.

---

## 1. Context — why this exists

The adversarial review confirmed Murmur's crypto is **real** (genuine symmetric + DH ratchet,
verify-before-surface, real pre-rotation, key hygiene) but **homegrown, not a vetted library** —
and homegrown crypto carried the exact bug classes the PRD predicted. We hardened it in place (7
highs + 2 mediums fixed, every fix with an adversarial regression test, gate green). But the
review's own root-cause recommendation stands: **don't roll your own ratchet.** Replacing
`session.rs` / `ratchet.rs` / `dh_ratchet.rs` / the X3DH in `prekey.rs` with `libsignal-protocol`
**retires at the source**: **H1/H6** (nonce reuse), **H3** (out-of-order — libsignal's
skipped-message-key cache), **H4** (relocation — libsignal binds identity keys into the session),
**H5/H7** (zeroization — opaque `SessionRecord`), and **L13/L16/L17** (counter/salt/nonce-reuse
detection). It does **not** retire **H2/M8** (relay quotas — already fixed) or **M9** (KERI
same-key check — already fixed); those are Murmur layers, not the ratchet.

**Decision (made):** use **`libsignal-protocol`** — the literal Signal Protocol (X3DH + Double
Ratchet), audited and battle-tested. The considered alternative, **vodozemac** (Matrix's audited
pure-Rust Olm), is Apache-2.0 and lighter to integrate but is *Olm, not Signal Protocol*; we chose
libsignal for the real thing. The trade-offs this forces are §3 (the license) and §6 (the
probes).

---

## 2. Goals / non-goals

**Goals**
- Replace the homegrown ratchet + X3DH with `libsignal-protocol`, behind a stable internal trait.
- Keep every closed claim (MSG-1..4, ENC-1..5, WIT-1, RVK-1, DEV-1) **green** through the swap.
- Re-arm **ENC-6** truthfully ("libsignal-backed", not "homegrown vector-tested").
- Leave the KERI↔Signal **join** as the only custom crypto seam, and route it through ENC-7
  (external audit) before any real user.

**Non-goals**
- Signal *interop* (we use the protocol, not Signal's servers/identifiers — our root is the AID).
- Replacing the KERI identity layer, the relay, or the two-layer envelope (all KEEP).
- Eliminating the external audit — the **join** is still custom; libsignal's prior audits cover
  the ratchet, not our wiring of it to a KERI root.

---

## 3. The critical decision — license (resolve before any code)

**`libsignal-protocol` is AGPL-3.0** (Signal Messenger's repo). Murmur's workspace is Apache-2.0.
AGPL is **network copyleft**: a networked service built on AGPL code can trigger a source-
disclosure obligation. For a messenger + relay this is a first-order product/legal decision, not a
footnote. **Spike S0 (blocking):** confirm the path — (a) accept AGPL for the engine and plan
accordingly, (b) obtain a commercial license/exception from Signal, or (c) reconsider the library
(vodozemac is Apache-2.0). **Do not write integration code until S0 is resolved.**

---

## 4. Scope — REPLACE / KEEP / JOIN

**REPLACE (Signal's job — delete the homegrown impl):**

| Murmur today | file:line | libsignal-protocol equivalent |
| --- | --- | --- |
| `Session` (AEAD + per-msg key) | `session.rs` | internal to `SessionRecord` |
| `Session::seal/open` | `session.rs` | `message_encrypt` / `message_decrypt` |
| `Ratchet` (HMAC chain) | `ratchet.rs` | internal to `SessionRecord` |
| `DhRatchet` (root advance) | `dh_ratchet.rs` | internal to `SessionRecord` |
| X3DH (`derive_root`, `x3dh_initiator/responder`) | `prekey.rs` | `SessionBuilder::process_prekey_bundle` |
| nonce / counter / zeroization | session/ratchet | internal (libsignal: fresh nonces, `checked_add`, `ZeroizeOnDrop`) |

**KEEP (not Signal's job — unchanged):** the KERI identity layer (`kel.rs`, `rotation.rs`,
`delegation.rs`, `corroboration.rs`, `identity.rs`/`Aid`), the relay (`relay.rs`/`MailboxStore`,
now quota-bounded), `number_free.rs`, `leakcheck.rs` (as a *tool*), and the two-layer
`OuterEnvelope`/`InnerEnvelope` (routing vs identity). The **inner signature** (`Endpoint` signs
`sender‖recipient‖body`, verified before surfacing) **stays** — it is what makes a message
authenticated *as an AID*, which libsignal does not provide.

**JOIN (the only custom crypto seam — must be externally audited):** how a KERI-authenticated
prekey bundle becomes a libsignal session.

---

## 5. Architecture — store traits + the join

libsignal is driven through caller-implemented **store traits**; Murmur implements them over its
KERI/relay state:
- `IdentityKeyStore` → the AID's **Signal identity key** (X25519), resolved from KERI key-state
  (distinct from the AID's Ed25519 signing key — the §3.1 hygiene rule, preserved).
- `SessionStore` → the opaque `SessionRecord`, keyed by **(recipient AID, device id)** — this is
  also how multi-device (delegated devices) maps in.
- `PreKeyStore` / `SignedPreKeyStore` → one-time + signed prekeys (recipient side).
- `KyberPreKeyStore` → optional, for PQXDH/Kyber (future, not v1).

**The join, precisely (stays custom, audited):**
1. Resolve recipient AID → current key via the KERI directory (KEEP).
2. **Verify** the published prekey bundle's signature against that key, and assert
   `signal_identity_key ≠ AID signing key` — today's `prekey.rs::verify_rooted` → `RootedBundle`
   capability (KEEP).
3. Construct a libsignal `PreKeyBundle` from the *verified* keys and call
   `SessionBuilder::process_prekey_bundle` (REPLACE the X3DH).
4. On rotation, re-verify the *republished* bundle against the **new** current key, then rebuild
   the session (today's `verified_rotation_rekey` → store a fresh `SessionRecord`).

The audit (ENC-7) scopes exactly here: KERI resolution, bundle-signature verification, identity-key
hygiene, and the `process_prekey_bundle` hand-off — *not* the ratchet (libsignal owns that).

**FFI:** wrap `SessionRecord` in an opaque uniffi newtype exposing only encrypt/decrypt; never
expose key bytes across the FFI (the app only ever calls stubbed FFI today, so blast radius stays
zero until wiring).

---

## 6. The load-bearing prerequisite — rewrite the probes black-box FIRST

Murmur's proofs currently **inspect internal ratchet state**, which the homegrown design exposed on
purpose. libsignal's `SessionRecord` is **opaque** — so these probes break, and must be rewritten
to test the *property through observable behavior*, with **no state inspection**. Do this **first,
against the existing homegrown impl, keeping the gate green** — then the gate survives *any* ratchet
backend. This is the single highest-leverage step and the one that de-risks the whole swap.

| Claim | Inspects internal state at | Black-box rewrite |
| --- | --- | --- |
| **ENC-2** forward secrecy | `lib.rs:556` `recv_chain.counter()` | seal 0..N, capture msg-0 wire, advance receiver by decrypting 1..N, prove msg-0 wire now fails — behavior only |
| **ENC-3** post-compromise | `lib.rs:683/695` `*sender_dh.root_state()` | build two sessions (pre-step "compromised" vs post-DH-step), prove the pre-step session can't open a post-step ciphertext — no root snapshot |
| **ENC-4** metadata hygiene | `lib.rs:891/1014` `send_chain.chain_state()`; `leakcheck.rs:126/86` scans for the literal chain key | prove the captured wire decrypts **only** with the correct session (and never equals plaintext); drop the literal chain-state scan |
| **ENC-5** AAD relocation | — (caller-level AAD) | **no rewrite** — AAD stays Murmur's responsibility above libsignal; `message_encrypt/decrypt` take AAD |

Each rewrite keeps its adversarial trap (the RED counterexample must stay RED).

---

## 7. Sequence (milestones) — which steps are recurve loops vs human-led

- **S0 — License (blocking, human).** Resolve §3 before anything else.
- **M1 — Spike (human + agent).** `cargo add libsignal-protocol`; prove it **cross-compiles** to
  the four Apple slices `MurmurFFI.xcframework` needs (`aarch64-apple-darwin`, `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, `x86_64-apple-ios`) — pure-Rust, low risk; dep overlap is high
  (x25519-dalek/sha2/hmac/hkdf already present). Rewrite **one** probe (ENC-2) as the black-box
  template.
- **M2 — Black-box probes (clean recurve cycle).** Rewrite ENC-2/3/4 per §6 against the *homegrown*
  impl; gate stays green. ✅ autonomous-safe.
- **M3 — Trait seam (clean recurve cycle).** Introduce an internal `Ratchet`/`Session` trait;
  `Endpoint`/relay/probes depend on the interface, not the concrete type. ✅ autonomous-safe.
- **M4 — libsignal backend, feature-flagged (agent + review).** Implement the store traits + the
  join (§5) behind the trait, gated on a `libsignal` feature; **both backends build**.
- **M5 — Parity gate (recurve as the safety net).** Run the black-box gate against **both**
  backends; add an **ENC-PARITY** claim (homegrown ⇄ libsignal behave identically on the claim
  set). Prove libsignal-backed Murmur passes every MSG/ENC claim.
- **M6 — Cutover (human review).** Flip the default to libsignal, delete the homegrown impl, re-arm
  **ENC-6** truthfully ("libsignal-backed Signal Protocol; the KERI join is the residual custom
  seam").
- **M7 — External audit (human, ENC-7).** Audit the **join** (§5) — non-negotiable before any real
  user. ENC-7 stays open/review-gated until it passes.

**Recurve's role:** the *gate* and the *refactor* steps (M2, M3, M5) are exactly what recurve is
for — autonomous-safe, with the adversarial traps as acceptance criteria. The *library decision*,
the *integration*, the *cutover*, and the *audit* (S0, M4, M6, M7) are human-led. **Recurve is the
safety net, not the unsupervised author of a crypto swap** — auto-greening our own probes is the
exact trap the review flagged.

---

## 8. Risks & spikes

| # | Risk | Sev | Mitigation |
| --- | --- | --- | --- |
| S0 | **AGPL-3.0 license** | **critical** | Resolve before code (§3) |
| R1 | Opaque-state probe rewrite (XL) | high | M1 template first; M2 keeps homegrown green as the reference |
| R2 | KERI↔Signal identity-key binding in `IdentityKeyStore` | high | the audited join (§5); keep the hygiene assertion |
| R3 | Deterministic test seeding (libsignal may not accept a fixed root) | med | a test-only `SessionRecord` builder, or accept behavior-only tests |
| R4 | FFI wrapping of opaque `SessionRecord` | med | opaque uniffi newtype, encrypt/decrypt only |
| R5 | Multi-device session keying (AID, device-id) | med | `SessionStore` keyed by the delegated-device id |
| R6 | PQXDH/Kyber | low | optional, future; `KyberPreKeyStore` when wanted |

---

## 9. Success criteria
- The black-box MSG/ENC claims are **green against both backends** (ENC-PARITY), traps still RED.
- `cargo test -p murmur-core` green; iOS cross-compile of the four slices succeeds.
- **ENC-6 re-armed** truthfully (libsignal-backed); the homegrown impl deleted.
- **ENC-7 (external audit of the KERI join) passes** — the release gate for real users.
- No high/medium findings in the audit of the join + store-trait impls.

---

## 10. Recurve claim sketch (delta)
- **ENC-2/3/4 → rewritten black-box** (behavioral; survive any backend) — M2.
- **ENC-5** — unchanged (caller-level AAD).
- **ENC-PARITY (new)** — homegrown and libsignal backends produce identical verdicts across the
  claim set (the migration safety net) — M5.
- **ENC-6 → re-armed** — "libsignal-backed Signal Protocol; KERI join is the residual custom seam,
  audit-gated" — M6.
- **ENC-7** — external audit of the join; stays open/review-gated until it passes — M7.
