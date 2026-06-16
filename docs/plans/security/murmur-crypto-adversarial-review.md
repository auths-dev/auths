# Murmur Crypto — Adversarial Review Findings & Fixes

**Date:** 2026-06-16
**Scope:** `crates/murmur-core` (+ `murmur-relay`, `murmur-ffi`) — the 14 closed recurve claims
(MSG-1..4, ENC-1..6, WIT-1, RVK-1, APP-1, DEV-1).
**Method:** neurotically-adversarial read-only review — 46 agents, 5 hostile lenses (crypto,
bugs, probe-skeptic, protocol/threat, memory-FFI-supply), per-finding adversarial verification.
**Raised → confirmed:** 39 findings → **17 survived verification** (7 high, 2 medium, 8 low; of
the lows, 4 are *confirmations that the code is correct*, not defects).

---

## TL;DR

**The crypto is REAL, not stubbed.** Every claim was independently verified as a genuine
implementation: a real symmetric ratchet (HMAC-SHA256 chain, distinct message/chain steps, keys
zeroized on advance) **and** a real DH ratchet (fresh ephemeral, HKDF root mix, old root
zeroized); verify-before-surface (AEAD-decrypt, then signature-check against the resolved identity
*before* the body is returned); real pre-rotation (SHA-256 commitment check); real key hygiene
(the Signal identity key is provably distinct from the AID signing key). The green gate was not
faked — 14/14 traps still discriminate.

**But the loop reimplemented the ratchet by hand instead of embedding `libsignal`** — the exact
"don't roll your own crypto" rule from ENC-6 / PRD §3.1 — and homegrown crypto carries exactly the
bug classes the PRD predicted: nonce-reuse via a public API, counter overflow, AAD relocation, no
out-of-order tolerance, and zeroization gaps.

### Root-cause recommendation (do this, not the band-aids)
1. **Replace the homegrown ratchet (`ratchet.rs`, `dh_ratchet.rs`, `session.rs` AEAD) with
   `libsignal`.** It retires HIGH-1, HIGH-3, HIGH-5, HIGH-6, HIGH-7 and LOW-13/15/17 *at the
   source* — nonce management, skipped-message keys (out-of-order), counter handling, and
   zeroization are all things libsignal solved years ago.
2. **Downgrade ENC-6 in the ledger.** It reads "vetted libsignal, used correctly"; it is in fact
   *homegrown crypto tested against reference vectors*. That is an overclaim and must be corrected.
3. **The external audit (ENC-7) is now mandatory, not optional**, for whatever ratchet ships.
4. If — against this advice — the homegrown ratchet is kept short-term, the 7 highs + 2 mediums
   below are all blocking for any real user.

---

## HIGH severity (7)

### H1 / H6 / L17 — Nonce reuse via the public AEAD surface  *(the #1 fix)*
- **Where:** `murmur-core/src/session.rs:38-43, 71-99` (`fresh_nonce`, `Session::seal`,
  `content_key`).
- **Issue:** `Session::seal()` is **public** and takes the 96-bit nonce as a *parameter*. The
  nonce is used both as the HKDF salt for the per-message content key *and* as the
  ChaCha20-Poly1305 nonce. Any caller (or test path, or future regression) that reuses a nonce
  derives the same content key → identical keystream → `C1 ⊕ C2 = P1 ⊕ P2`, breaking
  confidentiality. There is no dedup/sequence check that reuse hasn't happened.
- **Fix:**
  1. Make `Session::seal()` **`pub(crate)`**; expose only `Endpoint::seal_to()` / `Ratchet::seal()`
     publicly — both already call `fresh_nonce()`.
  2. Better: stop accepting the nonce as input at all — derive it from a **per-session monotonic
     counter** (`nonce = LE64(counter) ‖ ...`), which is *structurally* never-reused, and assert
     `counter` strictly increases. This removes the dependency on RNG quality entirely for nonce
     uniqueness.
  3. Best: **libsignal** (the per-message keys + nonces are derived from the ratchet, not passed
     in).

### H2 — `MailboxStore` unbounded growth (relay DoS)
- **Where:** `murmur-core/src/relay.rs:77-119`.
- **Issue:** `queues: HashMap<MailboxId, Vec<OuterEnvelope>>` has no size/quota/eviction. An
  attacker deposits unbounded ciphertext under one mailbox → unbounded relay memory.
- **Fix:** enforce a **per-mailbox byte+count quota** and a **global cap**; reject `deposit`
  past quota (`CoreError::Rejected`/`QuotaExceeded`); add **TTL eviction** of undrained messages;
  cap the per-`drain` response size and paginate.

### H3 / L15 — Ratchet has no out-of-order / gap tolerance
- **Where:** `murmur-core/src/ratchet.rs:194-215` (`Ratchet::open` requires `index == counter`).
- **Issue:** strict in-order open is correct for FS but means a single dropped/reordered message
  **desynchronizes the chain irreversibly** until a DH step. Real networks reorder and drop;
  "in-order delivery" is not a contract a messenger can assume.
- **Fix:** implement **skipped-message-key handling** — on receiving `index > counter`, derive and
  **store the intervening message keys** (bounded, e.g. ≤1000, with zeroization + TTL) so later/
  earlier-arriving messages decrypt; this is the standard Double Ratchet behavior. `libsignal`
  does this for free (primary reason to swap).

### H4 — AAD binding insufficient → relay can relocate messages across mailboxes
- **Where:** `murmur-core/src/session.rs:71-99` (`content_key` + `seal`), `envelope.rs:14-20`.
- **Issue:** the AEAD binds only the **mailbox id** as AAD. An attacker who has the session secret
  (e.g. device-theft scenario, or a single shared bidirectional session) can unseal a ciphertext
  for `mailbox_A`, re-seal it with a fresh nonce under `mailbox_B`, and the recipient's
  `open(mailbox_B)` validates the (new) tag — the message has been **moved to a mailbox it was
  never addressed to.**
- **Fix:** bind the **full routing+identity context** into the AAD — `sender_aid ‖ recipient_aid ‖
  thread/session-id ‖ sequence ‖ mailbox_id` — so a ciphertext cannot validate under a different
  context. Use **pairwise, per-direction sessions** (never one shared bidirectional session).
  Architecturally, the relay must never hold a session secret; libsignal binds the long-term
  identity keys into the session, closing this.

### H5 — Rekey does not zeroize / fully tear down the prior session
- **Where:** `murmur-core/src/rotation.rs:169-194` (`RotationRekeyReceipt`), `session.rs:47-50`
  (`Session` has no `Zeroize`).
- **Issue:** `verified_rotation_rekey()` re-establishes X3DH, but `RotationRekeyReceipt` holds both
  `prior_session` and `rekeyed_session`, and `Session`'s 32-byte secret is **not zeroized on
  drop**. The old root key lingers in memory; a memory snapshot while the receipt is live recovers
  it and decrypts pre-rotation traffic still live on a peer.
- **Fix:** `#[derive(ZeroizeOnDrop)]` on `Session` (and a `Drop` on `RotationRekeyReceipt` that
  zeroizes `prior_session` **immediately** after the rekey completes, not at end-of-scope).

### H7 — `Session` secret not zeroized on drop
- **Where:** `murmur-core/src/session.rs:48` (`Session` derives `Clone`, not `ZeroizeOnDrop`).
- **Issue:** the 32-byte root secret stays in memory after `Session`/`Endpoint` drop;
  use-after-free or heap inspection recovers it. (Note `Identity`'s seed *is* `ZeroizeOnDrop` —
  `Session` was missed.)
- **Fix:** `#[derive(zeroize::ZeroizeOnDrop)]` on `Session`; audit every struct holding key
  material for the same (grep for `[u8; 32]`/secret fields without `ZeroizeOnDrop`).

---

## MEDIUM severity (2)

### M8 — Dedup `seen` fingerprints are never garbage-collected
- **Where:** `murmur-core/src/relay.rs:77-146` (`seen: HashMap<MailboxId, HashSet<[u8;32]>>`).
- **Issue:** `handle()` removes `queues[mbx]` but never the matching `seen[mbx]`; SHA-256
  fingerprints accumulate forever → memory exhaustion (≈3.2 GB for 100M hashes).
- **Fix:** remove the `seen` entry when a mailbox is removed; bound the per-mailbox seen-set with
  a **TTL / sliding window / Bloom filter**; the replay window only needs to cover the delivery
  horizon, not all history.

### M9 — `verify_continuation` accepts a same-key "rotation"
- **Where:** `murmur-core/src/rotation.rs:131-156`.
- **Issue:** it checks `aid` equality + commitment hash but **not** that `current_key !=
  prior_key`. Called standalone (it's `pub`, reachable via `trust::evaluate()`), a "rotation" to
  the same key pre-committed to itself passes. The full `verified_rotation_rekey()` path catches
  it, but the public function isn't safe on its own.
- **Fix:** add the `current.current_key != prior.current_key` check **inside**
  `verify_continuation`, so it's correct regardless of caller path.

---

## LOW severity — actionable (4)

### L13 — Message counter `u64` overflow has no guard
- **Where:** `murmur-core/src/ratchet.rs:152` (`self.counter += 1`).
- **Issue:** wraps silently in release at 2^64 → index collision → FS/replay violation.
  (Practically unreachable in real time, but "wrap is always a bug here.")
- **Fix:** `self.counter = self.counter.checked_add(1).ok_or(CoreError::Rejected)?;` (force a
  re-key / refuse, never wrap). libsignal handles this.

### L14 — `number_free` scan has heuristic false-negatives
- **Where:** `murmur-core/src/number_free.rs:61-110`.
- **Issue:** the digit-run heuristic resets on chars outside `' - . ( ) +`, so `1415_555_0123`
  evades detection. *Low impact:* the number is inside the **encrypted** body — the relay never
  sees it — so the metadata claim holds; only the "no number anywhere" nicety is technically
  dented.
- **Fix:** treat the scan as best-effort UX (don't oversell it), or tighten by stripping all
  non-alphanumerics before the digit-run test; keep it advisory, not a security boundary.

### L16 — X3DH HKDF uses implicit `None` salt
- **Where:** `murmur-core/src/prekey.rs:252` (`Hkdf::<Sha256>::new(None, &ikm)`).
- **Issue:** sound (None → 32 zero bytes per RFC 5869, and `X3DH_ROOT_INFO` domain-separates) but
  implicit.
- **Fix:** pass an **explicit** `Some(&[0u8; 32])` (or a protocol-constant salt) + a comment, for
  reviewer clarity. No behavior change.

### L17 — see H1 (no runtime nonce-reuse detection in the symmetric ratchet) — fixed by H1.

---

## LOW severity — confirmed CORRECT (no action; recorded so we don't re-litigate)

- **L10 — verify-before-surface ordering is correct.** `Endpoint::open()` AEAD-decrypts, parses
  the inner envelope, verifies the sender signature over `sender ‖ recipient ‖ body`, and only
  then returns the body. A non-authenticating message is never surfaced.
- **L11 — domain separation is correct.** Root vs chain-seed (distinct HKDF `info`), message-key
  vs chain-key (`0x01` vs `0x02` HMAC steps) — all properly separated.
- **L12 — nonce-in-the-clear is correct by design** (prepended, standard ChaCha20-Poly1305 wire
  format; per-message content key derived from it).
- **L15 — in-order rejection is sound for FS** (it's the gap-tolerance concern of H3, not a
  separate defect).

---

## Disposition

| ID | Severity | Status | Retired by libsignal swap? |
| --- | --- | --- | --- |
| H1/H6 nonce reuse | high | fix required | ✅ |
| H2 mailbox DoS | high | fix required | ➖ (relay code, not the ratchet) |
| H3 out-of-order | high | fix required | ✅ |
| H4 AAD relocation | high | fix required | ✅ (identity-bound sessions) |
| H5 rekey teardown | high | fix required | ✅ |
| H7 session zeroize | high | fix required | ✅ |
| M8 seen GC | medium | fix required | ➖ (relay code) |
| M9 same-key rotation | medium | fix required | ➖ (KERI layer) |
| L13 counter overflow | low | fix required | ✅ |
| L14 number scan | low | de-scope claim | ➖ |
| L16 explicit salt | low | clarity | ✅ |
| L10–L12, L15 | low | confirmed correct | — |

**Bottom line:** the proof is real, the gate is honest — and the homegrown ratchet has 7 high-sev
bugs the gate could not see. The correct next move is the **libsignal swap** (retires the majority)
plus the relay-side quotas/GC (H2, M8) and the KERI-side same-key check (M9), then the external
audit (ENC-7). Until then this ships to **no real user**.

---

## Resolution (2026-06-16)

All **actionable** findings were fixed in place in `crates/murmur-core` (+ `murmur-relay`), each
with an adversarial regression test in the existing in-file `#[cfg(test)]` style. The `murmur`
SwiftUI app was **not** touched (FFI blast radius is zero — the app calls stubbed FFI functions,
and `murmur-ffi` carries no `Endpoint`/`Session` callers). `cargo test -p murmur-core`: **108
passed** (98 baseline + 10 new); `cargo clippy -p murmur-core -p murmur-relay --all-targets`:
**clean**. Five unsigned commits on `dev-chatApp`:

| Commit | Findings | What changed | Files |
| --- | --- | --- | --- |
| **A** | H1/H6/L17, H7, H5 | `Session::seal` → `pub(crate)` (no public surface can pass a stale nonce; the two in-crate callers draw a fresh OS-entropy nonce); stray `test_reuse.rs` PoC deleted. `#[derive(ZeroizeOnDrop)]` on `Session`. `RotationRekeyReceipt` carries a `was_rekeyed: bool`, never a prior/re-keyed `Session` — both sessions drop+zeroize in `verified_rotation_rekey`'s scope. | `session.rs`, `rotation.rs` |
| **B** | H4 | AEAD AAD binds `sender_aid ‖ recipient_aid ‖ mailbox_id` (was mailbox-only). `Endpoint` now carries the peer AID so the AAD is reconstructed symmetrically on `open`. | `lib.rs`, `leakcheck.rs`, `murmur-relay/src/main.rs` |
| **C** | L13, M9, L16 | Ratchet counter uses `checked_add` (refuse, never wrap). `verify_continuation` rejects a same-key "rotation" inside the public function. X3DH HKDF salt made explicit `Some(&[0u8; 32])` (no behavior change). | `ratchet.rs`, `rotation.rs`, `prekey.rs` |
| **D** | H2, M8 | `MailboxStore` gets per-mailbox message+byte quotas and a global byte cap; `deposit` returns `DepositOutcome::QuotaExceeded` past quota; a drain frees global bytes. The dedup `seen` set is a bounded sliding window (oldest evicted), not cleared on drain. | `relay.rs`, `lib.rs` |
| **E** | ledger/docs | This section + the ENC-6 downgrade + the ENC-7 libsignal-swap note. | `gaps.yaml`, this doc |

### Two corrections to the findings above

- **H4 is narrower than first written — defense-in-depth, not a forgery fix.** Content forgery is
  already prevented by the **inner signature**, which binds `sender ‖ recipient ‖ body` and is
  verified in `Endpoint::open` *before* any body surfaces (confirmed by L10). The AEAD AAD binding
  added in Commit B hardens **relocation** (an attacker holding the session secret cannot move a
  ciphertext to another mailbox or re-attribute it to another sender/recipient pair without the
  tag failing). It is implemented and tested, but it is hardening, not the thing that stops a forged
  message — the signature is.
- **L14 is de-scoped to best-effort UX, not a security boundary.** The phone number lives inside the
  **encrypted** body; the relay never sees it, so the metadata claim holds regardless of the digit-
  scan heuristic. The `number_free` scan is therefore advisory UX ("we didn't spot a number"), not a
  privacy gate, and is documented as such rather than tightened into a guarantee it can't make.

### Deferred (recorded, intentionally not done in this pass)

- **Replace the homegrown ratchet with libsignal** — the root fix (retires H1/H6, H3, H4-class,
  H5, H7, L13/L15/L17 at the source). XL, C-backed, opaque-session — it breaks the transparent-state
  probes, so it is **human-in-loop**, recorded as the ENC-7 precondition.
- **H3 — proper out-of-order tolerance (bounded skipped-message-key cache).** Kept **strict in-order**
  this pass and documented as the contract (`Ratchet::open` requires `index == counter`); a
  half-built skipped-key cache is a foot-gun. Belongs with the libsignal swap.
- **External cryptographic audit (ENC-7)** — mandatory before any real user, whatever ratchet ships.
  ENC-6 has been downgraded in the ledger from "vetted libsignal" to "homegrown, vector-tested,
  highs fixed, gated on the external audit".

### Confirmed-correct, no change (re-recorded so they aren't re-litigated)

L10 (verify-before-surface ordering), L11 (domain separation), L12 (nonce-in-the-clear by design),
L15 (in-order rejection is sound for FS) — all verified correct in the original review and left as-is.
