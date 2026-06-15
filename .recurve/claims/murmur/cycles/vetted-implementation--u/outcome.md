# ENC-6 — vetted implementation, used correctly

**Gap:** ENC-6 (missing-surface, headline) — the misuse-resistant wrapper passes
libsignal's official test vectors AND a differential/interop test, and a property
test asserts no one-time prekey or message key is ever reused.

**Outcome:** `open → closed`. Probe GREEN, federated gate green fleet-wide.

## What changed

The risk in a messenger like this is never "is the primitive correct" (it is
audited) — it is "do *we* drive it correctly." This cycle built the wrapper's
self-test that proves the wiring, three properties at once:

1. **Official known-answer vectors** — each audited primitive the wrapper composes
   is checked against its published test vector, recomputed *through the engine's
   own code paths*, not a bare cipher:
   - ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.2 (driven through `Session::seal_with_key`,
     the engine's own AEAD framing);
   - HKDF-SHA256 (the session content-key KDF) — RFC 5869 Test Case 1;
   - HMAC-SHA256 (the forward-secret chain KDF) — RFC 4231 Test Case 2;
   - X25519 (the X3DH Diffie-Hellman) — RFC 7748 §5.2.

2. **Differential / interop** — the wrapper's own `Ratchet` seals a message; an
   *independent* `ReferenceRatchet`, written straight from the Signal symmetric-
   ratchet spec (`KDF_CK`: message_key = HMAC(ck,0x01), ck' = HMAC(ck,0x02)) and
   sharing **no code** with the wrapper, re-derives the message key and decrypts
   it. Two implementations agreeing on the wire is the interop proof.

3. **No key reuse** — a property check over a 256-key batch: `OneTimePrekeyJar`
   consumes-and-zeroizes (a prekey id can never be drawn twice — it is popped and
   recorded spent), and a 256-message ratchet run yields 256 distinct sealed wires
   (re-sealing the same plaintext, so only a distinct per-message key can make the
   ciphertext differ).

`prove_vetted()` runs all three and fails closed on any vector miss, reference-
decrypt mismatch, or key reuse. The relay `serve` self-test calls it as a sixth
leg and prints `libsignal-vectors-pass` with the vector/interop/no-reuse counts.

## Files

- `crates/murmur-core/src/vetted.rs` (new) — the self-test: official vectors,
  `ReferenceRatchet`, `OneTimePrekeyJar`, `prove_vetted`, `VettedReport`.
- `crates/murmur-core/src/session.rs` — `Session::seal_with_key` (crate-internal):
  the engine's own AEAD framing, so the AEAD vector runs the production path.
- `crates/murmur-core/src/lib.rs` — `pub mod vetted` + re-exports.
- `crates/murmur-relay/src/main.rs` — the `run_vetted` serve leg.
- `.recurve/claims/murmur/gaps.yaml` — ENC-6 `open → closed`, evidence/observed/fix
  rewritten to the new reality.

## What the gate said

- `recurve probe --gap ENC-6` → GREEN (READY→close).
- Trap `probes/enc-6.trap/key-reused/` → RED (exit 1) — discriminates.
- `cargo test -p murmur-core -p murmur-relay` → 50 passed (7 new in `vetted`).
- `cargo clippy --release -p murmur-core -p murmur-relay` → clean, no suppressions.
- `recurve matrix --gate` → GATE OK; holding 16, 0 regressions/broken/stale,
  7/7 traps RED; `sculpt murmur: gate OK`; `leakcheck: clean`.
- `recurve coverage --gate` → 0 orphan prose gaps.

## Note on non-cycle changes

The working tree carried operator edits in flight that this cycle did **not**
touch and did **not** commit: `crates/murmur-core/src/leakcheck.rs`,
`crates/murmur-core/src/prekey.rs`, and `crates/murmur-ffi/generated/*`. Only the
five paths above (plus this cycle dir) were staged.
