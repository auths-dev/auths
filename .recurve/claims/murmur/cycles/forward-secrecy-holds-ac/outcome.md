# Outcome — forward-secrecy-holds-ac (ENC-2)

## Gap closed

**ENC-2 — Forward secrecy holds across our wiring: a captured ciphertext cannot
be decrypted from a later, compromised session state; used message keys are
zeroized.** RED → GREEN, promoted `open → closed`.

## What changed (the real feature, not a probe hack)

Built the **forward-secret symmetric ratchet** in `murmur-core` and drove it
through the real `murmur-relay` binary. X3DH (ENC-1) agrees the *initial* root
secret; this cycle owns the part that gives every message its own key and
forward secrecy — the symmetric-key (sending/receiving) chain of the Double
Ratchet.

- **`ratchet.rs` (new)** — the chain:
  - `Ratchet` holds one 32-byte chain key + a message counter, seeded from the
    X3DH root `Session` via a domain-separated HMAC bind (`from_session`).
  - Each message runs the Double Ratchet's symmetric-key step over HMAC-SHA256
    (the same construction Signal's `kdf_ck` uses): `message_key = HMAC(chain_key,
    0x01)`, `chain_key' = HMAC(chain_key, 0x02)`, then **zeroizes the spent
    message key** (a `Drop` impl) and **zeroizes the prior chain key** on every
    advance (`replace_chain_key`), incrementing the counter.
  - Because the chain KDF is one-way, a state holding `chain_key_n` cannot
    reproduce `chain_key_{n-k}` and therefore cannot derive any earlier message
    key — forward secrecy is a property of the chain alone, no DH step.
  - `seal` / `open` carry the message index `counter(8) ‖ Session::seal output` so
    the receiver derives the matching key in lockstep without ever transmitting a
    key; an out-of-order / replayed index, a tamper, or a wrong key all fail
    closed (`CoreError::Rejected`) — the relay gets no decryption oracle.
- **`session.rs`** — `secret_bytes()` (crate-internal) so the ratchet can seed its
  chain from the X3DH root; the bytes never cross the public API or the FFI.
- **`lib.rs`** — `deliver_forward_secret` + `ForwardSecrecyReceipt`: seal N
  authenticated messages over a ratcheted session → store-and-forward → **capture
  the first ciphertext off the relay** → drain + open in order (advancing the
  receiving chain) → replay the captured early ciphertext against the *advanced
  (compromised)* state — which **must** fail. A later state that *did* decrypt the
  early message is returned as an error (the RED the trap records), never a silent
  pass.
- **`murmur-relay` `serve`** — now drives a third leg and prints
  `forward-secrecy-held` (a captured ciphertext at index 0 could not be decrypted
  from the compromised state at index 4).

The crypto is **not** reimplemented: HMAC-SHA256 over the audited `hmac`/`sha2`
crates and `zeroize` — all already in the workspace lock, pinned through the
workspace. No new transitive tree.

## Deliberately deferred (named seams, not stubs that pretend)

- The **asymmetric (DH) ratchet step** that injects fresh entropy on a reply to
  give *post-compromise healing* (the post-compromise-healing claim) — its own
  later feature; forward secrecy is provable from the chain alone.
- Embedding **libsignal's** audited Double Ratchet behind a misuse-resistant
  wrapper, and skipped-message-key caching for out-of-order delivery (the thin
  slice is in-order).
- The external cryptographic review of the KERI↔Signal join + multi-device
  lifecycle (the review-gated precondition).

## Gate verdict

```
recurve --config .recurve/murmur.toml matrix --gate   → exit 0
  ENC-2                GREEN  closed
  holding 16 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0
  traps: 4/4 counterexamples still RED
  GATE OK
  sculpt murmur: gate OK (exit 0)
  leakcheck: clean
recurve --config .recurve/murmur.toml coverage --gate → 0 orphan prose gaps
```

- `cargo test --release -p murmur-core`: 33 passed (was 27; +6 ratchet tests:
  in-order round-trip, distinct per-message keys, the counter, forward secrecy
  (later state cannot open an earlier ciphertext), replay-against-advanced-chain
  rejection, tamper rejection).
- `cargo clippy --release -p murmur-core -p murmur-relay --all-targets`: clean, 0
  warnings, no suppressions (the impossible HMAC keying / HKDF length errors are
  propagated, never `expect`ed).
- The trap (`enc-2.trap/late-state-decrypts-old`) turns the probe RED — the probe
  discriminates (GREEN on the good path, RED on the captured counterexample where
  a later state decrypted an earlier ciphertext).
- ENC-1 and DEV-1 stayed GREEN (their `bundle-verified-against-aid` and
  `delivered-and-authenticated` markers still print); zero regressions. The app
  sculpt tree was not touched.
```
