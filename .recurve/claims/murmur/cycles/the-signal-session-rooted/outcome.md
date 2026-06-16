# Outcome — the-signal-session-rooted (ENC-1)

## Gap closed

**ENC-1 — The Signal session is rooted in a KERI-authenticated prekey bundle; a
wrong-key bundle is rejected.** RED → GREEN, promoted `open → closed`.

## What changed (the real feature, not a probe hack)

Built the KERI→Signal *join* in `murmur-core` and drove it through the real
`murmur-relay` binary. This is the one seam where a KERI identity roots a Signal
session — the MITM the safety-number warning exists to catch is closed at the
*identity* layer (verify the bundle against the AID's current key) instead of by
key-pinning.

- **`prekey.rs` (new)** — the join:
  - `PrekeyBundle` carries a recipient's **distinct** X25519 *Signal identity
    key* + X25519 *signed prekey*, plus a signature by the recipient's **AID
    current (Ed25519) signing key** over (context ‖ AID ‖ identity key ‖ signed
    prekey).
  - `PrekeyBundle::verify_rooted(aid_current_key)` does three fail-closed checks:
    (1) the resolved key derives the claimed AID (reuses `verify_sender`'s
    AID↔key binding); (2) the AID's current key signed *this* bundle — a wrong /
    non-pre-committed key is rejected here; (3) **key hygiene** — the Signal
    identity key is distinct from the AID signing key (no signing↔DH reuse). Only
    on all three does it return a `RootedBundle` **capability**.
  - `x3dh_initiator` / `x3dh_responder` derive the initial session secret (three
    X25519 DH's → HKDF-SHA256). The initiator side takes `&RootedBundle`, so X3DH
    is **type-unreachable** without a prior `verify_rooted` — verify-then-agree is
    enforced by the type, not by convention.
  - `PrekeySecrets` mints the recipient DH key material; `publish` refuses to even
    emit a bundle that reuses the signing key as a DH key.
- **`lib.rs`** — `deliver_rooted`: publish a bundle → resolve the recipient AID →
  verify the bundle → X3DH (both sides agree) → seal under the rooted session →
  store-and-forward → drain → verify+decrypt. Returns a `RootedReceipt`. Re-exports
  the new types.
- **`murmur-relay` `serve`** — now drives both legs and prints one marker line per
  proven property: the existing `delivered-and-authenticated` and the new
  `bundle-verified-against-aid` (good path *and* the adversarial twin — a bundle
  claiming the recipient's AID but signed by Mallory is rejected before any DH).

The crypto is **not** reimplemented: real ChaCha20-Poly1305 AEAD + HKDF (already
in the crate) and `x25519-dalek` (already in the workspace lock; auths-core uses
it) for the DH. The audited libsignal Double Ratchet (forward secrecy,
post-compromise healing) and the external-audit precondition remain named later
work — this cycle owns the *join*, not the ratchet.

## Deliberately deferred (named seams, not stubs that pretend)

- The forward-secret Double Ratchet that takes over per-message (forward secrecy,
  post-compromise healing) — its own later features.
- Witnessed KEL replay with pre-rotation continuity (the directory stands in for
  "resolve the AID → current key").
- The external cryptographic review of the KERI↔Signal join + multi-device
  lifecycle (the review-gated precondition).

## Gate verdict

```
recurve --config .recurve/murmur.toml matrix --gate   → exit 0
  ENC-1                GREEN  closed
  holding 16 · regressions 0 · broken 0 · stale 0 · missing 0
  traps: 3/3 counterexamples still RED
  GATE OK
  sculpt murmur: gate OK (exit 0)
  leakcheck: clean
recurve --config .recurve/murmur.toml coverage --gate → 0 orphan prose gaps
```

- `cargo test -p murmur-core`: 27 passed (was 19; +8 prekey/join tests).
- `cargo clippy -p murmur-core -p murmur-relay --all-targets`: clean, 0 errors,
  no suppressions (X3DH propagates the HKDF length error rather than `expect`).
- The trap (`enc-1.trap/wrong-key-bundle`) turns the probe RED — the probe
  discriminates (GREEN on the good path, RED on the mis-signed counterexample).
- DEV-1 stayed GREEN (its `delivered-and-authenticated` marker still prints);
  zero regressions. The app sculpt tree was not touched.
