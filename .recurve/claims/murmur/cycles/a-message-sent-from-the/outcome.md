# Outcome — a-message-sent-from-the (DEV-1)

## Gap closed

**DEV-1 — A message sent from the Mac arrives, authenticated, on the iPhone.**
RED → GREEN, promoted `open → closed`.

## What changed (the real feature, not a probe hack)

Built the end-to-end delivery leg in `murmur-core` and drove it through the real
`murmur-relay` binary:

- **`identity.rs` (new)** — `Identity` holds an Ed25519 signing key; the `Aid` is
  *derived from* the public key (`Aid::from_public_key`, SHA-256 digest →
  `did:keri:…`), so the address is bound to the key by construction.
  `verify_sender` rejects a signature that doesn't verify under the key the AID
  resolves to, and rejects a key that doesn't derive the claimed AID. Real
  Ed25519 via `auths-crypto` synchronous primitives — no async runtime.
- **`session.rs` (new)** — real AEAD confidentiality: HKDF-SHA256 derives a
  per-message content key from a shared session secret + a fresh 96-bit nonce;
  ChaCha20-Poly1305 seals the inner envelope with the mailbox id bound in as AAD.
  A tampered ciphertext, a wrong secret, or a re-filed mailbox all fail the tag.
- **`relay.rs`** — `MailboxStore`, a real in-memory store-and-forward queue
  (deposit appends; drain returns-and-empties). It only ever touches the
  `OuterEnvelope` (mailbox id + opaque bytes).
- **`envelope.rs`** — `InnerEnvelope` now carries the sender AID, recipient AID,
  body, and the sender's signature over all three (`signing_bytes`), sealed
  *inside* the outer ciphertext.
- **`lib.rs`** — `Endpoint::seal_to` / `Endpoint::open` / `deliver_once`: the
  whole leg. `open` AEAD-decrypts, resolves the sender AID via a `Directory`,
  and verifies the signature **before** surfacing the body — so a message that
  *arrived* but didn't *authenticate* is rejected, never shown.
- **`murmur-relay` `serve`** — now runs `deliver_once` hermetically (a "Mac"
  endpoint seals → relay stores-and-forwards → a "phone" endpoint drains+opens)
  and prints `delivered-and-authenticated`, exit 0.

The FFI seam (`murmur_core::seal`/`open`) stays honestly `NotBuilt`: the app→engine
session/Secure-Enclave wiring is the shell's own later work, so it fails closed
rather than emitting an unauthenticated or unencrypted envelope. The FFI crate is
unchanged and decoupled from this gate (vendored xcframework).

## Deliberately deferred (named seams, not stubs that pretend)

- Witnessed key-log replay with pre-rotation continuity (the directory stands in).
- X3DH key agreement + the forward-secret Double Ratchet (the session secret is
  established out-of-band today; confidentiality from the relay holds, per-message
  forward secrecy does not yet).
- Delegated-device + revocation chain.

## Gate verdict

```
recurve --config .recurve/murmur.toml matrix --gate   → exit 0
  DEV-1                GREEN  closed
  holding 16 · regressions 0 · broken 0 · stale 0 · missing 0
  traps: 2/2 counterexamples still RED
  GATE OK
  sculpt murmur: gate OK (exit 0)
  leakcheck: clean
```

- `cargo test -p murmur-core`: 19 passed.
- `cargo clippy -p murmur-core -p murmur-relay --all-targets`: clean, no
  suppressions (`fresh_nonce` propagates an error rather than `expect`).
- The trap (`dev-1.trap/arrives-unauthenticated`) turns the probe RED — the probe
  discriminates.
- The live two-device simulator demo remains the operator's dev confirmation; this
  deterministic relay self-test is the gate.
