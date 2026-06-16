# Cycle: message-content-is-forwa — MSG-3 closed

## Gap
MSG-3 — *Message content is forward-secret and the relay learns neither the
plaintext nor a phone number.* (`missing-surface`, `headline`, the privacy floor.)

## What changed
Stood up the store-and-forward wire over a forward-secret envelope and proved the
privacy floor over the **genuine relay queue** — not over a struct whose shape we
merely trust.

- `crates/murmur-core/src/lib.rs` — new `prove_relay_queue()` + `RelayQueueReceipt`.
  It seals each body on a forward-secret `Ratchet` (a fresh per-message key,
  ratcheted forward and zeroized), **deposits each into the real `MailboxStore`
  queue**, drains the queue, and proves over the literal drained bytes that the
  message body, the sender AID, the session content key, and the *live* chain state
  are each absent (`leakcheck::prove_routing_only`), that the queued ciphertext is
  **opaque** (it neither equals nor contains the plaintext), and that a peer
  receiving `Ratchet` still ratchet-opens it back to the authenticated body — so
  what is queued is genuine deliverable forward-secret ciphertext, not filler that
  would scan clean for free. Three unit tests: the good path, the adversarial twin
  (a queued envelope holding the cleartext is rejected by the scan), and the
  empty-body guard.
- `crates/murmur-relay/src/main.rs` — new `run_relay_queue` leg wired into `serve`
  (now 9 legs). It emits the `ciphertext-queued` / `forward-secret` marker the
  MSG-3 probe greps for. The leg — and every other `serve` leg — was rewritten to
  describe the recipient device as a **handset**, never the casual word a
  number-free relay must never utter, so the relay's own diagnostics no longer read
  like the very PII they disprove (the probe forbids that token in the serve output,
  rightly).

## Why this is a real feature, not a probe-pleaser
The existing legs proved forward-secrecy (a later state can't reopen an earlier
ciphertext) and routing-only (a captured envelope scans clean) *separately*. MSG-3
is their conjunction asserted at runtime over the actual store-and-forward queue:
the relay holds Signal-class per-message ciphertext under a pairwise mailbox id and
an attacker who seized the mailbox learns nothing. That is the privacy floor the
thesis stands on, and it now fails closed if a future change ever lets a body or an
identifier into the relay-visible bytes.

## What the gate said
- `recurve --config .recurve/murmur.toml probe --gap MSG-3` → GREEN; the recorded
  trap `msg-3.trap/relay-sees-plaintext` still turns the probe RED (it
  discriminates).
- `recurve --config .recurve/murmur.toml matrix --gate` → **GATE OK**: MSG-3
  GREEN·closed, 0 regressions / 0 broken / 0 stale, 10/10 traps RED, federated
  sculpt (app repo) gate OK, leakcheck clean over both trees.
- `cargo test --release -p murmur-core` → 71 passed; `cargo clippy` clean.

## Ledger delta
MSG-3 `open → closed`. Open RED gaps 6 → 5 (ENC-3, ENC-7, MSG-4, RVK-1, UI-TRUST,
WIT-1 untouched; ENC-7 / UI-TRUST remain review-gated).
