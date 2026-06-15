# Cycle outcome — MSG-4 (a delegated device sends as the root; revoking it stops it)

## Gap

MSG-4 (murmur · missing-surface · headline) — *A delegated device (the Mac) sends
authenticated as the same root identity; revoking it stops the next message.*

Baseline: RED — `ours=feature-absent expected=device-as-root+revoked-rejected`. The
sender-AID resolve for a delegated device (resolve the device to its root, then claw
it back on revocation) was unbuilt.

## What changed (the real feature)

New module `crates/murmur-core/src/delegation.rs` models the delegated-device chain
as a real signature-checked authorization, not a flag:

- `DelegatedDevice` — its own signing key + the root AID it sends as (the Mac under
  the iPhone's root).
- `DelegationAnchor::{issue,verify}` — the **root's** signature over
  `(root AID ‖ device AID ‖ device key)`. The iPhone anchoring the Mac's delegated
  inception (PRD §6.2). A contact admits a device only on this root signature; a
  forged anchor is rejected at admission against the root key.
- `DeviceRevocation::{issue,verify}` — the **root's** signature clawing a device
  back (PRD §6.5). A relay cannot fabricate or suppress one without the root key.
- `DelegationState` — the witness-corroborated KEL-replay stand-in: the root key,
  the admitted anchors, the revocations. `resolve_device_to_root()` resolves a
  device to the SAME root AID iff it is anchored, its key matches the anchored key,
  and it is not revoked.

`crates/murmur-core/src/lib.rs` — `prove_delegated_device()` drives the whole leg
hermetically through the relay's `MailboxStore`: the root anchors the Mac; the Mac
seals a message that is stored-and-forwarded; the contact opens it (authenticating
the Mac's own signature) and resolves the Mac to the root (`device = Mac,
identity = root`); the root revokes the Mac; the Mac's NEXT message — still
decrypting, still validly device-signed — is rejected on resolve (clawback from the
chain), never surfaced. A revoked device still accepted as the root is an error.

`crates/murmur-relay/src/main.rs` — new `run_delegated_device` self-test leg
(now 10 legs) prints the `device-as-root + revoked-rejected` marker line the probe
greps for; any leg breaking fails the whole self-test closed.

Tests: 8 new (6 module unit tests for anchor/revoke/resolve including forged-anchor,
forged-revocation, swapped-key, and unanchored rejections; 2 lib-level end-to-end +
trap-shape tests). `cargo test -p murmur-core` 79 passed. `cargo clippy` clean (no
suppressions — argument count kept at 7 by folding the two bodies into `[&str; 2]`).

## The honest boundary

The clawback here is the chain event; the *stale-served window* (a contact who
re-resolves from a relay cache rather than witness-corroborated state still has a
window, PRD §6.5) is carried by RVK-1, not this claim — noted in the ledger evidence
so the two stay honest and separate.

## Verdict (the only ground truth)

- `recurve --config .recurve/murmur.toml probe --gap MSG-4` — GREEN.
- Trap `probes/msg-4.trap/revoked-device-accepted/` — turns the probe RED (exit 1):
  the probe discriminates.
- `recurve --config .recurve/murmur.toml matrix --gate` — GATE OK; `sculpt murmur:
  gate OK`; leakcheck clean; holding 16 · ready_to_close 0 · regressions 0 ·
  broken 0 · stale 0 · missing 0 · traps 11/11 still RED.
- `recurve --config .recurve/murmur.toml coverage --gate` — 0 orphans.

Ledger: MSG-4 `open → closed`. Red open gaps 6 → 5 (ENC-3, ENC-7*, RVK-1, UI-TRUST*,
WIT-1 remain; * = review-gated).
