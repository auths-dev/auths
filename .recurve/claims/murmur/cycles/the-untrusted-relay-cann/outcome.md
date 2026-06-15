# Outcome: the-untrusted-relay-cann (ENC-5)

> One cycle, finished and proven. ENC-5 RED → GREEN → closed; federated gate green.

## What changed

The untrusted-relay boundary now closes tamper, replay, and link — the relay is
dumb AND safe (PRD §10, the untrusted-relay claim).

- **`crates/murmur-core/src/relay.rs`** — `MailboxStore` gained a dedup guard.
  `deposit(&OuterEnvelope) -> DepositOutcome` fingerprints the *opaque ciphertext*
  with SHA-256 (per mailbox, never reading inside the bytes) and drops a
  byte-identical replay (`DepositOutcome::DedupedReplay`) instead of forwarding it
  a second time. The fingerprint set is keyed by mailbox so it never correlates
  traffic across two pairwise mailboxes, and it outlives a drain so a capture
  replayed *after* delivery is still dropped. `handle`'s `Deposit` now routes
  through `deposit`, so the dumb relay never forwards a replay. Five unit tests
  cover queue/dedup/post-drain-replay/bit-flip-not-a-dup/per-mailbox-scoping.
- **`crates/murmur-core/src/lib.rs`** — `hold_relay_boundary(...) ->
  RelayBoundaryReceipt` drives all three properties end-to-end over a real sealed
  envelope: (a) a bit-flipped ciphertext is opened by the recipient and MUST fail
  AEAD with the same uniform `Rejected` error a wrong key produces (no oracle);
  (b) the original capture is re-deposited and MUST be deduped so exactly one copy
  is drained and authenticates as the sender; (c) the captured envelope is scanned
  routing-only (body, sender address, session key each absent). Any property that
  fails returns an error — never a silent pass. Re-exports `DepositOutcome`.
- **`crates/murmur-relay/src/main.rs`** — a fifth `serve` self-test leg
  (`run_relay_boundary`) runs the guard and prints the markers the probe greps for:
  `aead-rejected` + `replay-deduped`, plus the mailbox the envelope routed on.

No loop vocabulary in product code — claims are referenced by name ("the
untrusted-relay claim"), never by gap id; `leakcheck` clean over both trees.

## What the gate said

- `recurve --config .recurve/murmur.toml probe --gap ENC-5` — **GREEN**
  ("a bit-flipped ciphertext failed AEAD and was rejected; a replay was deduped;
  the envelope carried only a pairwise mailbox id").
- Trap discriminates: `TRAP_FIXTURE=probes/enc-5.trap/tamper-accepted` turns the
  probe **RED** (exit 1) — the captured "tamper-accepted" run is caught.
- `cargo test -p murmur-core -p murmur-relay` — 43 passed, 0 failed.
- `cargo clippy --release -p murmur-core -p murmur-relay` — clean.
- `recurve --config .recurve/murmur.toml matrix --gate` — **GATE OK**:
  holding 16 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0;
  traps 6/6 still RED; `sculpt murmur: gate OK (exit 0)`; `leakcheck: clean`.
- `recurve --config .recurve/murmur.toml coverage --gate` — clean (no prose drift;
  the murmur suite carries no GAPS.md, the ledger is canonical).

## Ledger delta

ENC-5: `open → closed`. `observed` rewritten to the GREEN reality; `evidence` and
`smallest_fix` updated to the feature note. Trap count 5/5 → 6/6 (the ENC-5
counterexample is now an active guard).
