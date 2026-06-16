# Cycle: a-forked-kel-is-rejected — WIT-1 closed

## Gap
WIT-1 (missing-surface, headline) — *A forked KEL is rejected and a
relay-suppressed / stale key-state is caught by the witness threshold — the
continuity story's correctness root.*

The verified-continuation badge (PRD §2) is only trustworthy if the key-state it
replays is the **one true witnessed log**. Two relay-served corruptions could
make it lie: a **forked KEL** (two different rotations at the same sequence — a
relay serving two contradictory branches) resolved last-writer-wins, and a
**relay-suppressed / stale key-state** (receipts withheld below the witness
threshold) accepted as current. The replay had neither check.

## What changed (target tree: ../auths)

- **`crates/murmur-core/src/kel.rs` (new).** A served witnessed key-event-log:
  `Kel` = an ordered run of signed `KelEvent`s, each carrying its sequence
  number, the prior key that signed it, the current key it installs, the
  next-key pre-rotation commitment, and the distinct `WitnessReceipt`s a witness
  pool returned. `Kel::replay` derives the witnessed current `KeyState` **only**
  when:
  - the log is **fork-free** — two *distinct* events at the same sequence are
    `Rejected("forked-kel: …")`, never resolved last-writer-wins (a byte-identical
    duplicate is not a fork but is still caught as a repeated sequence);
  - each rotation is signed by the prior key the preceding event installed and
    reveals a key that event **pre-committed** to;
  - the **tip clears the AID's `WitnessPolicy` threshold** — fewer than
    `threshold` *distinct* corroborating witnesses (or a withheld-receipt /
    stale snapshot) is `Rejected("stale-keystate: …")`. Duplicate receipts from
    one witness cannot inflate the count; a zero threshold never accepts.
- **`crates/murmur-core/src/lib.rs`.** `prove_witnessed_keystate` drives all
  three halves hermetically: the honest incept→rotate log replays to the
  pre-committed current key-state corroborated above threshold; a fork (a second
  different rotation spliced in at sequence 1, *even signed by the legitimate
  prior key* so signature alone would not catch it) is refused; the same log
  served with the tip's receipts withheld below threshold is caught. Fails closed
  on a forked or stale key-state that was *accepted* (the trap). Module wired in;
  `Kel`/`KelEvent`/`WitnessPolicy`/`WitnessReceipt` re-exported.
- **`crates/murmur-relay/src/main.rs`.** New `run_witnessed_keystate` leg added
  to `serve` (11→12 legs); prints `fork-rejected + witness-corroborated`.

No loop vocabulary in product code (claims referenced by description / PRD
section, never gap-ID — leakcheck clean on both trees).

## Verdict (the only arbiter)

- `recurve --config .recurve/murmur.toml probe --gap WIT-1` — **GREEN**; trap
  `forked-kel` stays **RED** (the probe discriminates).
- `cargo test -p murmur-core` — **92 passed** (7 new in `kel`).
- `cargo clippy --release -p murmur-core -p murmur-relay` — clean (no
  warnings, no suppressions).
- `recurve --config .recurve/murmur.toml matrix --gate` — **GATE OK**: 16
  holding, 0 regressions / broken / stale / missing, **13/13 traps RED**,
  `sculpt murmur: gate OK`, `leakcheck: clean`.

## Ledger delta
WIT-1 `open → closed`. No new draft gaps (the fix was complete; ENC-3 / WIT-1's
neighbours were not touched). `recurve coverage --gate` — no prose drift (the
suite carries no GAPS.md prose file).
