# Cycle: post-compromise-healing — ENC-3 closed

## Gap
ENC-3 (missing-surface, feature) — *Post-compromise healing: after a simulated
state compromise, the next DH ratchet step restores confidentiality — the
attacker is locked back out.*

ENC-2 built the **symmetric** half of the Double Ratchet (forward secrecy: a
captured ciphertext can't be reopened from a *later* state). What it cannot do is
**heal**: an attacker who snapshots the full session state at one instant — the
root key and the live chain key — can derive every subsequent *symmetric* step,
because the symmetric chain only ever HMACs what it already holds; it injects no
new secret entropy. A transient compromise stayed permanent. The **asymmetric**
(Diffie-Hellman) half of the Double Ratchet — the part that mixes fresh DH entropy
into the root on each turn — was unbuilt, so there was no session to heal.

## What changed (target tree: ../auths)

- **`crates/murmur-core/src/dh_ratchet.rs` (new).** A `DhRatchet` = a 32-byte root
  key plus the party's current X25519 ratchet key pair. A **DH ratchet step**
  (`ratchet_send`) mints a *fresh* ephemeral key pair and mixes a fresh
  `DH(new_priv, peer_pub)` into the root through HKDF-SHA256 — the Signal `KDF_RK`:
  the old root **salts** the KDF, the fresh DH output is the IKM, and the expand
  emits `(next_root, chain_seed)` under two distinct domain-separation labels. The
  peer follows with `ratchet_receive` (`DH(my_priv, peer_new_pub)`) and lands on
  the **same** new root because DH is symmetric. The old root is `zeroize`d on
  every advance and on drop. The step seeds a fresh forward-secret symmetric
  `Ratchet` (the ENC-2 chain) from `chain_seed`, so the two ratchets compose into
  the full Double Ratchet. **Why it heals:** the new root depends on a private key
  minted *after* the compromise that never left the device; an attacker holding
  only the prior root, with both ratchet public keys on the wire, still cannot
  compute the DH output, so cannot derive the new root — locked out.
- **`crates/murmur-core/src/lib.rs`.** `prove_post_compromise_healing` drives the
  property hermetically: both ends seed a `DhRatchet` from the same agreed root;
  the full pre-step root is snapshotted exactly as the attacker would seize it; the
  sender takes a DH step and the receiver follows; messages sealed on the post-step
  (healed) chain are store-and-forwarded through the relay, drained, opened, and
  **authenticated as the sender**; finally the compromised pre-step root is run as a
  symmetric chain against the captured post-step ciphertext and **cannot open it**.
  Returns a `PostCompromiseReceipt`; an attacker who could still decrypt after the
  step is an error, never a silent pass (the trap). Module wired in; `DhRatchet` /
  `DhStep` re-exported.
- **`crates/murmur-relay/src/main.rs`.** New `run_post_compromise_healing` leg
  (the 5th of now 13) emits the `post-compromise-healed` marker the probe greps
  for, naming the healing turn index and the count of healed messages delivered.

## Composition with ENC-2
The DH ratchet **advances the root** and seeds a fresh chain on each turn; the
per-message keys on that chain are the existing forward-secret `Ratchet`. Forward
secrecy (ENC-2: an earlier ciphertext can't be reopened from a later state) and
post-compromise security (ENC-3: a later state can't be opened from an earlier
*compromised* one) are duals, and together are the full Double Ratchet. Embedding
libsignal's audited ratchet behind a misuse-resistant wrapper remains its own work,
gated on the external-audit precondition (ENC-7).

## The probe and its trap
- `probes/enc-3.sh` drives the staged `bin/murmur-relay serve` and greps for
  `post-compromise-healed`. RED before (the leg was absent), GREEN after.
- Trap `probes/enc-3.trap/no-healing/` — a captured run where the attacker still
  decrypted after the ratchet step — turns the probe RED (discrimination verified:
  GREEN on the good path, RED on the trap).

## Verdict (the only arbiter)
- `recurve --config .recurve/murmur.toml probe --gap ENC-3` — GREEN.
- `recurve --config .recurve/murmur.toml matrix --gate` — **GATE OK**, fleet-wide:
  `holding 16 · ready_to_close 0 · regressions 0 · broken 0 · stale 0 · missing 0`,
  `traps 14/14 RED` (the ENC-3 trap is now an enforced counterexample, 13→14),
  `leakcheck: clean` over both trees, `sculpt murmur: gate OK (exit 0)`.
- `recurve --config .recurve/murmur.toml coverage --gate` — 0 orphan prose gaps.
- `cargo test -p murmur-core` — 98 pass (6 new: 4 in `dh_ratchet`, 2 in `lib`).
- `cargo clippy -p murmur-core -p murmur-relay --all-targets` — clean, no
  suppressions of a real defect (the `too_many_arguments` allow on the orchestration
  function matches the established `deliver_rooted` convention in the same file).

## Notes
- No loop vocabulary in product code: the feature is referenced by its real
  cryptographic name (DH ratchet, post-compromise security) and PRD §10, never by
  gap-ID, cycle name, or the tool's name; `leakcheck` clean over both trees.
- No crypto reinvented — X25519 over `x25519-dalek` (the curve X3DH already uses)
  and HKDF-SHA256, both already in the workspace lock.
- Committed unsigned, per-repo; only the paths this cycle created/edited were
  staged. The operator's in-flight edits were left untouched.
