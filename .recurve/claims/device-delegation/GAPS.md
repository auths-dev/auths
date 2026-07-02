# device-delegation — Workstream A gate

The executable definition of "done" for fixing the device-DID collapse
(`identity_did == device_did`). Each claim has a probe (GREEN/RED/BROKEN) and a
trap (a known-bad it must reject). The gate keeps every closed claim GREEN forever,
so no piece can "finish" while another regresses — the exact failure that stalled
the naive fix (init done, signing silently broken).

| id | claim | status | probe |
|----|-------|--------|-------|
| DD-1 | after `auths init`, `identity_did != device_did` | RED | `probes/dd-1.sh` |
| DD-2 | a commit signs+verifies end-to-end under delegated device #0 (**headline**) | RED | `probes/dd-2.sh` |
| DD-3 | the primary device is independently revocable; the root survives | RED | `probes/dd-3.sh` |
| DD-4 | one canonical device DID (no `did:key`/`did:keri` split) | RED | `probes/dd-4.sh` |
| DD-5 | the delegated inception is keripy byte-identical (interop) | **GREEN** (PR #360) | `probes/dd-5.sh` |

## Why DD-2 is the headline
The collapse looks like a one-line fix in `resolve_local_signer`, but the commit
trailer `Auths-Device` (from `resolve_local_signer`) and the signing key (from
`auto_detect_device_key`, which lists by the *root* DID) must agree on device #0 —
or the trailer claims device #0 while the root key signs and **verification fails**.
DD-2 is the probe that makes that impossible to fake: the refactor isn't done until a
real `init → sign → verify` round-trips green under device #0.

## Decisions routed to a human (not machine-decidable — kept OUT of the gate)
- The **recovery-key mechanism** (passkey multisig member vs pre-rotation).
- The **revocation-semantics interop** (auths's digest-seal convention vs a KERI-standard
  mechanism keripy honors) — see `device_did_collapse_notes.md` §8.
- The **root-threshold model** (single-controller governance root vs multisig).

## Run
From the auths repo root:
```bash
recurve --config .recurve/device-delegation.toml status   # RED count = remaining WS-A work
recurve --config .recurve/device-delegation.toml gate      # full gate (build once, probes hermetic)
```
