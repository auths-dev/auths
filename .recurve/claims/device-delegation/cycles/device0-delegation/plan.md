# Sculpting cycle: device0-delegation

> One cycle, finished and proven. The cycle is done when every probe below is
> GREEN and `recurve matrix --gate` is green across ALL suites — not just the
> ones that motivated the change.

## Gaps this cycle closes

| gap | suite | severity | class | probe |
| --- | --- | --- | --- | --- |
| DD-1 | device-delegation | headline | missing-surface | `dd-1.sh` |
| DD-2 | device-delegation | headline | missing-surface | `dd-2.sh` |
| DD-3 | device-delegation | headline | missing-surface | `dd-3.sh` |
| DD-4 | device-delegation | feature | missing-surface | `dd-4.sh` |

## Smallest fixes (the SCULPT scope — keep it minimal, type-driven)

- **DD-1** — init delegates device #0 (its own dip AID) and resolve_local_signer reports it, so whoami's identity_did != device_did.
- **DD-2** — init + resolve_local_signer + auto_detect_device_key agree on device #0's key and AID, so `auths sign` then `auths verify` round-trips GREEN with Auths-Device == device #0's did:keri.
- **DD-3** — `auths device remove <device#0>` revokes the delegated device; the root identity still verifies and a NEW commit from the revoked device is rejected.
- **DD-4** — every surface (whoami, attestation subject, Auths-Device trailer) reports device #0's single delegated did:keri; did:key stays underlying key material only.

## What gets stronger (the REBUILD payoff)

- **DD-1** unlocks: the device is a first-class identifier, separable from the identity
- **DD-2** unlocks: the headline gate — the refactor cannot be "done" while signing is broken underneath
- **DD-3** unlocks: "lost my device" recovery without nuking the identity
- **DD-4** unlocks: interop consumers see one device identity, not two conflicting ones

## Definition of done (the GATE)

- [ ] Every gap probe above flips RED → GREEN (`recurve probe --gap <id>`).
- [ ] `recurve matrix --gate` green across all suites: zero regressions, zero broken.
- [ ] Each touched suite's harness green.
- [ ] Tree changes satisfy the quality constitution (parse-don't-validate,
      ports/adapters, one source of truth); build/lint/tests clean; no suppressions.
- [ ] `gaps.yaml` statuses promoted open→closed; `GAPS.md` prose updated to
      describe the NEW reality (the gap becomes a feature note).
- [ ] Anything discovered mid-cycle that can't be closed is filed as a NEW gap
      with its own RED probe (the loop never silently drops scope).

## Matrix baseline (captured at cycle start)

```
    gap         outcome   status     Δ        detail
  ● DD-1        GREEN    open       READY→close identity_did (did:keri:EPvD0iAks7SawINxrVBUBgpt99rphuHQL7CqR
  ● DD-2        GREEN    open       READY→close artifact signs+verifies AND is signed by device #0 (did:keri
  ● DD-3        GREEN    open       READY→close device #0 revoked; root (did:keri:ECjOSyzOBjBJirsrlXRhozTs4Z
  ● DD-4        GREEN    open       READY→close one canonical device DID across surfaces: did:keri:EPlqT8p_1

holding 0 · ready_to_close 4 · regressions 0 · broken 0 · stale 0 · skipped 0 · missing 0
GATE OK
```
