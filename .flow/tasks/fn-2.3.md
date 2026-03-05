# fn-2.3 Add identity resolution verification to e2e shell script

## Description
Add identity resolution verification to the e2e shell script (`scripts/radicle-e2e.sh`).

## What to add

Insert a new Phase 6b (between current Phase 6 and Phase 7) that:

1. Calls `auths device resolve --device-did $NODE1_DID` → captures `RESOLVED_DID_1`
2. Calls `auths device resolve --device-did $NODE2_DID` → captures `RESOLVED_DID_2`
3. Asserts `RESOLVED_DID_1 == CONTROLLER_DID` (from Phase 2)
4. Asserts `RESOLVED_DID_2 == CONTROLLER_DID`
5. Asserts `RESOLVED_DID_1 == RESOLVED_DID_2` (both devices → same identity)

## Context

The `CONTROLLER_DID` is already extracted in Phase 2. Both `NODE1_DID` and `NODE2_DID` are extracted in Phase 1. The `LAYOUT_ARGS` and `AUTHS_HOME` are already set up.

## Key file

- `scripts/radicle-e2e.sh` — insert after Phase 6 (line ~346), before Phase 7

## Example output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Phase 6b: Verify identity resolution
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  → Resolving device 1 DID to controller...
  ✓ Device 1 resolves to controller DID
  → Resolving device 2 DID to controller...
  ✓ Device 2 resolves to controller DID
  ✓ Both devices resolve to the same controller identity

  ✓ PASS: Phase 6b: Verify identity resolution
```

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Phase 6b exists in the e2e script between Phase 6 and Phase 7
- [ ] `auths device resolve` is called for both device DIDs
- [ ] Both resolved DIDs are compared to `CONTROLLER_DID` from Phase 2
- [ ] Both resolved DIDs are compared to each other
- [ ] Phase reports PASS/FAIL like other phases
- [ ] `bash scripts/radicle-e2e.sh` passes Phase 6b (requires fn-2.2 completed first)
## Done summary
Added Phase 6b to radicle-e2e.sh that resolves both device DIDs via 'auths device resolve' and asserts they map to the same controller DID.
## Evidence
- Commits:
- Tests:
- PRs:
