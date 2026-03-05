# fn-3.10 Update e2e script for SDK-based seed import

## Description
STRIP all `LAYOUT_ARGS` overrides from the e2e script. If the script requires flags to find the identity, the implementation of fn-3.2 has failed.

## Strict Requirements

1. **DELETE** all `LAYOUT_ARGS` variable definitions and usages from `scripts/radicle-e2e.sh`
2. **DELETE** any `--identity-ref`, `--attestation-prefix`, or similar layout override flags from CLI invocations
3. **IMPLICIT AGREEMENT**: The `auths` CLI and `rad` CLI must agree on the default layout internally. The RIP-X layout is the only layout.
4. **REWRITE** any verification steps that check old paths:
   - DELETE "Phase 6b: Verify identity resolution" if it checks old `refs/rad/multidevice` paths
   - REPLACE with verification that `did-key` and `did-keri` blobs exist at `refs/keys/<nid>/signatures/`
5. **SEED FILES**: Document any remaining seed-file-to-disk usage as test-only. If the SDK import from fn-3.4 enables a cleaner path, use it.

## Dependencies
- fn-3.2 (ref paths reconciled -- no LAYOUT_ARGS needed)
- fn-3.4 (SDK seed import -- enables cleaner seed handling)

## Key Files
- `scripts/radicle-e2e.sh` -- target script
- `justfile` -- `e2e-radicle` target

## Verification
- `grep -i "LAYOUT_ARGS" scripts/radicle-e2e.sh` returns zero results
- `grep "identity-ref\|attestation-prefix" scripts/radicle-e2e.sh` returns zero results
- Script validates blobs at `refs/keys/<nid>/signatures/{did-key,did-keri}`
- `just e2e-radicle` passes end-to-end
## Problem

The current e2e script:
- Writes seed files to disk (`$NODE1_SEED`, `$NODE2_SEED`) at lines ~171-173
- Calls `auths key import --seed-file` which reads from those files
- Uses `LAYOUT_ARGS` CLI flags to override ref paths

After fn-3.4 (SDK seed import) and fn-3.2 (ref path reconciliation), the script should:
- Avoid writing seed files to disk where possible (or at least document the security tradeoff for testing)
- Remove `LAYOUT_ARGS` overrides if `StorageLayoutConfig::radicle()` is now the default
- Validate that attestations appear at the reconciled ref paths

## Implementation

1. Review current `scripts/radicle-e2e.sh` flow
2. Update seed import steps to use the new SDK-based approach (if the CLI now wraps the SDK function, the CLI invocation may remain but with different flags)
3. Remove or simplify `LAYOUT_ARGS` if no longer needed
4. Add verification steps that check attestations exist at the canonical RIP-X ref paths
5. Add comments explaining any remaining security tradeoffs (test-only seed file usage)

## Dependencies
- fn-3.4 (SDK seed import) -- must be done first
- fn-3.2 (ref path reconciliation) -- must know canonical paths

## Key Files
- `scripts/radicle-e2e.sh` -- target script
- `justfile` -- `e2e-radicle` target

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `LAYOUT_ARGS` DELETED from e2e script
- [ ] Zero layout override flags in CLI invocations
- [ ] `grep -i "LAYOUT_ARGS" scripts/radicle-e2e.sh` returns zero results
- [ ] Old-path verification steps DELETED or REWRITTEN
- [ ] Script validates blobs at RIP-X ref paths (`refs/keys/<nid>/signatures/`)
- [ ] Seed file usage documented as test-only
- [ ] `just e2e-radicle` passes
## Done summary
Made RIP-X layout the default StorageLayoutConfig. Deleted all LAYOUT_ARGS from radicle-e2e.sh and test_cli_radicle. Removed --preset radicle flag. Rewrote Phase 6b to verify refs/rad/id and refs/keys/<nid>/signatures/ paths. Documented seed file usage as test-only. Updated radicle.md guide.
## Evidence
- Commits: e1ee1fb
- Tests:
- PRs:
