# fn-1.3 GitKel::with_ref() constructor for custom ref paths

## Description
Add a `GitKel::with_ref()` constructor to `crates/auths-id/src/keri/kel.rs` that accepts a custom ref path, allowing the KEL reader to use `refs/keri/kel` (RIP-X layout) instead of the default `refs/did/keri/<prefix>/kel`.

This is the "Adapter" pattern — by allowing the ref path to be injected, `GitKel` becomes a more flexible storage component.

### What to implement

1. Add `pub fn with_ref(repo: Repository, prefix: Prefix, ref_path: String) -> Self` to `GitKel`.
2. The existing `GitKel::new()` at `crates/auths-id/src/keri/kel.rs:59` should delegate to `with_ref()` using the default path from `kel_ref()` at line 44.
3. Validate that the provided ref_path is a valid Git refname.
4. All existing `GitKel` methods (`read_events()`, `append_event()`, etc.) must use the configured ref path.
5. **Safety**: Ensure `GitKel` still performs its internal prefix validation even when a custom path is used. The prefix must still match the KEL's inception event prefix regardless of ref path.

### Key context

- Current `kel_ref()` at line 44 produces `refs/did/keri/<prefix>/kel`.
- RIP-X identity repos use `refs/keri/kel` (no prefix in path — the prefix is implicit from the repo itself).
- The `GitKel` struct stores `repo: Repository` and `prefix: Prefix` — add a `ref_path: String` field.
- Do NOT change the `kel_ref()` function — it's used by existing non-Radicle code paths.

### Affected files
- Modified: `crates/auths-id/src/keri/kel.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `GitKel::with_ref()` constructor exists and accepts a custom ref path
- [ ] `GitKel::new()` delegates to `with_ref()` with default path (no regression)
- [ ] `GitKel::with_ref(repo, prefix, "refs/keri/kel".into())` reads KEL from the RIP-X path
- [ ] Invalid ref path returns a clear error
- [ ] Prefix validation still runs even with custom ref path (inception event prefix must match)
- [ ] All existing `GitKel` tests pass unchanged
- [ ] New tests: custom path reads events correctly, default path unchanged, prefix mismatch rejected
- [ ] `cargo nextest run -p auths-id` passes
## Done summary
- Added ref_path field to GitKel struct
- Added with_ref() constructor accepting custom ref path
- new() delegates to with_ref() with default kel_ref() path
- All methods now use stored ref_path instead of computing it
## Evidence
- Commits: b253fb5
- Tests: cargo nextest run -p auths-id -E test(kel)
- PRs:
