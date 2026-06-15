# Quality constitution — pre-launch preset

The gate every sculpt must satisfy beyond "the probe is GREEN". Human-owned:
the loop obeys this document and never edits it.

1. **Parse, don't validate.** Boundary functions return fully-formed types or
   fail loudly with located errors; nothing downstream re-checks.
2. **Ports and adapters at I/O edges.** Core logic never imports transport,
   storage, or UI directly.
3. **One source of truth.** A fact lives in one place; everything else
   derives from it.
4. **Delete divergent paths.** No back-compat shims, no deprecated twins kept
   "just in case" — pre-launch, the kindest thing is the knife. Move the
   module down the dependency graph instead of shimming around it.
5. **Discovered problems become filed gaps.** Anything unrelated you find
   becomes a NEW draft entry with a RED probe sketch — never a TODO comment,
   never a silent fix smuggled into this cycle's diff.
6. **No fake green.** Never weaken a probe, skip a trap, or special-case a
   fixture to pass the gate. A green you argued into existence is a
   regression you scheduled.
7. **Consumers of a changed type are part of your change.** Bindings,
   call sites, serializations — if the type moved, they move in the same
   cycle.
8. Build, lint, and tests clean. No suppressions; a suppression is a filed
   gap wearing a disguise.
