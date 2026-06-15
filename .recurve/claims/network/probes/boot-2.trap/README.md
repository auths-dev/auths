# boot-2 trap — the witness-node feature stopped being additive

`node-in-default-tree/default-tree.txt` is a `cargo tree -p auths-cli` of the
**default** build in which `auths-witness-node` appears as a dependency. That is
the WIT-B2 regression: a default `auths` build dragging the node crate (and its
heavy deps) into the lean install. The BOOT-2 probe MUST turn RED on this
fixture — a green here would mean the additivity guard blessed its own
counterexample, the highest-order gate failure.

The probe consumes this fixture via `TRAP_FIXTURE`: it reads `default-tree.txt`
in place of the live `cargo tree`, then runs the same additivity assertion.
