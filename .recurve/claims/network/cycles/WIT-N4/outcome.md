# Cycle WIT-N4 — the node proves what binary it runs

- **Date:** 2026-06-14
- **Gap:** `WIT-N4` (class `missing-surface`, severity `feature`)
- **Result:** **CLOSED — promoted.** Probe authored greenfield (+ wrong-digest
  forged-attestation trap), baselined RED, driven GREEN; the trap stays RED; the
  BOOT, WIT-N1, WIT-N2, WIT-N3 probes still GREEN; all three gates green (suite
  `recurve matrix --gate` → exit 0, demos `rictl matrix --gate` → exit 0,
  interop `ictl matrix --gate` → exit 0). `open → closed` in `gaps.yaml`;
  GAPS.md §WIT-N4 rewritten to the closed reality.
- **auths rev:** branch `dev-auths-network` (parent `13767be3`).

## The claim, and why it was genuinely RED

A witness operator vouches for the network; the operator must in turn be
**vouchable** — a relying party has to confirm the node runs the binary the
platform shipped, not a silently-swapped one. WIT-N4: a running node exposes a
**signed version+digest build attestation** (dogfooding `auths artifact sign
--ci`), `auths witness status` verifies it, and a forged attestation — perfectly
signed but over a DIFFERENT binary — is rejected.

The probe (`probes/wit-n4.sh`, authored this cycle) stands up its own throwaway
node with a build attestation the harness produced over the released image's
binary, GETs `/build`, asserts `status` verifies it, then stands a SECOND node up
with an attestation signed over a different artifact and asserts `status` refuses.
At baseline it was honestly RED — the running node had **no build-proof surface
at all** and `status` had no build leg:

```
$ NO_COLOR=1 bash probes/wit-n4.sh
curl: (22) The requested URL returned error: 404
ours=no-build-endpoint expected=served-proof — the node did not serve a build
attestation at /build (curl exit 22); a node that cannot say which binary it
runs cannot be vouched for                                       (exit 1 RED)
```

`status` previously printed only `healthy: <url>` and exited 0 — it never asked
which binary the node ran.

## The fix (smallest honest change in `../auths`)

Compose the trust kernel; never re-implement protocol. The seam is the repo
boundary: the *signature check* is protocol (correct-for-strangers → the public
verifier); the *self-measurement and serving* is operation (the node + its CLI).

1. **The node measures its own binary** (`auths-core` witness server,
   `auths-witness` binary): at startup the binary computes the SHA-256 of its own
   executable (`/proc/self/exe`) and pairs it with the signed attestation it reads
   from `AUTHS_WITNESS_BUILD_ATTESTATION`, serving both as a `BuildProof` at a new
   `GET /build`. The server interprets none of it; **404** when no attestation was
   configured — a node that cannot prove its binary says so plainly.
2. **The offline check is in the PUBLIC verifier**
   (`auths_verifier::verify_build_attestation_offline`): a **two-leg, fail-closed**
   verdict — the attestation's signature verifies against the key its
   self-describing `did:key` issuer embeds (composing the existing attestation
   verifier, the `artifact verify --signature-only` path), AND the attested digest
   equals the node's self-measured running digest. A valid signature over the
   WRONG binary lands on `DigestMismatch`, never `Verified` — the forgery the
   claim exists to catch.
3. **The node crate composes it** (`auths-witness-node`):
   `BuildAttestation::verify → NodeBuildVerdict`, rendered by a new
   `SocketHttpFetch` port; `auths witness status` fetches `/build`, verifies, and
   fails closed (non-zero, distinct reason) on a forged or absent build.
4. **Standup injects the attestation** (WIT-B4): `auths witness up
   --build-attestation <path>` mounts the operator's attestation read-only into
   the node and points the binary at it, so a stood-up node serves its build proof
   from first boot. The attestation is produced over the **released image's**
   binary, never a source build — the harness extracts `/usr/local/bin/auths-witness`
   from the image and dogfoods `auths artifact sign --ci` over it
   (`harness/ensure-build-attestation.sh`).

The `witness-node` feature stays additive — `cargo tree -p auths-cli` (default)
pulls no `auths-witness-node`; only `--features witness-node` does (WIT-B2). The
lean default build is unchanged.

## The adversarial twin (kept RED)

`probes/wit-n4.trap/wrong-digest/forged.auths.json` — a genuinely-signed
attestation whose attested digest is NOT the node's running binary. Fed where the
GREEN path injects the genuine one, `status` rejects it:

```
rejected: the attestation is for a different binary (attested 296078e6…,
running 7ce84d53…) — this node is not running what it attests   (exit 1 RED)
```

A probe that called this "verified" would be one whose digest check is cosmetic.

## Gate (the conjunction, in order)

- `recurve matrix --gate` (suite) → **exit 0**: 7/7 probes GREEN, 7/7 traps RED,
  zero regressions/broken/stale/missing.
- demos `rictl matrix --gate` → **exit 0** (after rebuilding the lean default
  `auths` + every demo's `scripts/build.sh`, since this cycle touched `../auths`).
- interop `./scripts/build.sh && ./ictl matrix --gate` → **exit 0**.
- Build + clippy clean (`-D warnings`) across auths-core, auths-verifier,
  auths-witness, auths-witness-node, auths-cli (feature build). Unit tests added:
  the `/build` endpoint (404 absent / serves present), the offline build verdict's
  fail-closed arms, the node-crate parse + no-protocol-vocabulary summary.

## Files

- `../auths/crates/auths-core/src/witness/server.rs` — `BuildProof` +
  `measure_self`, `/build` route + handler, threaded through config/state.
- `../auths/crates/auths-core/src/witness/mod.rs`,
  `../auths/crates/auths-sdk/src/witness.rs` — re-export `BuildProof`.
- `../auths/crates/auths-witness/src/main.rs` (+ Cargo.toml) — read
  `AUTHS_WITNESS_BUILD_ATTESTATION`, measure self, attach the proof.
- `../auths/crates/auths-verifier/src/witness.rs` (+ lib.rs) —
  `OfflineBuildVerdict` + `verify_build_attestation_offline`.
- `../auths/crates/auths-witness-node/src/build.rs` (new), `engine.rs`,
  `standup.rs`, `lib.rs` (+ Cargo.toml) — `BuildAttestation`/`NodeBuildVerdict`,
  `HttpFetch`/`SocketHttpFetch`, standup `--build-attestation` mount.
- `../auths/crates/auths-cli/src/commands/witness.rs` — `status` verifies the
  build; `up --build-attestation`.
- Suite: `probes/wit-n4.sh`, `probes/wit-n4.trap/wrong-digest/forged.auths.json`,
  `probes/wit-n4.trap/README.md`, `harness/ensure-build-attestation.sh`,
  `gaps.yaml` (WIT-N4 closed), `gaps.draft.yaml` (promotion note), `GAPS.md`
  (§WIT-N4 rewritten).
