# Release runbook (agent-facing)

Every step in order, what to run, what success looks like, and how to recover.
Optimized so an agent can cut a release end to end without a human diagnosing.
Reference (human overview): `scripts/releases/README.md`.

**Model:** one signed `v{version}` tag push fans out to every channel in
parallel. Versions are synced and CI-gated *before* the tag, so no channel can
drift. Everything is a dry-run first; `--push` / `--publish` / `--write`
execute.

**Preconditions (verify before starting):**
- On `main`, clean working tree: `git status --porcelain` prints nothing.
- Authed: `gh auth status` OK; `cargo login` done (or `CARGO_REGISTRY_TOKEN` set) if publishing crates locally.
- Decide the new version (semver). Current: `grep '^version' Cargo.toml` under `[workspace.package]`.

---

## Step 1 — Bump the workspace version

Edit `Cargo.toml` `[workspace.package] version = "X.Y.Z"`. Then sync the npm /
PyPI / mobile-ffi versions off it:

```bash
python scripts/releases/0_versions.py            # dry-run: prints planned edits
python scripts/releases/0_versions.py --write     # apply
```

- **Success:** `--write` reports the stamped files (package.json, pyproject, mobile-ffi Cargo.toml) at the new version.
- **Verify:** `python scripts/releases/0_versions.py --check` exits 0 (this is the same gate CI runs).
- **Recover:** if `--check` fails, a file drifted — re-run `--write` and re-check.

## Step 2 — Commit the version bump

```bash
git add -A && git commit -m "release: vX.Y.Z"
```

- **Success:** clean tree again (`git status --porcelain` empty).
- **Note:** if the `auths-sign` commit hook hangs on a keychain prompt, the sign step is waiting on hardware approval — approve it, or commit with the hook disabled if unattended.

## Step 3 — Tag and push (triggers the whole fan-out)

```bash
python scripts/releases/1_github.py               # dry-run: shows the tag it will create
python scripts/releases/1_github.py --push         # verifies clean tree + bumped version, creates + pushes the signed vX.Y.Z tag
```

- **Success:** the `vX.Y.Z` tag exists on the remote (`git ls-remote --tags origin | grep vX.Y.Z`) and the tag-triggered workflows start.
- **Recover (bad tag):** delete locally and remotely, fix, re-tag:
  `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`.

## Step 4 — Watch the fan-out (parallel, tag-triggered)

```bash
gh run list --branch vX.Y.Z --limit 10
```

| Workflow | Publishes | Success signal |
|---|---|---|
| `release.yml` | GitHub release binaries (4 platforms, signed + Sigstore) → pushes the updated Homebrew formula to `auths-dev/homebrew-auths-cli` | GitHub Release `vX.Y.Z` has 4 tarballs + `.sha256`; the tap repo has a new formula commit |
| `publish-crates.yml` | all workspace crates to crates.io in dependency order (`2_crates.py`) | run is green; `cargo search auths-cli` shows the new version |
| `publish-node.yml` | `@auths-dev/sdk` to npm | run green; `npm view @auths-dev/sdk version` |
| `publish-python.yml` | `auths` to PyPI (trusted publishing) | run green; `pip index versions auths` |

- **Recover (crates partial failure):** `publish-crates.yml` runs `2_crates.py`, which is **idempotent** — already-published versions are skipped, so re-running the workflow after a mid-batch failure is safe.

## Step 5 — Post-release verification

```bash
gh release view vX.Y.Z          # 4 tarballs + checksums present
cargo search auths-cli          # crates.io shows X.Y.Z
```

---

## Known gotchas

- **PyPI stale `0.1.0`.** PyPI has a stale `0.1.0` upload that sorts above any `0.0.1`-series prerelease. Until launch, `pip install auths` may resolve the wrong version — yank `0.1.0` (or release from `0.1.0`+) before expecting a synced resolve.
- **PEP 440 version form.** PyPI uses the PEP 440 form (`0.0.1-rc.12` → `0.0.1rc12`); `0_versions.py` handles the translation.
- **mobile-ffi is its own cargo workspace.** `crates/auths-mobile-ffi` sits in a separate workspace; `0_versions.py` is what keeps it on the main version — don't hand-edit it.
- **`get.auths.dev` needs no per-release action.** The install script (Vercel edge fn in `deploy/get-auths-dev/`) reads `scripts/install.sh` from `main` at request time.

## Secrets (configured in the repo/org, not per release)

`CARGO_REGISTRY_TOKEN` (crates), `NPM_TOKEN` (npm), `HOMEBREW_TAP_TOKEN`
(tap push). PyPI uses trusted publishing — no token secret.
