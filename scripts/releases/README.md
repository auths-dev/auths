# Release flow

One tag push fans out to every distribution channel. Versions are synced
*before* the tag and gated in CI, so no channel can drift behind a release.

## Cutting a release

```bash
# 1. Bump [workspace.package] version in Cargo.toml, then sync packages
just release-versions          # scripts/releases/0_versions.py --write

# 2. Commit, then tag + push (verifies clean tree, bumped version, signed tag)
just release-github            # scripts/releases/1_github.py --push
```

The `v*` tag push triggers, in parallel:

| Workflow | Publishes |
|----------|-----------|
| `release.yml` | GitHub release binaries (4 platforms, signed + Sigstore-logged) → then pushes the updated Homebrew formula directly to `auths-dev/homebrew-auths-cli` |
| `publish-crates.yml` | All workspace crates to crates.io in dependency order (`2_crates.py`) |
| `publish-node.yml` | `@auths-dev/sdk` to npm |
| `publish-python.yml` | `auths` to PyPI |

## Scripts

| Script | Purpose |
|--------|---------|
| `0_versions.py` | Stamp npm/PyPI/mobile-ffi versions from the workspace version. `--check` (CI gate, runs in `ci.yml` and `publish-crates.yml`), `--write`, or bare dry-run. |
| `1_github.py` | Create + push the signed `v{version}` tag. Bare invocation is a dry-run; `--push` executes. |
| `2_crates.py` | Publish all crates in dependency-ordered batches with 60s index waits. Idempotent — already-published versions are skipped, so re-running after a partial failure is safe. Bare invocation is a dry-run; `--publish` executes. |

## Secrets required

| Secret | Used by |
|--------|---------|
| `CARGO_REGISTRY_TOKEN` | `publish-crates.yml` (crates.io API token) |
| `NPM_TOKEN` | `publish-node.yml` |
| `HOMEBREW_TAP_TOKEN` | `release.yml` (push access to the tap repo) |
| PyPI trusted publishing | `publish-python.yml` (`pypa/gh-action-pypi-publish`, no token secret) |

## Notes

- The PyPI version uses the PEP 440 form of the workspace version
  (`0.0.1-rc.12` → `0.0.1rc12`). PyPI already has a stale `0.1.0` upload,
  which sorts *above* any `0.0.1`-series prerelease — yank it (or pass
  `0.1.0` at launch) before expecting `pip install auths` to resolve a
  synced version.
- `crates/auths-mobile-ffi` sits in its own cargo workspace; `0_versions.py`
  is what keeps it on the main workspace version.
- The install script served at `get.auths.dev` (Vercel edge function in
  `deploy/get-auths-dev/`) reads `scripts/install.sh` from `main` at request
  time — it needs no per-release action.
