# Release flow

One tag push fans out to every distribution channel. Versions are synced
*before* the tag and gated in CI, so no channel can drift behind a release.

> **Reading this with zero context? Do NOT run `just release` or
> `just release-github`.** Those assume an interactive Secure Enclave signer
> (fingerprint prompt) and run `cargo` under the hood. In a headless Claude
> session both fail. Follow **§ Cutting a release (headless, agent-signed)**
> below instead — it is the only path that works without a human at the
> keyboard, and it produces a properly `sign_release`-signed release.

## What a release must be

1. **Version-synced.** Every package manifest + lockfile stamped to the new
   workspace version (`0_versions.py` does this; `--check` gates it in CI).
2. **Agent-signed with `sign_release`.** The release *commit* carries the
   `claude-release` delegated agent's signature at scope `sign_release`, so
   `auths verify` accepts it through the pinned root. The tag points at that
   signed commit.
3. **Pushed as commit + tag together.** `main` advances to the release commit
   AND `vX.Y.Z` is pushed. The tag push is what triggers publishing.

## Cutting a release (headless, agent-signed)

Run from the `auths` repo root, on a clean `main` that is up to date with
origin. Replace `X.Y.Z` throughout.

```bash
cd /path/to/auths
export PATH="$HOME/.cargo/bin:$PATH"          # the auths CLI (0.1.x)
source ~/.auths-claude/env.sh                 # file keychain + agent registry (headless signing)

# 0. Preflight — must be clean, on main, synced. Confirm the version is NEW.
git switch main && git fetch origin && git status --short   # must be empty
python scripts/releases/1_github.py            # DRY RUN: checks crates.io + tag don't already have X.Y.Z

# 1. Bump + stamp EVERYTHING in one shot (no cargo needed — see gotcha #1).
python scripts/releases/0_versions.py --set X.Y.Z
python scripts/releases/0_versions.py --check  # must print "All package versions are in sync."

# 2. Commit as the claude-release agent (git's own SE signing OFF).
GIT_AUTHOR_NAME=claude-release GIT_AUTHOR_EMAIL=claude@auths.local \
GIT_COMMITTER_NAME=claude-release GIT_COMMITTER_EMAIL=claude@auths.local \
  git -c commit.gpgsign=false commit -aqm "release: X.Y.Z"

# 3. Agent-sign the commit at RELEASE scope (amends the commit, new SHA).
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.signingkey GIT_CONFIG_VALUE_0=auths:claude-release \
  auths sign HEAD --scope sign_release
env -u AUTHS_HOME -u AUTHS_REPO auths verify HEAD    # must print "verified: signed by did:keri:EO1c…"

# 4. Push main (the signed release commit) FIRST. --no-verify skips the slow
#    pre-push clippy hook; CI is the authority. Then mirror the registry ref
#    the skipped hook would have pushed.
git push --no-verify origin main
AUTHS_REGISTRY_MIRROR=1 git -C ~/.auths push git@github.com:auths-dev/auths.git \
  refs/auths/registry:refs/auths/registry || true

# 5. Tag the signed commit and push the tag → triggers all publish workflows.
#    tag.forceSignAnnotated=true is set repo-wide; it makes `git tag -a` invoke
#    the SE signer, which fails headless (AUTHS-E5910). Override it OFF here —
#    the RELEASE signature lives on the commit (step 3), not the tag object.
git -c tag.forceSignAnnotated=false tag -a vX.Y.Z -m "release: release for X.Y.Z"
git push --no-verify origin vX.Y.Z

# 6. Watch the fan-out (do not re-run locally):
gh run list --limit 8
```

Publishing is idempotent (`2_crates.py` skips already-published crates), so a
partial failure is safe to re-trigger — but npm/PyPI reject republishing an
existing version, so a re-tag of the *same* X.Y.Z will show red on those jobs
without harm. If you must re-cut, bump to the next patch instead.

## What the tag push triggers

| Workflow | Publishes |
|----------|-----------|
| `release.yml` | GitHub release binaries (4 platforms, `cargo build --release --locked`, signed + Sigstore-logged) → pushes the updated Homebrew formula to `auths-dev/homebrew-auths-cli` |
| `publish-crates.yml` | All workspace crates to crates.io in dependency order (`2_crates.py`) |
| `publish-node.yml` | `@auths-dev/sdk` to npm |
| `publish-python.yml` | `auths` to PyPI |

`release.yml` builds `--locked`, so the root `Cargo.lock` **must** already be
stamped to X.Y.Z — `0_versions.py --set` does that (gotcha #1); don't skip it.

## Gotchas (each one cost a real session)

1. **`0_versions.py --set` is complete — you do NOT need `cargo update` or
   `cargo run xtask gen-error-docs`.** `--set` stamps the workspace version,
   all npm/PyPI manifests, the internal workspace dep versions across crate
   `Cargo.toml`s, the root `Cargo.lock` (all workspace crates), the maturin
   `packages/auths-python/Cargo.lock`, and both `uv.lock`s. The heavier
   `just release` recipe runs cargo only as belt-and-suspenders; skip it.
   (Never run `cargo build`/`check`/`clippy`/`update` here — they pull the
   whole workspace and time out. CI compiles.)
2. **Sign with the AGENT, not the Secure Enclave.** `source ~/.auths-claude/env.sh`
   switches to the file keychain. Commit with `-c commit.gpgsign=false` then
   `auths sign HEAD` — never let git's own SE signer run (it needs a
   fingerprint and dies headless with `AUTHS-E5910`).
3. **Scope is `sign_release`, not `sign_commit`.** The agent
   (`did:keri:EO1cBsYoV5izKvdIL6TstN5TOQl1hYN3WnhtAOh1lwAp`) holds both;
   releases claim `sign_release`. (See the "Claude can sign" note in the repo
   `CLAUDE.md`.)
4. **`git tag -a` fails headless** because `tag.forceSignAnnotated=true` is set
   repo-wide → SE signer → `AUTHS-E5910`. Always pass
   `-c tag.forceSignAnnotated=false`. The provenance is the signed commit, so
   an unsigned tag object is fine.
5. **`1_github.py --push` pushes only the tag, and its `git tag -a` hits
   gotcha #4.** Use it for its DRY-RUN precheck (bare invocation: verifies the
   version isn't on crates.io and the tag is free), then do the tag yourself
   as in step 5. Push `main` separately — `1_github.py` never pushes it.
6. **Sign BEFORE you tag, tag BEFORE you push.** `auths sign` amends the commit
   (new SHA); if you tag first you'll tag the unsigned commit and have to
   re-point the tag. Order: bump → commit → sign → verify → push main → tag →
   push tag.

## Scripts

| Script | Purpose |
|--------|---------|
| `0_versions.py` | Stamp every package version + lockfile from the workspace version. `--check` (CI gate, in `ci.yml` and `publish-crates.yml`), `--write` (stamp, workspace version already bumped), or `--set X.Y.Z` (bump workspace version **and** stamp — use this). |
| `1_github.py` | Bare = dry-run prechecks (crates.io + tag existence + clean tree). `--push` creates & pushes an annotated tag — but its signing breaks headless (gotcha #4/#5); prefer the manual tag in step 5. |
| `2_crates.py` | Publish all crates in dependency-ordered batches with 60s index waits. Idempotent — already-published versions are skipped, so re-running after a partial failure is safe. Bare = dry-run; `--publish` executes. Called by `publish-crates.yml`. |

## Secrets required (CI-side; nothing to do locally)

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
- Downstream of an SDK release: bump the `@auths-dev/sdk` pin in
  `auths-site/apps/market` (`scripts/ensure-sdk-binding.mjs` VERSION +
  `package.json`) and redeploy; and cut the `@auths-dev/mcp` CLI release from
  the `auths-mcp` repo so the published gateway matches.
