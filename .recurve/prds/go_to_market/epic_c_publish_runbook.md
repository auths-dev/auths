# Epic C — Publish Runbook (AU-9 / AU-10 / AU-11 OPS)

All in-repo edits are done (renames, version bumps, the `publish-typescript.yml`
workflow). This is the copy-paste OPS half: publishes, deprecations, and the Go
module tag. Run from the `auths` repo root unless noted. Requires: npm login as
the `auths-dev` org owner, PyPI trusted-publisher already configured (the
workflow uses it), push rights to `auths-dev/auths`.

> Prerequisite: merge/commit the Epic B+C edits to `main` first — the
> workflow-dispatch jobs run from the default branch.

## 1. AU-9 — publish `@auths-dev/verifier` (TS/WASM)

Via the new workflow (preferred — provenance + tests):

```bash
gh workflow run publish-typescript.yml -f target=dry-run   # sanity check first
gh workflow run publish-typescript.yml -f target=npm
```

Or locally:

```bash
cd packages/auths-verifier-ts
npm install && npm run build && npm test
npm publish --access public
```

Verify: `npm view @auths-dev/verifier version` → `0.1.1` (all package versions
are synced to the workspace version by `scripts/releases/0_versions.py`, gated in CI).

## 2. AU-11 — publish `@auths-dev/express`

Covered by the same `publish-typescript.yml` run (its second job). Local
fallback:

```bash
cd packages/auths-express
npm install && npm run build && npm test
npm publish --access public
```

Verify: `npm view @auths-dev/express version` → `0.1.1`.

## 3. AU-11 — republish the Node + Python SDKs (now versioned to match the CLI: 0.1.1)

```bash
gh workflow run publish-node.yml -f target=dry-run
gh workflow run publish-node.yml -f target=npm

gh workflow run publish-python.yml -f target=testpypi      # smoke first
gh workflow run publish-python.yml -f target=pypi
```

Verify:
```bash
npm view @auths-dev/sdk version          # → 0.1.1
pip index versions auths                 # → 0.1.1
```

> Note: 0.1.1 is a stable semver — it supersedes the stale 0.1.0 on npm and PyPI by normal resolution (no yanks needed).

## 4. AU-11 — deprecate the throw-on-import stubs

The local `npm-stubs/` sources are deleted; deprecate the published 0.0.1
packages so installs warn loudly (names stay reserved):

```bash
npm deprecate @auths-dev/policy@'*' "Not yet available — use @auths-dev/sdk; see https://auths.dev"
npm deprecate @auths-dev/react@'*'  "Not yet available — use @auths-dev/sdk; see https://auths.dev"
```

Note: `@auths-dev/sdk@0.0.1` was also originally a stub, but 0.1.0+ are real —
no deprecation needed (step 3 supersedes it).

## 5. AU-10 — tag the Go module so `go get` resolves

Go's nested-module convention: the tag must be prefixed with the module's
subdirectory path.

```bash
git tag packages/auths-verifier-go/v0.1.1
git push origin packages/auths-verifier-go/v0.1.1
```

Verify (in a scratch dir):
```bash
go mod init scratch && go get github.com/auths-dev/auths/packages/auths-verifier-go@v0.1.1
```

## 6. Post-publish doc check

`docs/sdk/verifier/wasm.md`, `docs/sdk/node/*`, `docs/sdk/python/*`, and the
package READMEs already reference the new names — once steps 1–3 are done,
every `npm install` / `pip install` command in docs resolves.

Then tick the remaining OPS halves of AU-9/AU-10/AU-11 in `next_plan.md`.
