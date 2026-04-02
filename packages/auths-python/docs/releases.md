# Releasing auths

## Cutting a release

Push a `v*` tag using the release script:

```bash
python scripts/releases/1_github.py          # dry-run
python scripts/releases/1_github.py --push   # create tag and push
```

This triggers both `release.yml` (CLI/Rust) and `publish-python.yml` (PyPI) in parallel.

You can also publish manually via `workflow_dispatch` on the **Publish Python SDK** workflow, choosing `testpypi` or `pypi` as the target.

## One-time PyPI setup

These steps only need to be done once before the first publish:

1. **Register `auths` on PyPI** (or let the first publish create it)
2. **Configure OIDC Trusted Publisher on PyPI:**
   - Owner: `auths-dev`
   - Repository: `auths`
   - Workflow: `publish-python.yml`
   - Environment: `pypi`
3. **Configure OIDC Trusted Publisher on TestPyPI** — same settings but with environment: `testpypi`
4. **Create GitHub Environments:**
   - `pypi` — add approval protection (requires manual approval before publish)
   - `testpypi` — no protection needed
