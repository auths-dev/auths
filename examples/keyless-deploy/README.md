# Example: keyless deploy (static token deleted)

> **First-party only.** A CI job deploying to *your own* target. Not third-party API auth.

This example is the leading-indicator artifact for the
[Delete your static token](../../docs/guides/delete-your-static-token.md) recipe: a CI deploy
job that **no longer stores a `DEPLOY_TOKEN`**. The job fetches a single-use challenge, presents
proof of control of a delegated workload credential, and the deploy target verifies it offline.

## The diff that deletes the secret

```diff
  jobs:
    deploy:
      steps:
-       - name: Deploy
-         env:
-           DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}   # long-lived bearer secret in CI
-         run: |
-           curl -sSf -X POST https://deploy.internal/v1/deploy \
-             -H "Authorization: Bearer $DEPLOY_TOKEN" -d @release.json
+       - name: Deploy (keyless — no stored secret)
+         run: |
+           NONCE=$(curl -sSf https://deploy.internal/v1/auth/challenge | jq -r .nonce)
+           AUTH=$(auths credential present \
+                    --subject "$AUTHS_WORKLOAD_ALIAS" --said "$AUTHS_CREDENTIAL_SAID" \
+                    --audience deploy.internal --nonce "$NONCE")
+           curl -sSf -X POST https://deploy.internal/v1/deploy -H "$AUTH" -d @release.json
```

The after-state workflow is committed as [`deploy.yml`](./deploy.yml). There is no
`secrets.DEPLOY_TOKEN` reference anywhere — `grep -r DEPLOY_TOKEN .` over this example returns
nothing, which is the point.

## Proving the cutover is safe

Before deleting the secret, dual-run and confirm nobody uses the token path (see the recipe's
"Cutover" section). Only then remove the GitHub Actions secret and the token-accepting branch of
the middleware.

## End-to-end

The full challenge → present → verify → authorized, then revoke → denied flow is exercised by
the in-repo tests; run them with:

```bash
../../scripts/e2e-keyless-deploy.sh
```
