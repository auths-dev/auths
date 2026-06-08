# Delete your static token (keyless service-to-service)

> **First-party only.** This recipe replaces a long-lived secret that *your own* code holds to
> talk to *your own* service (CI → your deploy target, service A → service B inside your
> org). It does **not** cover authenticating to a third party (AWS, Stripe, npm) — that needs
> the witness/discovery commons and is out of scope.

A static `DEPLOY_TOKEN` (or `SERVICE_TOKEN`, internal API key, …) is a bearer secret: anyone
who reads it from a log, a CI environment, or a leaked `.env` can replay it until you rotate.
This recipe swaps it for an **Auths presentation**: the caller proves *current control* of a
KERI-delegated credential per request, the relying party verifies it **offline against a
pinned root**, and there is **no stored secret to leak**.

The trust path is: a human/org root **delegates** a workload identity (a `did:keri:` AID) and
**issues** it a capability credential. The caller signs a fresh, single-use challenge with the
workload's current key; the relying party checks the signature, the credential, and revocation
against its local copy of the KELs — no online issuer, revocable by a KEL event.

---

## Before / after

The painful case: a CI job holding a long-lived token to deploy to your own target.

```diff
  # .github/workflows/deploy.yml
  jobs:
    deploy:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
-       - name: Deploy
-         env:
-           DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}   # long-lived bearer secret
-         run: |
-           curl -sSf -X POST https://deploy.internal/v1/deploy \
-             -H "Authorization: Bearer $DEPLOY_TOKEN" \
-             -d @release.json
+       - name: Deploy (keyless — no stored secret)
+         run: |
+           # 1) fetch a fresh single-use challenge bound to the audience
+           NONCE=$(curl -sSf https://deploy.internal/v1/auth/challenge | jq -r .nonce)
+           # 2) present: sign (credential_said ‖ audience ‖ nonce) with the workload's CURRENT key
+           AUTH=$(auths credential present \
+                    --subject "$AUTHS_WORKLOAD_ALIAS" \
+                    --said "$AUTHS_CREDENTIAL_SAID" \
+                    --audience deploy.internal \
+                    --nonce "$NONCE")
+           # 3) call the deploy target with the presentation (no bearer secret)
+           curl -sSf -X POST https://deploy.internal/v1/deploy \
+             -H "$AUTH" \
+             -d @release.json
```

The relying party (`deploy.internal`) mounts a drop-in middleware. Pick the stack that matches
your service:

- **Node / Express** → `@auths/express` (`packages/auths-express`) — canonical example below.
- **Python / FastAPI** → `auths-fastapi` (`packages/auths-fastapi`).
- **Rust / Axum** → `auths-api`'s `rp_auth` middleware (`crates/auths-api/src/rp_auth.rs`).

### Express relying party (canonical)

```ts
import express from 'express'
import { authsAuth, challengeHandler, ChallengeStore } from '@auths/express'

const app = express()
const challenges = new ChallengeStore(10_000)          // bounded, TTL-pruned, single-use
const audience = 'deploy.internal'

// 1) the mint route the client fetches a nonce from
app.get('/v1/auth/challenge', challengeHandler({ audience, challenges }))

// 2) guard the deploy route: a verified `principal` is reachable ONLY here
app.post(
  '/v1/deploy',
  authsAuth({
    audience,
    pinnedRoots,                 // your org root did:keri: lines from .auths/roots (DID-only)
    challenges,
    loadInputs,                  // resolve the issuer/subject/delegator KELs + TEL for a SAID
    verifyPresentation,          // the @auths-dev/sdk binding
    capabilityFor: () => 'deploy:prod',   // the capability this route requires
  }),
  (req, res) => {
    // `req.principal` exists only because the middleware verified it.
    res.json({ deployedBy: req.principal.subject })
  },
)
```

`.auths/roots` is **DID-only** — one `did:keri:` per line. Capabilities come from the
**presented credential's scope seal**, never the roots file.

---

## Cutover: dual-run, then delete

Do not flip in one commit. Run both auth paths, watch, then remove the secret.

1. **Add the passport path next to the token path.** Accept *either* a valid `Auths-Presentation`
   *or* the legacy `Authorization: Bearer $DEPLOY_TOKEN`. Tag each request with which path it
   used (a metric/log label `auth_path=presentation|token`).
2. **Migrate callers.** Switch each CI job / service to fetch a challenge and present. Watch
   `auth_path` — the `token` count should fall to zero.
3. **Prove nobody uses the old token.** Before deleting, confirm zero token-path requests over a
   full duty cycle (a week of nightly deploys, a full release train):

   ```bash
   # over your logging window — must be 0 before you delete the secret
   grep -c 'auth_path=token' deploy.log
   # or, in your metrics backend:  sum(rate(auth_requests_total{auth_path="token"}[7d])) == 0
   ```
4. **Delete the secret.** Remove the `DEPLOY_TOKEN` GitHub Actions secret / Vault entry / env
   var **and** the token-accepting branch of the middleware. The visible diff is the leading
   indicator that the secret is gone — see `examples/keyless-deploy/`.
5. **Rotate is now a KEL event, not a secret swap.** To revoke a compromised workload, run
   `auths credential revoke <said> --issuer <root>`; the next presentation is denied within the
   freshness bound (no secret to rotate, no redeploy).

---

## Challenge mode vs TTL mode

Prefer **challenge mode** (the default): the relying party mints a fresh single-use nonce, so a
captured presentation cannot be replayed — `consume` is remove-on-read.

**TTL mode** (a subject-chosen nonce valid until `not_after`) exists for callers that cannot do
the challenge round-trip. It carries a **within-TTL, same-audience replay residual**: a captured
presentation can be replayed until `not_after`. Keep the TTL short and only enable it
deliberately.

> Single-process challenge store only. Behind a load balancer the single-use guarantee holds
> per node — see the load-balancer caveat in `crates/auths-rp/src/challenge.rs`. A shared
> backend implements the same `ChallengeStore` trait seam (deferred; see the epic tracking issue).

---

## End-to-end verification

The keyless path is exercised end-to-end in-repo (challenge → present → verify → authorized,
then revoke → denied):

- **SDK e2e:** `crates/auths-sdk/tests/cases/authenticate.rs`
  - `valid_presentation_authenticates_and_replay_rejected` — present → authorize; replay denied.
  - `valid_then_revoked_presentation_transition` — authorized before revoke; **denied after**.
  - `presentation_for_audience_a_rejected_at_server_b` — confused-deputy / wrong-audience.
- **HTTP middleware:** `crates/auths-api/tests/cases/rp_auth.rs` (Axum),
  `packages/auths-express/__tests__` (Express), `packages/auths-fastapi/tests` (FastAPI) —
  valid → 200, replay → 401, wrong-audience → 401, expired → 401, missing-cap → 403, store-full → 429/503.

Run the canonical local e2e:

```bash
./scripts/e2e-keyless-deploy.sh
```

See `examples/keyless-deploy/` for the committed before/after diff of a CI job with its static
token deleted.
