# Deploying the Auths GitHub App (PR commit-verification gate)

The Auths GitHub App posts a **blocking check-run** on every pull request: it fails the
PR if any commit's signature is not verified or the commit was not signed by `auths`.
This is the org's PR-gate enforcement point (Epic E1, task C). The app lives in the
separate `auths-github-app` repo.

## What it enforces today

For each PR (`opened` / `synchronize`), the app:

1. Verifies the webhook HMAC (`X-Hub-Signature-256`) in **constant time** and dedupes
   on the `X-GitHub-Delivery` GUID (GitHub retries deliveries).
2. Mints a GitHub **App JWT** (RS256, short-lived) → exchanges it for an
   **installation access token** (cached ~1h, refreshed before expiry).
3. Lists the PR's commits and **fails closed** unless every commit:
   - carries a **GitHub-verified** signature (`commit.verification.verified == true`), and
   - carries the `Auths-Id` / `Auths-Device` trailers (proof it was signed by `auths`).
4. Posts a `auths/commit-verification` check-run with conclusion `failure` (with the
   per-commit reasons) or `success`, against the PR **head SHA**.

GitHub performs the cryptographic signature check; the app gates on that result plus
the auths trailers. (Org-policy capability/revocation enforcement from an air-gapped
bundle is the documented enhancement below.)

## GitHub App configuration

Create a GitHub App with:

- **Permissions:** `Checks: write`, `Pull requests: read`, `Contents: read`.
- **Subscribe to events:** `Pull request`.
- **Webhook URL:** `https://<your-host>/webhook`; set a strong **webhook secret**.

## Secrets / environment

| Env var | Purpose | Rotation |
|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for webhook authenticity | rotate on leak; update in GitHub + the service together |
| `GITHUB_APP_ID` | App ID (JWT `iss`) | static |
| `GITHUB_PRIVATE_KEY` | App RSA private key, PEM (mints App JWTs) | rotate via GitHub → generate a new key, deploy, then revoke the old |
| `AUTHS_ORG_BUNDLE` | *(optional)* path to an air-gapped org bundle for org-policy enforcement (see below) | re-export with `auths org bundle` after membership/policy changes |
| `PORT` | listen port (default 3001) | — |

Never log the installation token, the webhook signature, or the private key. The
private key is the root of this trust path — store it in a secret manager, not in env
files committed to disk.

## Branch protection (REQUIRED — the gate only blocks if you pin it)

In the repo's branch-protection rule for the protected branch:

1. **Require status checks to pass before merging.**
2. Add **`auths/commit-verification`** as a required check.
3. **Pin it to this GitHub App** as the expected source. Without pinning, anyone with
   write access can post a passing status of the same name and bypass the gate — GitHub
   will show `Required status check '…' was not set by the expected GitHub App` when the
   guardrail is working.

Because the check is posted per head SHA and the app re-runs on `synchronize`, a moved
head re-triggers verification. A check that never reports leaves the PR **blocked**
(pending), which is the desired fail-closed behavior for a required check.

## Fail-closed posture

- Unsigned / unverified / non-auths commits → `failure` (PR blocked).
- A PR with no commits → `failure`.
- Webhook HMAC invalid → `401`, no processing.
- Duplicate delivery → acknowledged, not reprocessed.
- A transient GitHub API error (e.g. a moved head SHA) is logged and the webhook is
  acked; the next `synchronize` re-runs the check.

## Enhancement: offline org-policy enforcement via an air-gapped bundle

The shipped gate proves *the commit is validly signed by an auths identity*. To also
enforce **org policy** (capability / revocation / scope) — e.g. "only agents with
`sign_commit` and not revoked may land commits" — point the app at an **air-gapped org
bundle** produced by `auths org bundle` (`AUTHS_ORG_BUNDLE`). The bundle carries the
org KEL, member KELs, off-boarding records, and pinned roots, and verifies offline
(`verify_org_bundle`), so the app needs no network access to `~/.auths`.

Integration steps (the seam is wired; this is the remaining work):

1. Embed `auths-verifier` + `auths-policy` (the minimal-dependency, no-git crates) as
   path/published deps of the app.
2. On startup, load + `verify_org_bundle` the bundle; refuse to start on a tampered or
   stale bundle (fail closed).
3. Per PR commit, fetch its signed payload from the GitHub commits API, replay the
   signer's KEL from the bundle, and run the org policy gate
   (`evaluate_with_org_policy`). A revoked signer or an out-of-scope capability →
   `failure`, with the typed reason in the check-run output.
4. Re-export the bundle (`auths org bundle`) whenever membership, scope, or the org
   policy changes; deploy the new bundle to the app.

Until this is enabled, the app enforces the signature + trailer gate above (which
already fails PRs whose commits don't verify).
