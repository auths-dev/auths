# Sharing Your Identity

Make your identity verifiable by other people and machines. Today that works two ways:
**inside a repository** (automatic, via the committed trust file) and **out-of-band**
(via an exported identity bundle). A public registry for discovery is coming soon.

## In a repository: the committed trust file

If you and a teammate work in the same repo, you may not need to share anything
explicitly. Your first signed commit in a repo pins your identity root into the
committed file `.auths/roots`. Teammates get that file when they pull, and their
`auths verify` trusts commits delegated under the roots it lists.

```bash
cat .auths/roots
```

```
# Pinned by auths init — the trusted root for this identity.
did:keri:EGOASorjKXRvDzrmdX7WdCTu-5sFxzvhdUkY8YJeQrP9
```

Review changes to `.auths/roots` like you review code — adding a root to this file is
granting trust. See [Team Workflows](../guides/git/team-workflows.md).

## Out-of-band: identity bundles

For anyone who doesn't share a repo with you (or for CI that verifies statelessly),
export a portable bundle:

```bash
auths id export-bundle --alias main --output identity-bundle.json --max-age-secs 86400
```

The bundle contains your identity DID, current public key, and key event log — enough
to verify your signatures with no access to your machine and no network. It is
freshness-bounded (`--max-age-secs`); a stale bundle fails verification rather than
silently passing.

The recipient can either verify directly against it:

```bash
auths verify HEAD --identity-bundle identity-bundle.json
auths verify release.tar.gz --identity-bundle identity-bundle.json
```

or pin you as a trusted identity from it:

```bash
auths trust pin --did did:keri:EGOASorj... --bundle identity-bundle.json
```

After pinning, your signatures verify for them with no flags at all.

!!! note "You never need to share raw key material"
    `trust pin` resolves keys from the bundle or from a locally-replayed key event
    log. The `--key <hex>` form exists only for air-gapped ceremonies.

## Link a platform account

Platform claims connect your cryptographic identity to accounts on platforms like
GitHub, so people who know your GitHub handle can find your DID.

```bash
auths id claim github
```

The command walks you through an OAuth flow: it opens your browser, authenticates you
with GitHub, and publishes a signed proof (a GitHub Gist).

## The public registry (coming soon)

```bash
auths id register
```

publishes your identity document to a registry so others can discover it by DID. The
default registry (`https://registry.auths.dev`) is not yet live — registration is
**opt-in** (`auths init --register`) and nothing is published during normal setup.
Until the registry ships, bundles and the committed `.auths/roots` file are the
supported sharing mechanisms.

## Sharing with machines: CI and agents

CI runners and automated agents should hold their own identities — not borrow a
human's credentials.

- **CI runners** get an ephemeral identity from `auths init --profile ci`, which prints
  a copy-pasteable env block (see [CI/CD](../guides/platforms/ci-cd.md)).
- **Agents** are *delegated* identifiers under your root identity — scoped and
  time-limited:

```bash
auths id agent add --label deploy-bot --key main --scope sign_commit --expires-in 604800
```

The agent gets its own `did:keri:` whose delegation is anchored in your identity's
event log. A verifier replaying the log sees exactly what you authorized and until
when. Full guide: [Agent Identities](../guides/agents/agent-identities.md).

For CI agents that need cloud access (AWS, GCP, Azure), the
[OIDC bridge](../architecture/oidc-bridge.md) exchanges the identity proof for a
standard JWT — no static API keys or long-lived service account credentials required.

## Next

To understand the cryptography behind all of this — the event log, pre-rotation, and
why no central authority is needed — continue to [How It Works](how-it-works.md).
