# GitHub Claims

Link your GitHub account to your Auths cryptographic identity. This creates a publicly verifiable proof that a specific GitHub username is controlled by the same person who holds the corresponding `did:keri` identity.

## Prerequisites

- An initialized Auths identity (`auths init`)
- Your identity registered with the Auths registry (`auths id register`)

## How it works

The claim flow uses the [OAuth Device Flow (RFC 8628)](https://datatracker.ietf.org/doc/html/rfc8628) so the CLI never handles your GitHub password. The process:

1. **Authenticate via device flow** -- Auths requests a device code from GitHub using the `gist read:user` scopes. You authorize in your browser.
2. **Create a signed claim** -- Auths builds a JSON document containing your GitHub username, your controller DID, and a timestamp, then signs it with your identity key using Ed25519. The claim is canonicalized with [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) before signing to ensure deterministic verification.
3. **Publish proof Gist** -- The signed claim is uploaded as a public GitHub Gist (`auths-proof.json`). This Gist persists as a permanent, publicly verifiable anchor even after the OAuth token expires.
4. **Submit to registry** -- The proof URL is submitted to the Auths registry, which indexes the claim linking your platform identity to your DID.

## Claiming your GitHub account

```bash
auths id claim github
```

The CLI will:

1. Open your browser to `https://github.com/login/device` and display a one-time code.
2. Wait for you to enter the code and authorize the Auths GitHub App.
3. Fetch your GitHub username from the API.
4. Sign a platform claim linking `github:@<username>` to your `did:keri:E...`.
5. Publish the signed claim as a public Gist.
6. Submit the Gist URL to the registry for indexing.

On success you will see:

```
Platform claim indexed: github @<username> -> did:keri:E...
```

### Custom registry URL

By default, claims are submitted to `https://auths-registry.fly.dev`. To use a different registry:

```bash
auths id claim github --registry https://your-registry.example.com
```

## What the attestation proves

The published Gist contains a JSON document like this:

```json
{
  "type": "platform_claim",
  "platform": "github",
  "namespace": "octocat",
  "did": "did:keri:EaBcDeFgHiJkLmNoPqRsTuVwXyZ...",
  "timestamp": "2026-03-01T12:00:00+00:00",
  "signature": "<base64url-encoded Ed25519 signature>"
}
```

This proves:

- **Account ownership** -- At the time of signing, the person holding the private key for `did:keri:E...` also controlled the GitHub account `@octocat` (they had a valid OAuth token with `gist` and `read:user` scopes).
- **Cryptographic binding** -- The signature covers the canonicalized claim (excluding the `signature` field itself). Anyone with the DID's public key can verify the signature independently.
- **Permanent anchor** -- The Gist URL is publicly accessible. Even if the OAuth token is revoked, the signed claim remains verifiable using only the DID's public key.

The claim does **not** prove continuous ownership. If the GitHub account changes hands, the claim remains valid because it is bound to a point-in-time assertion. Future revocation would require a new signed statement.

## Verifying a claim

Anyone can verify a claim by:

1. Fetching the Gist at the proof URL.
2. Removing the `signature` field from the JSON.
3. Canonicalizing the remaining JSON with JCS (RFC 8785).
4. Verifying the Ed25519 signature against the public key derived from the `did` field.

## JSON output

For scripting and automation, use `--json` to get machine-readable output:

```bash
auths id claim github --json
```

```json
{
  "status": "success",
  "command": "id claim",
  "data": {
    "platform": "github",
    "namespace": "octocat",
    "did": "did:keri:EaBcDeFgHiJkLmNoPqRsTuVwXyZ..."
  }
}
```
