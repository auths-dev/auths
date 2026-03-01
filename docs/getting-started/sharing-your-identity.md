# Sharing Your Identity

Register your identity on a public registry so others can discover and verify your work.

## Register with the Auths Registry

If you ran `auths init --profile developer` interactively, your identity was registered automatically during setup. To register manually or re-register with a different registry:

```bash
auths id register
```

```
Success! Identity registered at https://auths-registry.fly.dev
DID: EAbcd1234...
```

By default this publishes to the Auths public registry. To use a different registry:

```bash
auths id register --registry https://your-registry.example.com
```

Registration uploads your identity document and device attestations so that anyone with your DID can look up your public key and verify your signatures.

## Link a platform account

Platform claims connect your cryptographic identity to accounts on platforms like GitHub. This makes it possible to look up an Auths identity by a GitHub username instead of a raw DID.

During `auths init`, you are offered the option to link GitHub. To add a claim after setup:

```bash
auths id claim github
```

The command walks you through an OAuth flow: it opens your browser, authenticates you with GitHub, publishes a signed proof (a GitHub Gist), and submits the claim to the registry.

## What are attestations?

Attestations are the foundation of trust in Auths. An attestation is a signed JSON document that records a specific authorization, such as "identity X authorizes device Y to sign commits."

Every attestation contains:

| Field | Purpose |
|-------|---------|
| `issuer` | The `did:keri` identity that granted the authorization |
| `subject` | The `did:key` device being authorized |
| `device_public_key` | The raw Ed25519 public key of the authorized device |
| `identity_signature` | Signature from the identity controller |
| `device_signature` | Counter-signature from the device |
| `capabilities` | What the device is allowed to do (e.g., `sign_commit`) |
| `expires_at` | Optional expiration timestamp |

Attestations are stored as Git refs under `refs/auths/` in the identity repository at `~/.auths`. They are dual-signed -- both the identity controller and the device must sign -- so a compromised device alone cannot forge an authorization.

### Why attestations matter

Without attestations, a public key proves nothing on its own. Anyone can generate a keypair. Attestations create a verifiable chain from a long-lived identity to an ephemeral device key, answering the question: "Was this device actually authorized by the person who controls this identity?"

When someone verifies your commit, the verification checks:

1. **SSH signature** -- the commit was signed by a specific public key
2. **Attestation chain** -- that public key was authorized by your identity
3. **Identity** -- the identity is registered and discoverable

This three-layer check means a verifier does not need to trust a central authority. They can independently verify the entire chain using only Git data and the public registry.

## View your attestations

List all devices authorized under your identity:

```bash
auths device list
```

To include revoked or expired devices:

```bash
auths device list --include-revoked
```

## Export an identity bundle for CI

For CI/CD pipelines that need to verify commits without access to your identity repository, export a portable bundle:

```bash
auths id export-bundle --alias main --output identity-bundle.json --max-age-secs 86400
```

The bundle contains your public key and attestation chain. Pass it to `auths verify` in CI:

```bash
auths verify HEAD --identity-bundle identity-bundle.json
```

## Next: How It Works

You have a signed identity, signed commits, and a public registry entry. To understand the cryptographic primitives and storage model behind all of this, continue to the [How It Works](how-it-works.md) section.
