# Registering on the Public Registry

Register your identity so anyone can look you up by DID, GitHub username, or package name at [public.auths.dev](https://public.auths.dev).

## Quick start

```bash
# 1. Create an identity (skip if you already have one)
auths init

# 2. Register it
auths id register
```

That's it. Your identity is now discoverable on the public registry.

## Signing and publishing artifacts

Once registered, you can sign artifacts and publish them so others can verify provenance.

```bash
# Sign a release tarball
auths artifact sign my-app-v1.0.0.tar.gz --device-key-alias main

# Publish the signature to the registry
auths artifact publish --signature my-app-v1.0.0.tar.gz.auths.json --package npm:my-app@1.0.0
```

Your signed artifacts appear on your identity's profile page on the registry.

## Verifying

Anyone can verify your artifacts without an account:

```bash
auths artifact verify my-app-v1.0.0.tar.gz
```

Or in the browser at [public.auths.dev/registry](https://public.auths.dev/registry) — search by package name, GitHub username, or DID.

---

## How it works

### What gets sent

`auths id register` reads your local identity from `~/.auths` and sends two things to the registry:

1. **Inception event** — your KERI inception event (ICP) containing your public key and DID prefix. This is the cryptographic root of your identity.
2. **Attestations** — any device authorizations or platform claims stored locally (e.g., linking your GitHub account to your DID).

The registry indexes this data so others can discover and verify you.

### What stays local

Your private keys never leave your machine. The registry only receives public keys and signed events.

### Registry endpoint

The default registry is `https://public.auths.dev`. To register on a different instance:

```bash
auths id register --registry https://my-registry.example.com
```

### Re-registering

If you've added new device authorizations or platform claims since you first registered, run `auths id register` again. The registry will update your profile with the new attestations. If your identity is already registered and nothing changed, you'll get a `409 Already registered` response.

### Publishing artifacts

`auths artifact publish` sends a signed attestation (the `.auths.json` file) to the registry's artifact index. The `--package` flag tells the registry how to categorize it:

```
--package <ecosystem>:<name>@<version>
```

Supported ecosystems: `npm`, `pypi`, `cargo`, `docker`, `go`, `maven`, `nuget`.

### What the registry stores

| Data | Source | Purpose |
|---|---|---|
| DID prefix | Inception event | Unique identity identifier |
| Public keys | KEL (Key Event Log) | Signature verification |
| Platform claims | Attestations | Link GitHub/GitLab to DID |
| Artifact signatures | Published `.auths.json` | Package provenance |

All data is cryptographically signed. The registry is an index — it doesn't grant trust, it surfaces it. Trust comes from the cryptographic chain: artifact signature &rarr; device key &rarr; identity &rarr; platform attestation.
