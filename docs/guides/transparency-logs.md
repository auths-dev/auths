# Transparency Logs

Auths uses transparency logs to create an immutable, publicly-auditable record of every artifact attestation. When you sign an artifact with `auths artifact sign --ci`, the attestation is submitted to a transparency log and an inclusion proof is embedded in the `.auths.json` file. Verifiers check this proof to confirm the attestation was logged.

## Default: Sigstore Rekor

Out of the box, auths submits attestations to [Sigstore's Rekor](https://rekor.sigstore.dev), a free public transparency log operated by the Linux Foundation. No setup required.

```bash
# Signs and submits to Rekor automatically
auths artifact sign release.tar.gz --ci --commit $(git rev-parse HEAD)
```

## Choosing a Backend

| Backend | When to use | Ops burden | Privacy |
|---|---|---|---|
| **Public Rekor** (default) | Open source projects, shared monitoring | None | Attestations are public |
| **Private Rekor** | Enterprise, private repos | You run it | Your data, your infra |
| **--allow-unlogged** | Local testing only | None | No transparency guarantees |

## Using a Private Rekor Instance

Deploy your own Rekor instance, then register it:

```bash
# Add your private Rekor to trust config
auths trust log add \
  --id my-rekor \
  --key <hex-encoded-public-key> \
  --origin "rekor.example.com - <tree-id>" \
  --url https://rekor.example.com

# Sign using your private instance
auths artifact sign release.tar.gz --ci --commit HEAD --log my-rekor
```

## Local Testing Without a Log

For development and testing, skip the transparency log:

```bash
auths artifact sign test.txt --ci --commit HEAD --allow-unlogged
```

This produces an attestation without transparency data. Verifiers reject unlogged attestations by default:

```bash
# This fails:
auths artifact verify test.txt

# This succeeds with a warning:
auths artifact verify test.txt --allow-unlogged
```

## Trust Configuration

Trust config lives at `~/.auths/trust_config.json`. If the file doesn't exist, compiled-in defaults are used (Rekor production shard).

```json
{
  "default_log": "sigstore-rekor",
  "logs": {
    "sigstore-rekor": {
      "log_public_key": "0000000000000000000000000000000000000000000000000000000000000000",
      "log_origin": "rekor.sigstore.dev - 1193050959916656506",
      "witnesses": [],
      "signature_algorithm": "ecdsa_p256"
    }
  }
}
```

## Tradeoffs

**Public Rekor:** You get shared monitoring (the Sigstore community watches for log misbehavior), zero operational burden, and broad ecosystem compatibility. You accept a dependency on Sigstore infrastructure and the Linux Foundation's governance.

**Private Rekor:** Full control over your log, your data stays on your infrastructure, but you're responsible for uptime, monitoring, and key management.

**No log (--allow-unlogged):** No transparency guarantees. Suitable for isolated development environments. Not suitable for production artifacts.
