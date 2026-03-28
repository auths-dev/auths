# AUTHS-E4001: Unknown Identity Under Explicit Trust Policy

## Error

```
Unknown identity '{did}' and trust policy is 'explicit'
```

## What Happened

You attempted to verify a signature from an identity that is not in your local trust store, and your trust policy is set to `explicit` (which means "reject unknown identities").

## Why This Matters

The `explicit` trust policy is a security feature that prevents accepting attestations from identities you haven't explicitly authorized. This is useful in CI/CD environments where you want to ensure only specific identities can sign releases.

## How to Fix

Choose one of the following:

### Option 1: Add the identity to your trust store

```bash
auths trust add did:keri:E8iJnggDfF81VNCCSv4iN1c385y_koyaxHGRMlWjZspU
```

This will guide you through adding the identity and verifying its key.

### Option 2: Modify roots.json

Edit `.auths/roots.json` in your repository and add the identity:

```json
{
  "roots": [
    {
      "did": "did:keri:E8iJnggDfF81VNCCSv4iN1c385y_koyaxHGRMlWjZspU",
      "public_key_hex": "abcd1234..."
    }
  ]
}
```

### Option 3: Use TOFU trust policy

If you're on a TTY, switch to TOFU (Trust-On-First-Use) mode:

```bash
auths verify --trust tofu <attestation>
```

The CLI will prompt you to confirm the identity on first encounter.

### Option 4: Bypass trust with direct key

If you have the issuer's public key, provide it directly:

```bash
auths verify --issuer-pk abcd1234... <attestation>
```

## Related

- `auths trust --help` — manage your trust store
- `auths verify --help` — verification options
