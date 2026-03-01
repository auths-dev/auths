# Key Compromise Recovery

End-to-end walkthrough: from "key compromised" to "identity recovered and verified."

## Background: Pre-Rotation

Auths uses KERI-style pre-rotation. When you create an identity, two Ed25519 keys are generated:

1. **Current key** - signs events now
2. **Next key** - committed to via `blake3(next_public_key)`, used for the next rotation

The commitment hash is stored in the Key Event Log (KEL). The actual next key is stored only in your local keychain. This means an attacker who steals your current key **cannot rotate** your identity because they don't have the pre-committed next key.

## Step 1: Create an Identity

```bash
auths id create --alias my-key
```

This generates:
- A current signing keypair stored under alias `my-key`
- A next keypair stored under alias `my-key--next-0`
- An inception event (ICP) in the KEL with:
  - `k`: your current public key
  - `n`: `blake3(next_public_key)` — the pre-rotation commitment

## Step 2: Compromise Scenario

An attacker gains access to your current signing key (`my-key`). They can:

| Action | Can attacker do it? | Why? |
|--------|-------------------|------|
| Sign with the old key | Yes | They have the key material |
| Create valid interactions (IXN) | Yes | IXN events are signed by the current key |
| Rotate the identity | **No** | Rotation requires the pre-committed next key |
| Forge a rotation event | **No** | `blake3(attacker_key) != stored_commitment` |
| Reorder past events | **No** | Hash chain (`p` field) prevents reordering |
| Replay old events | **No** | Sequence numbers prevent replay |

The critical protection: rotation events are signed by the **new** key and verified against the pre-rotation commitment. Without the pre-committed next key, the attacker is locked out of identity control.

## Step 3: Why the Attacker's Rotation Fails

If the attacker tries to rotate with their own key:

```
1. Attacker generates a new keypair
2. Attacker builds a RotEvent with their key in `k`
3. Registry checks: blake3(attacker_public_key) == stored_commitment?
4. Check FAILS → CommitmentMismatch error
5. Rotation rejected
```

The `verify_commitment()` function compares:
```
blake3(attacker_key) → "EXyz..."  (attacker's hash)
stored commitment    → "EO8C..."  (legitimate next key's hash)
```

These will never match unless the attacker has the exact pre-committed next key.

## Step 4: Legitimate Recovery

The legitimate key holder rotates the identity:

```bash
auths id rotate --alias my-key
```

This succeeds because:

1. Loads the pre-committed next key from keychain (`my-key--next-0`)
2. Verifies `blake3(next_key) == stored_commitment` — **matches**
3. Generates a new next key for future rotation
4. Creates a rotation event (ROT) signed by the next key
5. Appends the ROT to the KEL
6. Updates the keychain with the new current and next keys

After rotation:
- The compromised key is no longer the current key
- A new pre-rotation commitment is in place
- The identity continues under the legitimate holder's control

## Step 5: Re-Authorize Devices

After rotation, existing device attestations reference the old key. Re-link devices:

```bash
auths device link \
  --identity-key-alias my-key-rotated \
  --device-key-alias device-key \
  --device-did "$DEVICE_DID" \
  --note "Re-linked after key rotation"
```

## Step 6: Verify Recovery

Inspect the KEL to confirm the full event history:

```bash
auths id inspect --alias my-key-rotated
```

This replays the full KEL and verifies:
- Every event has a valid SAID (self-addressing identifier)
- Every signature is valid
- Every rotation satisfies its pre-rotation commitment
- The hash chain (`p` field) is unbroken
- Sequence numbers are contiguous

## What Happens with Multiple Rotations

Each rotation creates a new pre-rotation commitment. The chain looks like:

```
ICP (seq 0):  k=key₀  n=blake3(key₁)
ROT (seq 1):  k=key₁  n=blake3(key₂)  — signed by key₁
ROT (seq 2):  k=key₂  n=blake3(key₃)  — signed by key₂
IXN (seq 3):  ...                       — signed by key₂
```

At any point, only the holder of the pre-committed next key can perform the next rotation.

## Abandonment

If you want to permanently freeze an identity (no future rotations), rotate with an empty next commitment:

```
ROT (seq N):  k=keyₙ  n=[]  — identity abandoned
```

After abandonment, `can_rotate()` returns false and all rotation attempts fail with `IdentityAbandoned`.
