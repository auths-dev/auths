# Platform blockers: missing pieces between the vision and the code

**Provenance.** These findings come from an adversarial planning review of Demo 3
("Drop the Laptop in the River", `auths-demos/.flow/specs/fn-7.md`), 2026-06-11,
verified against platform source at rev `861c430f`. Every claim below was checked
against the code, not doc comments. Line numbers are accurate at that rev; re-grep
for the quoted snippets if the files have moved.

**How to use this document.** Each item is self-contained: problem → why it
matters in plain language → evidence (file:line + snippet) → suggested change →
acceptance criteria. An agent can pick up any single item and build it without
reading the others, except where a dependency is called out explicitly.

**Severity legend.**
- 🔴 **Breaks a core product promise** — the headline KERI story does not survive this gap.
- 🟡 **Blocks a major workflow** — feature exists in the vision/docs but cannot be exercised.
- 🟢 **Sharp edge** — works, but silently misleads or fails unsafely.

| # | Item | Severity |
|---|------|----------|
| 1A | Pre-committed next key has no escrow path | 🔴 |
| 1B | Phone-driven shared-KEL rotation blocked on CESR indexed signatures | 🟡 |
| 1C | LAN device recovery unsupported | 🟡 |
| 2A | Root rotation retroactively invalidates all prior commit history | 🔴 |
| 2B | Root signers skip revocation/rotation ordering entirely | 🔴 (same fix as 2A) |
| 3A | `Auths-Anchor-Seq` is self-asserted and forgeable | 🔴 |
| 3B | Stale trailer file silently mis-orders honest commits | 🟢 |
| 4A | `auths pair --offline` cannot complete a pairing | 🟡 |
| 4B | No loopback bind for the pairing daemon | 🟢 |
| 4C | Paired devices are islands — no post-pairing KEL sync channel | 🟡 |
| 4D | Cross-machine registry propagation: nothing pushes | 🟡 |
| 5A | Auth challenges can be signed but not verified offline | 🟡 |
| 6A | Mobile FFI has no KEL read surface | 🟡 |
| 6B | `build-xcframework.sh` swallows per-target build failures | 🟢 |

---

## Theme 1 — Key lifecycle & recovery

The product's signature story is "lose a device, lose nothing: rotate and move on."
Today, every path that would make that true is missing or blocked.

### 1A. The pre-committed next key has no escrow path — losing the device loses the next key too 🔴

**Problem.** KERI's recovery guarantee rests on pre-rotation: at inception you
commit to the *digest* of your next key, and the next private key is supposed to
live somewhere safer than the device that signs daily. In Auths, the next key is
generated and stored **in the same keychain file as the current key**, and rotation
can only read it from that local keychain:

`crates/auths-sdk/src/domains/identity/rotation.rs:375-392`
```rust
fn retrieve_precommitted_key(
    did: &IdentityDID,
    current_alias: &KeyAlias,
    state: &KeyState,
    ctx: &AuthsContext,
) -> Result<(Zeroizing<Vec<u8>>, KeyAlias), RotationError> {
    let target_alias = KeyAlias::new_unchecked(format!(
        "{}--next-{}",
        current_alias, state.last_establishment_sequence
    ));

    let (did_check, _role, encrypted_next) =
        ctx.key_storage.load_key(&target_alias).map_err(|e| {
            RotationError::KeyNotFound(format!(
                "pre-committed next key '{}' not found: {e}",
                target_alias
            ))
        })?;
```

So if the laptop (keychain and all) is destroyed, **rotation is impossible from any
machine** — `auths id rotate` on a fresh machine fails with `KeyNotFound` even when
it can read the shared registry. The same applies to `auths device remove`, which is
single-author and needs the root's signing key
(`crates/auths-cli/src/commands/device/authorization.rs:306-309`):

```rust
DeviceSubcommand::Remove { device_did, key } => {
    // Remove = revoke the device's KERI delegation: the root anchors a
    // revocation marker so verifiers stop honouring the device. Single-
    // author (the root's key signs); the device's key is not needed.
```

**Layman implication.** The pitch is "your identity survives the death of your
laptop." The reality is: if your laptop dies, the key that would rescue your
identity died with it. Recovery today means "you had a full backup of the
keychain," which is no better than the systems Auths claims to replace.

**Suggested change.** Add a **recovery-kit export/import** flow:

1. `auths id create` (and every rotation) offers/performs an export of *only* the
   encrypted pre-committed next key: `auths key export-next --out recovery-kit.enc`
   (contents: the `<alias>--next-<seq>` keychain entry + DID + sequence metadata,
   passphrase-encrypted; printable as a QR for paper backup).
2. `auths id rotate --recovery-kit recovery-kit.enc` on any machine: imports the
   next key into the local keychain under the expected alias, then proceeds through
   the existing `retrieve_precommitted_key` path unchanged.
3. In `retrieve_precommitted_key`, on `KeyNotFound`, return a purposeful error that
   names the recovery-kit path (today the error is a bare "not found").

The minimal seam: a new function in
`crates/auths-sdk/src/domains/identity/rotation.rs` that hydrates the keychain
from a kit file before `resolve_rotation_context` runs, plus CLI surface in
`crates/auths-cli/src/commands/id/identity.rs` (`IdSubcommand::Rotate` arm, around
line 514) and a new `key export-next` subcommand.

**Acceptance.**
- A fresh machine with only `recovery-kit.enc` + the shared registry can run
  `auths id rotate --recovery-kit …` successfully; the resulting `rot` validates.
- The kit file never contains the *current* signing key.
- `auths id rotate` on a machine without the next key fails with an error that
  names the recovery-kit mechanism.

### 1B. Phone-driven shared-KEL rotation is scaffolding, blocked on CESR indexed signatures 🟡

**Problem.** The vision ("from the phone, rotate the identity's keys") is
explicitly stubbed:

`crates/auths-mobile-ffi/src/shared_kel_context.rs:14-20`
```text
**Status**: scaffolding only. End-to-end shared-KEL rotation is
blocked on CESR indexed-signature support in `auths-keri::validate`
(the validator rejects asymmetric rotations today). Callers that
invoke `build_shared_kel_rot_payload` during Stage-1 development
receive `MobileError::PairingFailed(…)` with a clear message;
```

**Layman implication.** The most dramatic recovery story — your phone, the
surviving device, presses one button and rotates the compromised identity — cannot
happen. The phone can pair and sign, but it cannot change the identity's keys.

**Suggested change.** Two pieces, in order:
1. **CESR indexed-signature support in `auths-keri::validate`** so a rotation event
   signed by one of N controllers (an indexed signature) validates. This is the
   named blocker; search `crates/auths-keri/src/` for the validation path that
   rejects asymmetric rotations.
2. **A daemon endpoint to receive the signed `rot`** — the phone has no write path
   to the registry (see 4C). Add a `POST /kel/events` route to
   `crates/auths-pairing-daemon/src/router.rs` that validates the event against the
   current KEL and appends it to the registry.

Then unstub `build_shared_kel_rot_payload` / `assemble_shared_kel_rot` (the
two-step SE signing dance is already designed; only the validator and transport are
missing).

**Acceptance.** A paired controller device can produce a `rot` via the FFI
two-step, POST it, and `auths id show` / KEL replay reflects the rotation; the
validator accepts the indexed signature.

### 1C. LAN device recovery is a hard error 🟡

**Problem.** `crates/auths-cli/src/commands/device/pair/lan.rs:47-54`
```rust
if let Some(ref old_did) = recover {
    let _ = old_did;
    return Err(anyhow::anyhow!(
        "Device recovery (--recover) over LAN is not yet supported. Use online recovery \
         (`auths pair --recover <did> --registry <url>`), or remove the lost device with \
         `auths device remove <did>` and pair a replacement."
    ));
}
```

**Layman implication.** Replacing a lost phone requires a registry *server* —
the offline-first, no-server promise breaks exactly when the user is most
stressed (they just lost a device).

**Suggested change.** The LAN path already carries `recovery_target` in
`CreateSessionRequest` (lan.rs:91 populates it). Implement the
pair-replacement-then-revoke flow over the LAN session: on successful pairing
where `recovery_target` is set, anchor the new device's delegation *and* the old
device's revocation in one sequence (reuse
`auths_sdk::domains::device::remove_device` after the pairing attestation lands).

**Acceptance.** `auths pair --recover <old-did>` (no `--registry`) completes over
LAN; `auths device list` shows the old device revoked and the new device active.

---

## Theme 2 — Verification semantics: history must survive rotation

### 2A. Rotating a root identity retroactively invalidates its entire commit history 🔴

**Problem.** The KERI promise is "old commits still verify; the verifier reports
which (now-superseded) key era signed them." The verifier does not do this. It
checks the SSH signature against **only the current key**, and a signature by any
prior establishment key is mapped to a *rejection*:

`crates/auths-verifier/src/commit_kel.rs:606-619` (current-key-only check)
```rust
let Some(current_cesr) = device_state.current_keys.first() else { … };
…
match verify_commit_signature(
    commit_bytes,
    std::slice::from_ref(&current_pk),   // ← only the CURRENT key
    provider,
    None,
)
```

`crates/auths-verifier/src/commit_kel.rs:720-740` — `establishment_keys` is used
only to pick **which rejection** to emit:
```rust
if envelope.public_key != *current_pk
    && establishment_keys(device_kel).contains(&envelope.public_key)
{
    return CommitVerdict::SignedBySupersededKey;
}
CommitVerdict::SignerKeyMismatch
```

And the CLI treats that as invalid —
`crates/auths-cli/src/commands/verify_commit.rs:635-641`:
```rust
CommitVerdict::SignedBySupersededKey => {
    result.ssh_valid = Some(false);
    result.error = Some(
        "Commit was signed by a superseded device key (the device has since rotated)"
            .to_string(),
    );
}
```

Because the machine that runs `auths id create` signs **directly as root**
(`crates/auths-sdk/src/domains/identity/local.rs:55-64`; confirmed by
`crates/auths-sdk/src/domains/identity/service.rs:130` — "The CI identity is a
root identity signing directly"), this is the *default* configuration. Rotate
your key once and every commit you ever signed goes red.

**Layman implication.** The one thing this product exists to fix — "key rotation
is routine, your history is safe" — is inverted. Today, rotation is the apocalypse
the docs say it prevents: it bricks your past instead of your future.

**Suggested change.** Era-aware verification in `authorize_commit`
(`commit_kel.rs:538-638`). When the signature matches a superseded establishment
key, order the commit's in-band position against the **rotation** position (the
same trick already used for revocations):

1. Generalize `revocation_position` (`commit_kel.rs:190-198`) with a sibling
   `supersession_position(device_kel, signer_key) -> Option<u128>` — the sequence
   of the `rot`/`drt` event that rotated the signer key away.
2. In `classify_unknown_signer`, when the key is a superseded establishment key:
   - `parse_anchor_seq(commit_bytes) < supersession_position` → return
     `CommitVerdict::Valid { … }` carrying era metadata (suggested: extend `Valid`
     with `key_era: Option<u128>` rather than adding a parallel "ValidSuperseded"
     verdict, so downstream `is_valid()` callers keep working).
   - `>= supersession_position`, or no anchor seq → keep
     `SignedBySupersededKey` (now a *meaningful* rejection: "signed by a key after
     it was rotated away").
3. CLI rendering (`verify_commit.rs`): `Valid` with `key_era` prints
   "valid (signed under key era N, since rotated)" — green, with the era note.

Note `classify_unknown_signer` will need `root_kel`/positions threaded in; it
currently receives only `commit_bytes`, `device_kel`, `current_pk`
(`commit_kel.rs:720`).

**Dependency.** The ordering input is the self-asserted anchor seq — see 3A. Land
2A first (it makes the semantics right against honest signers), but 3A is what
makes it hold against adversaries.

**Acceptance.**
- A commit signed pre-rotation by a root identity verifies `valid: true` after
  one or more rotations, with the era reported.
- A commit signed by the old key *at a position at/after the rotation* still
  yields `SignedBySupersededKey`.
- Existing tests in `commit_kel.rs` (`commit_before_revocation_still_valid` etc.)
  gain rotation-ordering twins.

### 2B. Root signers skip revocation/rotation ordering entirely 🔴 (folded into 2A)

**Problem.** `reject_unauthorized_delegate` returns early for the root:

`crates/auths-verifier/src/commit_kel.rs:659-662`
```rust
let root_signs_directly = device_prefix == *root_prefix && device_state.delegator.is_none();
if root_signs_directly {
    return None;     // ← revocation/ordering checks never run for root signers
}
```

So `SignedAfterRevocation` — the precise, ordered rejection — is **unreachable**
for the default (root-signing) configuration; root-key misuse can only ever
surface as the blunt `SignedBySupersededKey`. The fix is the same
supersession-ordering logic as 2A; just ensure it runs on the root path too.

---

## Theme 3 — Revocation ordering security

### 3A. `Auths-Anchor-Seq` is self-asserted: a thief forges a low number and stays green 🔴

**Problem.** The verifier orders a commit against a revocation using a trailer
**the signer writes and signs**:

`crates/auths-verifier/src/commit_kel.rs:224-234`
```rust
fn parse_anchor_seq(commit_bytes: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(commit_bytes).ok()?;
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(ANCHOR_SEQ_TRAILER)?;
        …
```

`crates/auths-verifier/src/commit_kel.rs:318-331`
```rust
match (revocation, signing_anchor) {
    (None, _) => RevocationOrdering::NotRevoked,
    (Some(_), None) => RevocationOrdering::RevokedUnknownPosition,
    (Some(rev), Some(sign)) if sign < rev => RevocationOrdering::SignedBefore,  // ← attacker picks `sign`
    …
```

An attacker holding a stolen (later revoked) device key simply stamps
`Auths-Anchor-Seq: 0` on their commit. `
