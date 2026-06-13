# Blockers: what stands between Auths and its revolutionary claims

**Status:** living document. Written 2026-06-11 against the workspace at that date
(spot-check line numbers before editing — they drift).
**Audience:** an engineer or LLM session picking up any one theme and building the fix.
Each theme is self-contained: the claim, the code reality (with file:line and snippets),
what it costs in the real world if unsolved, what it unlocks once solved, and a concrete
suggested design with acceptance criteria.

**Context:** Auths' paradigm — *identity is an event log, keys are rotatable entries* —
is sound (KERI). The engineering is high quality. But several headline properties are
currently aspirational: they hold against polite actors, not adversaries, or they hold
in the delegated-device path but not the root path, or they exist as scaffolding. This
document is the gap list. We are pre-launch with zero users (see root `CLAUDE.md`):
no backward-compatibility constraints — rip and replace freely.

Severity ordering: Theme 1 and 2 are existential to the pitch. Themes 3–5 block the
multi-device story. Themes 6–7 are enablers.

---

## Theme 1 — Revocation ordering is self-asserted (the verifier trusts the attacker)

### The claim
"If a thief resurrects the laptop and signs something *after* the rotation, verification
flags it — the KEL proves that key's authority had ended." (`auths-demos/demo_vision.md`,
Demo 3.) This is the single most dramatic security property in the pitch.

### The code reality
A commit's signing position is carried in the `Auths-Anchor-Seq` trailer — written by
the **signer**, covered by the **signer's own signature**, and trusted verbatim by the
verifier.

`crates/auths-verifier/src/commit_kel.rs:224-234` — the verifier parses the claimed
position straight out of the commit body:

```rust
fn parse_anchor_seq(commit_bytes: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(commit_bytes).ok()?;
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(ANCHOR_SEQ_TRAILER)?;
        rest.trim_start().strip_prefix(':')?.trim().parse::<u128>().ok()
    })
}
```

`crates/auths-verifier/src/commit_kel.rs:318-331` — ordering against the revocation
uses only that claimed number:

```rust
fn classify_revocation(signing_anchor: Option<u128>, revocation: Option<u128>) -> RevocationOrdering {
    match (revocation, signing_anchor) {
        (None, _) => RevocationOrdering::NotRevoked,
        (Some(_), None) => RevocationOrdering::RevokedUnknownPosition,
        (Some(rev), Some(sign)) if sign < rev => RevocationOrdering::SignedBefore, // attacker picks `sign`
        (Some(rev), Some(sign)) => RevocationOrdering::SignedAfter { signed_at: sign, revoked_at: rev },
    }
}
```

A thief holding a stolen (revoked) device key simply stamps `Auths-Anchor-Seq: 0` and
their post-revocation commit classifies `SignedBefore` → checked against the device's
current key (which the thief holds, and which never rotated because the device is dead)
→ **`CommitVerdict::Valid`**. The trailer is inside the signed payload, so the thief's
own signature legitimizes the forged position.

The honest path stamps the trailer from a *static file* refreshed only when a KEL-advancing
command runs on that machine (`crates/auths-sdk/src/workflows/commit_hooks.rs:195-206`,
`refresh_commit_trailers`) — so the
