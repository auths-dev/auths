# Agent demos — proving the wedge

Five demo PRDs, each proving **one** property of the auths agent wedge that no incumbent
can structurally match, in a scenario a real 2026 engineer is already losing sleep over.
Each is **claimify-ready**: `recurve init --from-prd <slug>.md` decomposes its
functional-requirements-as-claims into a draft ledger, which then arms → baselines →
burns down against `../auths`, exactly like the five shipped demos in `auths-demos/`.

These are the *dramatization* layer on top of the aspirational capability claims: the
[`aspirational_claims`](../aspirational_claims/) burndown proves each **primitive** at the
probe level (`OPS-1`, `AGT-1`, `AGT-4`, `AGT-3`, `AGT-2`); a demo turns "the probe is
green" into "the story is believable" — and several demos are the *forcing function* that
drags a parked primitive into an end-to-end build.

## The set

| Demo | Proves | Incumbent it beats | Reuses claim | Maturity |
| --- | --- | --- | --- | --- |
| [`the-agent-that-wouldnt-die`](the-agent-that-wouldnt-die.md) | instant fleet-wide revocation, no propagation window, replay-resistant | Sigstore (cert expiry), OIDC (token windows) | `OPS-1` | **near-term** |
| [`the-agent-with-a-credit-limit`](the-agent-with-a-credit-limit.md) | un-exceedable quantitative caps enforced at verify | API keys, OAuth scopes (boolean), app limiters | `AGT-4` | **near-term** |
| [`the-intern-that-couldnt`](the-intern-that-couldnt.md) | full-chain attenuation as physics, not policy | OAuth scopes, IAM roles, API keys | `AGT-1` | **mid** (CLI wiring) |
| [`two-agents-who-never-met`](two-agents-who-never-met.md) | cross-org scoped trust in one round trip, no IdP, mutually revocable | OAuth federation, Okta/Auth0 B2B | `AGT-3` (live leg) | **spiked** |
| [`was-a-human-there`](was-a-human-there.md) | verifiable human-present custody, biometric never leaves device | Apple enclave (no 3rd-party class), OIDC amr/acr | `AGT-2` | **spiked / research** |

## Build order

Tractable + visceral first, so wins bank before the research-grade pair:

1. **`the-agent-that-wouldnt-die`** — the single most universally-felt claim ("we can't
   kill a compromised agent fast enough today") and the sharpest vs the incumbents. Builds
   the global resolution/propagation surface `OPS-1` flagged as missing.
2. **`the-agent-with-a-credit-limit`** — the most commercially concrete (agent payments),
   and `AGT-4` is a contained build (quantitative predicate + counter-bound verify).
3. **`the-intern-that-couldnt`** — forces the `AGT-1` end-to-end wiring. *Note:* the
   PRD-writing pass found the codebase has moved since the 2026-06-14 baseline — the
   library scope gate now reaches via delegator-aware lookup, and the CLI is more wired
   than the RED text implies, so this may be closer to closable than it looks.
4. **`two-agents-who-never-met`** — highest strategic payoff (network effect), but rides on
   the `AGT-3` *live* mutual-introduction runtime, which does not exist yet.
5. **`was-a-human-there`** — highest societal/compliance payoff, but research-grade: needs
   the Secure-Enclave simulator and is the most likely to PARK. Never stub the enclave.

## Folding one into recurve

```
recurve init --from-prd roadmap/agent_demos/<slug>.md --target ../auths --suite <slug>
# review the draft claims → arm (author probes + traps) → baseline → burn down
```

Each PRD's §9 "Recurve gap sketch" is the draft-claim seed (ids like `AGENT-KILL-*`,
`AGENT-CAP-*`, `AGENT-ATTEN-*`, `AGENT-XORG-*`, `AGENT-HUMAN-*`), with proposed probe names
and accept + adversarial paths already specified. Each demo sculpts `../auths` and
federates with the existing gates, exactly as the shipped demos do.
