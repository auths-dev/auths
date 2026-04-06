# Signed Tool-Call Audit Log

Every tool call your agent makes, cryptographically signed.

When your PydanticAI agent calls `read_csv`, `summarize`, or `send_notification`, this demo produces a signed envelope for each call — stamped with a unique Ed25519 identity — and appends it to an append-only audit log. The log can be verified offline at any time: if any envelope was tampered with or injected after the fact, verification fails.

**Why this matters:** Compliance teams ask "prove the AI didn't hallucinate the send." This answers it.

---

## Quick start

```bash
# 1. Install dependencies
uv sync

# 2. Set your OpenAI key
export OPENAI_API_KEY=sk-...

# 3. Run the agent
uv run run-agent "read data/sales.csv, summarize it, and notify the team"
```

Expected output:

```
Agent identity: did:key:z6Mk...
Task: read data/sales.csv, summarize it, and notify the team

[agent] Calling: read_csv(path='data/sales.csv')           ✓ signed
[agent] Calling: summarize(data='month, product, rev...')  ✓ signed
[agent] Calling: send_notification(channel='team', ...)    ✓ signed

Result: I've read the sales data and sent the summary to the team.

✓ 3 action(s) signed by did:key:z6Mk...
Run verify-log to verify the audit trail.
```

## Verify the audit trail

```bash
uv run verify-log
```

```
Verifying audit trail...
Signer: did:key:z6Mk...

 #  Tool               Valid  Timestamp
 1  read_csv           ✓      2026-04-06 14:32:11
 2  summarize          ✓      2026-04-06 14:32:12
 3  send_notification  ✓      2026-04-06 14:32:13

✓ 3/3 signatures valid — audit trail is intact.
```

If any entry is tampered with, verification prints `✗` for that row and exits with code 1.

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  1. Agent starts                                             │
│     generate_inmemory_keypair() → (priv, pub, did:key:z6Mk) │
│     Saves pub + did to .agent-key.json                       │
├─────────────────────────────────────────────────────────────┤
│  2. Tool call intercepted                                    │
│     sign_action(priv, "tool_call", {tool, args}, did)        │
│     → ActionEnvelope JSON (Ed25519 signed)                   │
│     → appended to audit.jsonl                                │
├─────────────────────────────────────────────────────────────┤
│  3. Verification                                             │
│     verify_action_envelope(envelope_json, pub_hex)           │
│     → VerificationResult.valid = True / False                │
└─────────────────────────────────────────────────────────────┘
```

The signing uses the `auths` Python SDK — a PyO3 Rust binding — so no subprocess calls to the CLI.

## What's in `audit.jsonl`

Each line is one JSON envelope:

```json
{
  "version": "1.0",
  "action_type": "tool_call",
  "identity": "did:key:z6MkqQ...",
  "payload": "{\"args\":{\"path\":\"data/sales.csv\"},\"tool\":\"read_csv\"}",
  "timestamp": "2026-04-06T14:32:11.482Z",
  "signature": "a3f9b2c1...",
  "attestation_chain": null,
  "environment": null
}
```

The `payload` field is signed — any change to `tool`, `args`, or the envelope itself breaks verification.

---

## Run the tests

```bash
uv run pytest
```

The tests cover signing, tamper detection, and all four tool functions — no LLM or network required.

---

## Next steps

- **[Demo #2: Delegation chain](../multi_agent/)** — orchestrator provisions sub-agents at runtime; each sub-agent's audit trail is bound to the parent identity
- **[auths Python SDK docs](https://docs.auths.dev/sdk/python)**
- **[auths init --profile agent](https://docs.auths.dev/guides/agent-identity)** — replace the in-memory keypair with a persistent, revocable agent identity
