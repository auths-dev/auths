# Agent Swarm — Delegation Chain

Every sub-agent in a governed swarm. Every action traceable to a human.

Multi-agent systems have no identity model today. Sub-agents run with whatever credentials the orchestrator passes them. There's no way to scope what a sub-agent can do, or prove that its outputs were authorized by anyone in particular.

This demo builds a three-layer identity tree — human → orchestrator → sub-agents — where each level's authority is cryptographically delegated. Every tool call is signed by the sub-agent that made it, and every sub-agent carries a delegation token proving the orchestrator authorized it. The full chain is verifiable offline.

**Why this matters:** This is the first real answer to "how do you govern a swarm."

---

## Quick start

```bash
# 1. Install dependencies
uv sync

# 2. Set your OpenAI key
export OPENAI_API_KEY=sk-...

# 3. Run the swarm
uv run run-swarm "read data/sales.csv, analyze it, and notify the team"
```

Expected output:

```
Swarm identity chain:
  Human          did:key:z6MkuXq...
  └─ Orchestrator  did:key:z6MkpRn...  [delegate, read_data, analyze, notify]
       ├─ DataAgent      did:key:z6MkiHa...  [read_data]
       ├─ AnalysisAgent  did:key:z6MktBc...  [analyze]
       └─ NotifyAgent    did:key:z6MkvWe...  [notify]

Scope enforcement demo:
  Attempting to use DataAgent for a 'notify' action it was never granted...
  ✓ Blocked: 'DataAgent' lacks 'notify' capability (granted: ['read_data'])

Task: read data/sales.csv, analyze it, and notify the team

  [DataAgent]     read_csv(path='data/sales.csv')     ✓ signed
  [AnalysisAgent] summarize(data='month, product...')  ✓ signed
  [NotifyAgent]   send_notification(channel='team')    ✓ signed

✓ 3 action(s) across 3 agent(s)
Run verify-swarm to verify the full delegation chain.
```

## Verify the delegation chain

```bash
uv run verify-swarm
```

```
Registered identities:
  Human               did:key:z6MkuXq...
  Orchestrator        did:key:z6MkpRn...
  DataAgent           did:key:z6MkiHa...
  AnalysisAgent       did:key:z6MktBc...
  NotifyAgent         did:key:z6MkvWe...

Verifying action audit trail...

 #  Agent          Tool              Sig  Delegation  Capabilities
 1  DataAgent      read_csv          ✓    ✓           read_data
 2  AnalysisAgent  summarize         ✓    ✓           analyze
 3  NotifyAgent    send_notification ✓    ✓           notify

  ✓ 3/3 action signatures valid
  ✓ 3/3 delegation chains valid

✓ Audit trail intact — every action is authorized and verifiable.
```

---

## How it works

```
Human
│  generates keypair, holds root authority
│
└─ Orchestrator  ← delegation token: signed by Human
   │  capabilities: [delegate, read_data, analyze, notify]
   │
   ├─ DataAgent  ← delegation token: signed by Orchestrator
   │     capabilities: [read_data]
   │     Each tool call envelope embeds the delegation token
   │
   ├─ AnalysisAgent  ← delegation token: signed by Orchestrator
   │     capabilities: [analyze]
   │
   └─ NotifyAgent  ← delegation token: signed by Orchestrator
         capabilities: [notify]
```

Each **delegation token** is itself a signed `ActionEnvelope` (`type: "delegation"`) whose payload records the grantee's DID and capabilities. When a sub-agent signs a tool call, it embeds this token in the payload — so both the action signature and the authorization chain are verifiable from a single JSON object.

**Scope enforcement happens at signing time:** calling `sign_tool_call` with a required capability the agent doesn't hold raises `CapabilityError` before the action is signed or the tool executes.

## What's in `audit.jsonl`

Each line is a signed `tool_call` envelope. The sub-agent's delegation token is embedded in the payload:

```json
{
  "version": "1.0",
  "type": "tool_call",
  "identity": "did:key:z6MkiHa...",
  "payload": {
    "tool": "read_csv",
    "args": {"path": "data/sales.csv"},
    "delegation_token": {
      "type": "delegation",
      "identity": "did:key:z6MkpRn...",
      "payload": {
        "delegate_to": "did:key:z6MkiHa...",
        "capabilities": ["read_data"]
      },
      "signature": "..."
    }
  },
  "timestamp": "2026-04-07T09:14:22Z",
  "signature": "..."
}
```

Tampering with the tool name, args, or delegation token breaks the signature.

---

## Run the tests

```bash
uv run pytest
```

Tests cover the full identity tree, delegation token validity, capability enforcement, tamper detection, and cross-agent scope isolation — no LLM or network required.

---

## Next steps

- **[Demo #1: Single agent audit log](../single_agent/)** — simpler starting point
- **[Demo #3: Verifiable AI-generated code](../verifiable_codegen/)** — LangChain + GitHub Actions
- **[auths Python SDK docs](https://docs.auths.dev/sdk/python)**
- **[auths init --profile agent](https://docs.auths.dev/guides/agent-identity)** — replace in-memory keypairs with persistent, revocable agent identities
