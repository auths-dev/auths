# CLI `--json` output

Pass the global `--json` flag (e.g. `auths --json status`) to get machine-readable
output on **stdout**. Human progress and hints go to **stderr**, so a pipeline can
safely capture stdout alone:

```bash
result=$(auths --json status)   # stdout is JSON only; stderr carries progress
```

Two shapes are in use. Commands that return a single domain object emit that object
directly; commands built on the shared envelope wrap their payload in
`{ "success", "command", "data" }` (with `"error"` replacing `"data"` on failure).

## `auths --json init`

Enveloped. `--json` forces non-interactive (it never prompts). `data` varies by
profile:

```json
{ "success": true, "command": "init",
  "data": { "profile": "developer", "identity": "did:keri:E…",
            "device": "did:key:z6Mk…", "key_alias": "auths-…",
            "registry": "https://…" } }
```

- `profile` — `"developer"`, `"ci"`, or `"agent"`.
- developer: `identity`, `device`, `key_alias`, `registry` (nullable).
- ci: `identity`, `env` (array of `KEY=VALUE` strings for CI secrets).
- agent: `identity` (nullable on dry-run), `capabilities` (array of strings).

## `auths --json status`

Emits a `StatusReport` object directly (not enveloped): identity, device, registry,
and witness fields. Absent identity is reported as a well-formed object with the
relevant fields null, not an error.

## `auths --json device list`

Enveloped. `data.identity` is the controller DID; `data.devices` is an array of
`{ "id": "did:…", "status": "active" | "revoked", "anchored": true }`.

## `auths --json device link`

Enveloped. `data` is `{ "device": "did:…", "attestation_id": "…" }`.

## `auths --json device verify`

Emits the verification result object directly: `{ "valid": bool, … }` on success, or
an error object `{ "valid": false, "error": "…" }` on failure. Exit code is nonzero
when verification fails.

## `auths --json kel validate`

Emits `{ "valid": true, "source": "…", "events": N }` on success. On a stale
encoding or broken chain it exits nonzero with the defect on stderr.
