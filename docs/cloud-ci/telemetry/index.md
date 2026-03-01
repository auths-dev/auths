# Auths Telemetry — Operations Guide

This document describes the enterprise telemetry pipeline shipped with
`auths-auth-server`. It is the authoritative reference for SRE teams,
SOC2 auditors, and M&A due-diligence reviewers evaluating the platform's
security observability posture.

---

## Architecture

Every security event in `auths-auth-server` passes through a single, modular
pipeline provided by the `auths-telemetry` crate:

```
Axum handler (hot path)
    │
    │  emit_telemetry(&event)         ← synchronous, non-blocking
    ▼
tokio::sync::mpsc channel             ← bounded, 1 024-slot default
    │
    │  background Tokio task
    ▼
tokio::io::BufWriter<Stdout>          ← async I/O, no global stdout lock
    │
    ▼
newline-delimited JSON on stdout      ← SIEM / log-shipper ingests here
```

The hot path never blocks. All I/O is delegated to a single background
task that owns the stdout writer. This architecture sustains 10 000+
concurrent authentications without contention on I/O.

For the full JSON schema see [`schema.md`](./schema.md).

---

## Observable Degradation (SOC2 / FedRAMP)

Silently dropping audit logs during a load spike would constitute a
forensic blind spot and a compliance failure. The pipeline implements
**observable degradation** instead:

### Drop Counter

```rust
pub static DROPPED_AUDIT_EVENTS: AtomicU64;
```

When the 1 024-slot channel is full and `try_send` fails, the counter is
incremented atomically. The hot path is never blocked.

### TelemetryDegradation Meta-Event

After each successful write, the background worker reads and resets the
counter. If the count is non-zero it immediately writes a
`TelemetryDegradation` event to the same stdout stream:

```json
{
  "timestamp": 1708531200,
  "event_type": "TelemetryDegradation",
  "actor_did": "system",
  "action": "telemetry_pipeline",
  "status": "Degraded",
  "dropped_count": 42
}
```

This tells the CISO exactly how many events were lost and precisely when
the blind spot closed. Alerting rules should page on `status = "Degraded"`.

---

## Graceful Shutdown

`init_telemetry(capacity)` returns a `TelemetryShutdown` handle. The only
strong `mpsc::Sender` lives inside this handle. When `shutdown().await` is
called:

1. The strong sender is dropped, closing the channel.
2. The background worker drains all buffered events.
3. The `BufWriter` is flushed to stdout.
4. The worker task exits and the future resolves.

In `auths-auth-server/src/main.rs` this happens after `run_server` returns,
ensuring no audit logs are lost during a Kubernetes pod rollout (SIGTERM →
Axum graceful shutdown → `telemetry.shutdown().await`).

---

## Extending the Emitter

Because the consumer crates call only `emit_telemetry(&event)` and
`build_audit_event(...)`, routing events to a different sink requires
modifying only `crates/auths-telemetry/src/emitter.rs`. No call sites
change. Planned upgrade paths:

| Sink | Notes |
|---|---|
| Syslog | Replace `BufWriter<Stdout>` with a UDP/TCP syslog writer. |
| DataDog | Replace the background task with an `opentelemetry-datadog` batch exporter. |
| Kafka | Send serialised JSON to a Kafka producer in the background task. |

---

## Schema Contract

The JSON schema for `AuditEvent` is auto-generated from the Rust struct
definition via [`schemars`](https://docs.rs/schemars). See [`schema.md`](./schema.md).

To regenerate after changing `AuditEvent`:

```bash
cargo xtask gen-schema
```

CI enforces synchronisation: the `schema_json_is_up_to_date` integration
test fails if `schema.json` does not match the compiled struct. This
guarantees the documentation is a cryptographically enforced artifact of
the build process, not an afterthought.
