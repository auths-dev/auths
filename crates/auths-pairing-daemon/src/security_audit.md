# Security Audit — Public Verification Network

**Date:** 2026-03-12
**Scope:** `.flow/tasks/fn-72.*` through `fn-76.*`, `public_network_spec.md`
**Severity scale:** Critical > High > Medium > Low

---

## Launch Blockers (fixed in task files)

These have been encoded directly into the task files with `**SECURITY:**` annotations.

| # | Severity | Finding | Task(s) | Fix Applied |
|---|----------|---------|---------|-------------|
| 1 | Critical | Log signing key as plain env var | fn-72.6 | HSM/KMS required for prod. Trait abstraction for key loading so HSM is drop-in. |
| 2 | High | Witness amnesia on restart enables fork acceptance | fn-73.2 | Persist `last_checkpoint.json` to disk with fsync. Load on startup. |
| 3 | High | Replay attack — no nonce on EntryContent | fn-72.6 | Content-hash dedup cache in sequencer (bounded, per-actor, 1hr TTL). |
| 4 | High | Namespace squatting — first-claim with no proof | fn-74.1 | Require Free tier (GitHub-verified) for claims. Rate-limit 5/day/identity, 10/hour/IP. |
| 5 | Medium | No entry body size limits | fn-72.6, fn-72.7 | 64 KiB max body. Field-level limits (ecosystem 128, package_name 256, display_name 256). |
| 6 | High | TOFU trust root poisoning via MITM | fn-76.2 | Hardcoded root key pinned in binary. Fetched trust root must be signed by pinned key. |
| 7 | Medium | Postgres desync allows stale-permission exploitation | fn-72.6 | Degraded mode: refuse appends if Postgres write fails, until reconciliation. |
| 8 | Medium | Unbounded identity creation (Sybil flooding) | fn-72.7 | Register entries rate-limited per IP (10/min). Uses existing `RateLimiter` pattern. |
| 9 | Medium | Self-referential delegation chains | fn-72.3 | Strict chain ordering, DID connectivity checks, no duplicate sequences. |
| 10 | Medium | Stale offline bundles verify indefinitely | fn-72.3 | Warning for bundles >90 days old. |

---

## Ship-Aware (monitor, fix soon — NOT in task files yet)

### SA-1: Access Grant Escalation via Gist Swap
**Severity:** Medium
**Tasks:** fn-75.3 (Auto-provisioning)

**Attack:** Create identity B, point its platform claim to identity A's public Gist. If the server only checks "does a valid Gist exist" rather than "does the Gist reference THIS identity's DID", identity B gets Free tier.

**Mitigation:** The `determine_tier()` function MUST verify that the Gist's signed platform claim references the requesting identity's `did:keri:E...`, not just any valid DID. Also re-verify the Gist exists periodically (not just at init time) — if the user deletes the Gist, the trust signal is gone.

### SA-2: Witness Collusion — All Same Operator
**Severity:** Medium
**Tasks:** fn-73.2, fn-73.3, fn-76.4

**Attack:** All 3 initial witnesses run on Fly.io under auths.dev control. Single entity compromise = quorum.

**Mitigation:** Before public launch, onboard at least one external witness operated by a different organization on different infrastructure. Document a witness diversity policy. The `TrustRoot.witnesses` list should eventually include organizational metadata so clients can audit diversity.

### SA-3: NamespaceTransfer Enables Instant Hostile Takeover
**Severity:** Medium
**Tasks:** fn-74.1

**Attack:** Compromised org admin key → immediate namespace transfer → sign malicious artifacts under stolen namespace. No cooling-off period, no multi-admin approval.

**Mitigation:** Consider a time-locked transfer (24-48hr cancellation window). Require multi-admin approval if the org has >1 admin. At minimum, the monitor (fn-76.3) should alert on all NamespaceTransfer events so the team can respond.

### SA-4: Sequencer DoS via Entry Flood
**Severity:** Medium
**Tasks:** fn-72.6

**Attack:** Per-entry checkpoint signing (Ed25519) + per-entry tile writes + per-entry Postgres writes = CPU and I/O bottleneck. Single-writer actor serializes everything through one channel.

**Mitigation:** Use a bounded mpsc channel (backpressure). The GovernorLayer IP rate limit handles most of this, but consider batching checkpoint signing (every N entries or every T seconds) if throughput becomes an issue. Per-entry signing is the correct default for now — it gives clients immediate proofs.

### SA-5: Tile API Read DoS (Pre-CDN)
**Severity:** Low
**Tasks:** fn-72.8

**Attack:** Tile API routes are exempt from rate limiting (public data). Before S3/CDN (fn-76.1), all reads hit the Fly Volume directly. Repeated partial-tile and checkpoint requests (10s TTL) are not cached.

**Mitigation:** Apply a generous IP rate limit on tile API reads (1000 req/min/IP) for Epic 1. Once S3TileStore (fn-76.1) is deployed with CDN cache headers, this becomes a CDN problem.

### SA-6: Revocation Check Misses During Postgres Desync
**Severity:** Medium
**Tasks:** fn-72.7

**Attack:** Specific instance of the Postgres desync problem. `DeviceRevoke` writes to tiles but Postgres write fails. Subsequent `Attest` from the revoked device passes validation (Postgres still shows active binding).

**Mitigation:** The degraded-mode fix (fn-72.6 launch blocker) addresses this — sequencer refuses appends when Postgres is behind tiles. For defense-in-depth, security-critical checks (device revocation, membership revocation) could double-check against the tile log.

### SA-7: Missing Expiry on Offline Bundles (Deep)
**Severity:** Medium
**Tasks:** fn-72.3

**Attack:** A revoked org member's old attestations remain valid in their offline bundles because the bundle was created before revocation. The bundle verifier cannot know about the revocation without contacting the live log.

**Mitigation:** The 90-day stale warning (launch blocker fix) helps. For stronger guarantees, consumers should re-verify bundles against the live log. Add an `auths artifact refresh` CLI command that re-fetches the latest checkpoint and delegation chain status for an existing bundle. Document that offline verification is a point-in-time check, not a live revocation check.

### SA-8: C2SP Key ID Collision (32-bit)
**Severity:** Low
**Tasks:** fn-72.1

**Attack:** 4-byte key ID = birthday collision at ~65K keys. Only relevant if the witness network grows large.

**Mitigation:** Verifier should try all keys matching a given key ID, not just the first match. This is a C2SP spec limitation, not something we can change.

---

## Existing Pattern to Reuse

The `RateLimiter` at `crates/auths-pairing-daemon/src/rate_limiter.rs` provides a clean per-IP sliding-window rate limiter with Axum middleware integration. This should be reused (or extracted to a shared crate) for:

- **Register entry rate limiting** (fn-72.7): 10/min/IP
- **NamespaceClaim rate limiting** (fn-74.1): 10/hour/IP
- **Tile API read rate limiting** (fn-72.8): 1000/min/IP (pre-CDN)

The pattern: `RateLimiter::new(limit)` + `limiter.check(ip)` + `rate_limit_middleware` as Axum layer. Thread-safe via `Mutex<HashMap<IpAddr, (u32, Instant)>>`. Consider extracting to a workspace-level `auths-rate-limit` crate or a shared module so the pairing daemon, registry server, and witness binary can all use it.

---

## Summary

- **6 launch blockers** fixed directly in task files (HSM signing key, witness persistence, replay dedup, namespace anti-squat, body size limits, trust root pinning)
- **4 additional launch blockers** fixed (Postgres degraded mode, Sybil rate limiting, chain validation, stale bundles)
- **8 ship-aware items** documented above for near-term follow-up
- **2 low-severity items** acceptable for v1
