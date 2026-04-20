# TLS pin kill-switch — threat model

## Problem statement

The mobile app pins the daemon's server SPKI to detect man-in-the-middle attacks. Pinning fails closed on mismatch: a device whose pinned key no longer matches the server's presented key cannot reach the daemon. This is the correct security posture, and it is also a self-DoS if the pinned key is ever lost, compromised, or rotated outside the deployment's planned schedule. Without a recovery path, every pin-compromise incident requires a forced App Store update — worst case ≈48 h.

This document defines the threat model for an emergency kill-switch that lets operators remotely suspend a specific pin (or set of pins) until the next app release can ship with a new pin. The [kill-switch transport ADR](ADRs/005-pin-kill-switch-transport.md) makes the concrete protocol/transport decision that this model drives.

## In scope

- Mobile → daemon TLS sessions protected by SPKI pins in the mobile client.
- Recovery from a pinned-key compromise, rotation error, or operational misconfiguration that would otherwise brick connectivity for the installed base.

## Out of scope

- TLS session security itself (assumed sound under a non-compromised pin).
- Daemon-side key management beyond the effect of pin changes on clients.
- The CDN / static-config infrastructure used to deliver the kill-switch document — that is an operational choice in the transport ADR, not a security property here.

## Adversary capabilities

We assume an adversary who can:

- **Observe and tamper with network traffic** to and from the mobile client, including the kill-switch fetch channel if it shares a trust root with the primary daemon TLS path. A properly-scoped transport does *not* share that root.
- **Replay captured kill-switch blobs** in an attempt to extend their effective window or re-suppress pinning after recovery.
- **Compromise a daemon's pinned TLS key** by one of: key-exfiltration from the daemon host, rogue certificate issuance under a trusted CA, or operational error (unsigned key rotation).
- **Compromise an operational sub-key** used to sign kill-switch documents, but not the offline root.

We explicitly assume the adversary **cannot** reconstruct the Shamir-split root without simultaneous compromise of two of the three shareholders. This is the operational property the transport ADR pins to.

## Protection goals

1. **Bounded blast radius on pin compromise.** A compromised pin that would otherwise lock every installed client out of the daemon can be unpinned within the recovery-latency target, without the client trusting the compromised TLS endpoint.
2. **Integrity of the kill-switch document.** A network attacker cannot forge or modify a kill-switch document without compromising the offline root.
3. **Freshness.** An attacker cannot replay an old kill-switch document past its declared validity window, nor after a subsequent document has superseded it.
4. **Non-bypassability of signature check.** A client that cannot verify the signature MUST NOT disable pinning on the basis of an unsigned or malformed document. Fail-closed on signature failure is a protection property, not merely a recommendation.
5. **No persistent pin disable.** A kill-switch document's effect expires at the end of its validity window. A client that comes back online after the window without having seen a superseding document resumes normal pinning.

## Recovery latency target

**< 1 hour from operator action to 99% of active clients disabling the pin.** The target drives three operational implications:

- The kill-switch document is fetched on every app launch and (if the app supports it) on network-regain events.
- The CDN / hosting layer must be able to serve a new document globally within 5 minutes of the operator push — this is a standard CDN property but worth stating.
- The daemon's failure mode during an active incident should tolerate unpinned clients reaching it. Most incidents will leave the daemon reachable; the kill-switch exists for the cases where it is not.

## Replay protection

Every kill-switch document carries:

- **`valid_not_before`** — Unix seconds. Clients reject documents whose `not_before` is in the future relative to their local clock (with a small skew allowance).
- **`valid_not_after`** — Unix seconds. Clients reject documents past `not_after`. Operational policy pins `(not_after − not_before)` to **≤ 24 hours**. A shorter window is acceptable; longer is not.
- **`sequence`** — monotonic `u64` counter. Clients record the highest `sequence` they have ever accepted and reject any document whose `sequence` is less than or equal to it. This defeats the "capture an old kill-switch and replay after recovery" attack.

The local clock check is a soft defense — a device with a manipulated clock is already compromised in other ways. The `sequence` check is the load-bearing one: even with a wrong clock, the client will not accept a document older than one it has already seen.

## Fail modes

| Failure | Response |
|---|---|
| Signature verification fails | **Fail closed.** Keep current pin set; do not apply any changes from the document. |
| Document's `sequence` ≤ last-seen | Ignore the document silently. (No user-visible effect — this is the common case when a client re-fetches between updates.) |
| Document `not_after` has passed | Ignore the document silently. |
| Document `not_before` is in the future (client clock slew) | Retry on next app launch. |
| Kill-switch endpoint unreachable | **Fail open on fetch.** Keep using the last-applied document if still within its validity window, otherwise revert to code-shipped pins. Do *not* block app functionality on the fetch — an attacker who can silence the endpoint should not thereby deny service to the user. The HSTS-preload precedent (where unreachable pin-set managers created a DoS amplification) is what this rule is defending against. |
| Daemon's pinned TLS key rotates to a key the client does not have | Client surfaces a clear error to the user: "pinned key rotated; update the app." Not the kill-switch's job — that's a normal app-update prompt. |

The signature-fail-closed / fetch-fail-open asymmetry is deliberate. A forged document is a critical incident; a missing document is a network blip.

## Signing-key custody

Per [ADR 005](ADRs/005-pin-kill-switch-transport.md): **2-of-3 Shamir secret-sharing over HSM-held shares**. Three operators hold one share each; any two can reconstruct the root for a scheduled rotation or emergency signing. The root signs *operational sub-keys* on a regular cadence; each sub-key signs day-to-day kill-switch documents. Loss of any one share is recoverable; loss of any two is the threshold at which the root must be regenerated from scratch (which in turn requires every client to ship an app update with the new root pinned).

Rotation cadence:

- **Operational sub-key**: rotated on a calendar schedule (e.g., monthly).
- **Root**: never rotated except on confirmed compromise. Root rotation is an app-release event, not an operational one.

## Detection

- **Transparency of signed documents.** The kill-switch CDN serves the *current* document. A wire observer can record every served document and flag any document that neither the operator nor the shareholders recognize.
- **Sequence-counter invariant.** Clients treat any observed regression in `sequence` as a forgery or replay. The client does not need to act on it beyond logging, but the log entries are monitored-channel evidence of tampering.
- **Client telemetry (opt-in).** Clients can report the `(sequence, not_before)` of the document they are operating under. A divergent fleet is visible to the operator.

## Known limitations

- **Compromise of two shareholders.** The scheme survives loss of one share. Loss of two shares compromises the root — and once the root is compromised, there is no rescue path that doesn't require a forced app update.
- **Local clock manipulation.** A device whose clock is set to an arbitrary point in the past can accept a historical document within its original validity window. The `sequence` check prevents this from permanently disabling pinning, but an attacker with clock control can brief windows of vulnerability. We accept this as a consequence of mobile clients not having a trusted monotonic clock source.
- **No fine-grained per-device targeting.** Documents disable a pin for the fleet, not for a specific device. This is deliberate — per-device targeting would require a per-device signing channel, which is a bigger lift than the problem warrants.

## Cross-references

- [ADR 005 — kill-switch transport](ADRs/005-pin-kill-switch-transport.md).
- `$MOBILE/docs/tls-pinning.md` — documents the residual-risk statement this model downgrades.
