# ADR-001: Deniable Messaging — Authenticate Messages by the Session, Not a Per-Message Signature

**Status:** Accepted
**Date:** 2026-06-19

## Context

Murmur is a privacy-first messenger. Its design goal is that the *only* identifier is a
self-certifying AID — no phone number, no email, no central directory keyed to a real-world
identity. The signing key behind the AID is a P-256 key held in the device's Secure Enclave.

That leaves an open question for the message path: **how is an individual message
authenticated as coming from its sender?** Two answers are possible, and they are mutually
exclusive:

1. **Per-message signature.** Each message carries an AID signature over its contents. Anyone
   — the recipient, or a third party the message is forwarded to — can later prove "this AID
   said this." This is *non-repudiation*.
2. **Session authentication.** The message carries no signature. It is sealed under a pairwise
   session (an AEAD keyed off a shared secret established by X3DH and rooted in the sender's
   AID-signed prekey bundle). A message that opens under that session is, by construction, from
   the peer — but nobody can prove that to a third party afterward. This is *deniability*.

The engine originally took approach (1): the inner envelope carried a `sender` AID and a
signature, and `open` verified it against the key the AID resolved to. That choice was the
reason the codebase had a software signing key on the message path at all — the Secure Enclave
cannot practically sign every message (it is biometric-gated and not built for high-frequency
signing), so a per-message-signing design forces a fast software key alongside the Enclave
identity.

For a privacy-first messenger this is the wrong trade. Per-message signatures are non-repudiable
by definition, which is the opposite of what a private conversation wants: a seized device, a
leaked log, or a compelled disclosure would yield cryptographic *proof* of who said what — the
precise harm a private messenger exists to prevent (coercion, source exposure, doxxing). It is
also redundant: once the X3DH handshake and ratchet are established (rooted in the AID-signed
prekey bundle), the session already authenticates every message. The signature adds only
provability, not authentication.

## Decision

**Messages are authenticated by the pairwise session, not by a per-message AID signature, and
the message envelope carries no identity.**

Concretely:

- The inner envelope is pure content: `message_id`, `content_type`, `flags`, `body`. It carries
  no sender AID, no recipient AID, and no signature. Integrity comes from the AEAD tag over the
  sealed frame.
- `seal` adds no signature. `open` performs no per-message signature check. It decrypts under
  the endpoint's session, binding `sender ‖ recipient ‖ mailbox` into the AEAD additional data,
  and attributes the message to the session **peer** (`from = peer`, `to = self`). A ciphertext
  that did not arrive through that session fails the AEAD tag and is rejected, never surfaced.
- The AID signatures that root trust remain where they belong: on the **prekey bundle** and the
  **key-state (KEL) events** that establish and rotate the session. Those are public
  key-distribution and identity-lifecycle artifacts, not message content, so they are compatible
  with message deniability.
- **Non-repudiation is a separate concern.** Verifiable, attributable, forwardable content
  ("this author signed this artifact") is a distinct product built on the same AID identity
  layer. It is deliberately *not* part of murmur's chat path.

Why session authentication still authenticates the sender: the session is *pairwise*, and the
AEAD additional data names the peer as sender. A ciphertext opens only if it was sealed under
the shared session key with that additional data. Exactly two endpoints hold the key; the
recipient knows it did not seal the message; therefore the peer did. Authentication is
preserved. What is shed is the ability to prove authorship to anyone else — which is the
deniability we want.

## Alternatives Considered

### Alternative A: Per-message AID signatures

Every message carries an AID signature, verified on open.

**Rejected** because:

- It is non-repudiable, which directly defeats deniability — a stored or seized conversation
  becomes cryptographic evidence of authorship.
- With the signing key in the Secure Enclave it forces an impossible UX (a biometric prompt per
  message) or a weaker Enclave policy that signs without per-use authorization.
- It is redundant with the session: after the handshake, the ratchet already authenticates each
  message. The signature adds provability, not authentication.

### Alternative B: Per-device session sub-key

The Enclave root signs a software signing sub-key once; that sub-key signs each message.

**Rejected** because:

- It still produces a per-message signature, so messages remain non-repudiable — it does not buy
  deniability, only better signing ergonomics.
- It adds a sub-key lifecycle (issuance, rotation, revocation, and binding back to the root) for
  no security gain on the property we actually care about.

### Alternative C: Optional / opt-in per-message signing

Keep the signature field and sign only when a caller asks.

**Rejected** because:

- A signed-by-default or easily-enabled path is a deniability footgun: the safe property must be
  structural, not a flag. Carrying an identity field in the message frame at all is a leak even
  when unsigned.

## Consequences

**Positive:**

- Messages are **deniable**: the shared session key means either endpoint could have produced
  any given ciphertext, so neither party can later prove to a third party who authored a message.
- The message frame carries no identity and no signature, so sealed ciphertexts are
  substantially smaller.
- The Secure Enclave key is used only for the rare, high-value operations that root a session
  (prekey bundle, key-state events), never per message — no biometric prompt to send a message.
- Clean separation of concerns: interactive, deniable chat here; durable, attributable content
  signing as a separate product on the same identity layer.

**Negative / accepted risks:**

- The security boundary is now the pairwise session key. A party that obtains it (a leaked or
  shared session key, a compromised endpoint) can forge messages indistinguishable from the
  peer's, because there is no per-message signature to additionally pin authorship. This is the
  inherent cost of deniability and is the same trade made by the protocols murmur follows.
- Within-session sender authentication depends on the session being genuinely pairwise and rooted
  in the authenticated prekey bundle. The integrity of first contact (verifying the peer's AID and
  its signed bundle) is therefore load-bearing.
- Deniability here is *cryptographic only*. It defeats cryptographic proof of authorship; it does
  not defend against screenshots, device forensics, or a participant's testimony. This should be
  represented honestly to users.

## Precedent

Deniable messaging is the deliberate design of Signal/OTR-style protocols: message authentication
derives from shared-secret session keys, so after the fact either participant could have produced
a transcript and none of it is provable to an outsider. Murmur follows that lineage for its chat
path.

Non-repudiation is not abandoned — it is relocated. The same AID identity that roots a murmur
session is the basis for explicitly attributable signing of standalone content, where durable,
forwardable proof of authorship is the goal rather than a hazard. Keeping the two apart lets each
have the property it needs: chat is deniable, attestation is provable.
