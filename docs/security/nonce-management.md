# AEAD Nonce Management

Rules for constructing and reusing nonces under every AEAD the workspace
supports. Reading this file is mandatory before touching any AEAD call site.

## Algorithms in use

| Build             | AEAD                  | Nonce length | Nonce reuse bound |
|-------------------|-----------------------|--------------|-------------------|
| default           | ChaCha20-Poly1305     | 96 bits      | 2^-32 collision at 2^32 random nonces per key |
| `--features fips` | ChaCha20-Poly1305 (aws-lc-rs) | 96 bits | same |
| `--features cnsa` | AES-256-GCM           | 96 bits      | 2^-32 collision at 2^32 random nonces per key |

Mixing nonces across algorithms under the same key material is catastrophic
and not possible at the API surface — `CryptoProvider::aead_encrypt`
accepts a key + nonce pair that is bound to the provider's AEAD by feature
flag. A ciphertext produced by the ChaCha provider cannot be decrypted by
the AES provider and vice versa.

## Discipline (default + FIPS: ChaCha20-Poly1305)

ChaCha20-Poly1305 is constant-time and accepts 96-bit nonces. The collision
bound with random nonces is 2^-32 at 2^32 messages per key — acceptable for
session-bounded protocols (≤ ~10 messages per session) but unsafe for bulk
transport.

**Rules:**

1. **Random nonces from `OsRng` only.** Do not use `rand::thread_rng` or
   `rand::random` (banned by clippy lint; see `docs/security/rng-policy.md`).
2. **Never reuse a nonce under the same key.** If you need to rotate keys
   frequently, derive them via HKDF with a counter in the `info` string.
3. **Session-bounded protocols can treat random 96-bit nonces as safe.**
   Collision at 2^32 messages is not reachable inside a single pairing
   session. The `SecureEnvelope` type (fn-129.T7) uses a deterministic
   counter IV pattern (RFC 8446 §5.3) instead — simpler and eliminates the
   probabilistic collision.

## Discipline (CNSA: AES-256-GCM)

AES-256-GCM under CNSA requires the same nonce discipline as ChaCha.
**Additional rule:** rotate the AES key after 2^32 messages or 2^39 bytes,
whichever comes first, per NIST SP 800-38D §8.3. This is an AES-GCM-
specific ceiling; ChaCha does not have an equivalent byte bound.

**AAD must be length-prefixed.** Naive concatenation of AAD fields is a
documented attack surface (see USENIX'23 "Subtle Differences in Real-World
Authenticated Encryption"). The workspace convention is:

```
AAD = u32be(len(field1)) || field1 || u32be(len(field2)) || field2 || ...
```

Enforced by construction in `auths-pairing-protocol::SecureEnvelope` (fn-
129.T7). Every hand-rolled AEAD call must follow this rule; grep for
naive `aead.concat()` during code review.

## Common mistakes and how to avoid them

- **Reusing nonces across encryption + MAC paths.** If an app uses
  ChaCha20-Poly1305 for transport AND HMAC-SHA-256 for auth tags, do not
  derive them from the same key material. HKDF-expand with domain-separated
  `info` strings (see `auths-pairing-protocol/src/domain_separation.rs`).
- **Counter nonces without domain separation.** A counter IV is safe only
  if each (key, counter) pair appears once. Keys derived from HKDF with a
  unique `info` guarantee this.
- **Writing zeros to unused parts of a nonce.** `Nonce::assume_unique_for_key`
  in aws-lc-rs / ring takes a `[u8; 12]` — if you construct it from a
  `u64` counter without filling the top 4 bytes, you have silently imported
  all-zero prefix nonces across keys. Use the crate's `Counter` helpers.

## References

- RFC 8439 — ChaCha20-Poly1305 construction.
- RFC 5288 — AES-GCM for TLS.
- NIST SP 800-38D — GCM mode of operation (key-and-data bounds).
- CFRG AEAD limits draft: https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-07.html
- USENIX'23 "Subtle Differences in Real-World Authenticated Encryption":
  https://charlie.jacomme.fr/publication/aead-usenix-23/aead-usenix-23.pdf
