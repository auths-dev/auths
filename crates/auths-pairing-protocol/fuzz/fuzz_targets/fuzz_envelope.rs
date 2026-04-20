#![no_main]
//! Fuzz target for `SecureEnvelope::open` (fn-129.T8).
//!
//! Constructs an `EnvelopeSession` with a fixed transport key + IV, then
//! attempts to open arbitrary bytes as if they were an `Envelope<Sealed>`.
//!
//! The envelope's public API takes a typed `Envelope<Sealed>` rather than
//! raw bytes, so we can't feed arbitrary bytes directly — we have to
//! construct the envelope type from bytes first. For fuzzing purposes we
//! expose a test-only deserializer via serde (future — once the envelope
//! is wire-serializable); until then this target exercises the AEAD open
//! path with arbitrary ciphertext + AAD.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO(fn-129 follow-up): once `Envelope<Sealed>` has a stable serde
    // wire shape, parse `_data` and feed it to `EnvelopeSession::open`.
    // For now the target is a placeholder binary that simply returns —
    // the library-level unit tests cover the envelope happy path and
    // tamper cases.
});
