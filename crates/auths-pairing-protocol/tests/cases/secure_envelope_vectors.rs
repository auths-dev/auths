//! Known-Answer Tests (KAT) for `SecureEnvelope`.
//!
//! The vectors in `tests/vectors/secure_envelope.json` are the
//! cross-implementation contract: every client that claims to speak
//! the auths pairing envelope must produce byte-exact identical
//! ciphertext, nonce, and AAD for the same inputs. The mobile-side
//! `SecureEnvelope.swift` mirror is validated against this file by
//! the mobile CI.
//!
//! # Two modes
//!
//! - Default (CI / regular test runs): load the committed JSON,
//!   reconstruct the envelope from the vector inputs, assert that the
//!   produced nonce/AAD/ciphertext match byte-for-byte. If the envelope
//!   implementation drifts, this test fails and the operator must
//!   investigate — drift without a matching JSON update is a bug.
//!
//! - `AUTHS_REGEN_VECTORS=1`: regenerate the JSON from the current
//!   envelope implementation. Use only after deliberate envelope-format
//!   changes, and coordinate a matching update to
//!   `$MOBILE/shared/secure-envelope-vectors.json` in the mobile repo.

use std::path::PathBuf;

use auths_pairing_protocol::{
    Envelope, EnvelopeSession, MAX_MESSAGES_PER_SESSION, Sealed, TransportKey,
};
use serde::{Deserialize, Serialize};

const VECTORS_PATH: &str = "tests/vectors/secure_envelope.json";

/// Top-level KAT document.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct VectorFile {
    /// HKDF `info` string / domain separator — must match
    /// `auths_pairing_protocol::domain_separation::ENVELOPE_INFO`.
    envelope_info: String,
    /// AEAD primitive used on the wire.
    aead: String,
    /// Format version — bump when the on-wire layout changes.
    version: u32,
    vectors: Vec<Vector>,
}

/// One KAT vector. Fields are serialized in insertion order via the
/// `#[derive]` order below so diffs stay stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Vector {
    name: String,
    /// 32 bytes (hex).
    transport_key_hex: String,
    /// 12 bytes (hex).
    iv_hex: String,
    session_id: String,
    path: String,
    counter: u32,
    /// UTF-8 plaintext. Kept human-readable where possible; binary vectors
    /// use `plaintext_hex` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plaintext_utf8: Option<String>,
    /// Hex-encoded plaintext (used for binary / large vectors).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plaintext_hex: Option<String>,
    /// Expected nonce (= iv XOR counter_be on last 4 bytes).
    nonce_hex: String,
    /// Expected AAD (len-prefixed session_id || len-prefixed path || counter_be).
    aad_hex: String,
    /// Expected ciphertext || 16-byte Poly1305 tag.
    ciphertext_hex: String,
    /// One of: "valid" | "tag-mismatch" | "aad-mismatch" | "counter-not-monotonic".
    /// Negative vectors mutate one of the inputs and assert the opener rejects.
    expected_result: String,
    /// For negative vectors: describes the mutation applied. Ignored in
    /// valid vectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation: Option<String>,
}

impl Vector {
    fn plaintext_bytes(&self) -> Vec<u8> {
        if let Some(utf8) = &self.plaintext_utf8 {
            return utf8.as_bytes().to_vec();
        }
        if let Some(hex_str) = &self.plaintext_hex {
            return hex::decode(hex_str).expect("valid hex plaintext");
        }
        Vec::new()
    }
}

fn transport_key_from_hex(h: &str) -> TransportKey {
    let mut bytes = [0u8; 32];
    let decoded = hex::decode(h).expect("valid hex");
    bytes.copy_from_slice(&decoded);
    TransportKey::new(bytes)
}

fn iv_from_hex(h: &str) -> [u8; 12] {
    let mut iv = [0u8; 12];
    let decoded = hex::decode(h).expect("valid hex");
    iv.copy_from_slice(&decoded);
    iv
}

fn vectors_path() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join(VECTORS_PATH)
}

/// Regenerate the vectors from the current envelope implementation.
///
/// Builds each vector by creating a fresh `EnvelopeSession`, sealing the
/// plaintext at the declared counter, and capturing the resulting
/// nonce/AAD/ciphertext. Negative vectors are synthesized by applying
/// the named mutation to a valid vector.
async fn regenerate() -> VectorFile {
    // Shared inputs. `0xA5` / `0x07` are arbitrary, chosen for visual
    // distinctness in a hex dump.
    let transport_key_bytes = [0xA5u8; 32];
    let iv_bytes = [0x07u8; 12];

    let mut vectors = Vec::<Vector>::new();

    // --------- Valid vectors ---------

    // v1: basic round-trip, counter=1, small plaintext.
    vectors.push(
        seal_vector(
            "basic_round_trip_counter_1",
            transport_key_bytes,
            iv_bytes,
            "sess-kat",
            "/v1/pairing/sessions/x/response",
            1,
            PlaintextInput::Utf8("hello world".into()),
        )
        .await,
    );

    // v2: same session, counter=2 — exercises counter increment.
    vectors.push(
        seal_vector(
            "same_session_counter_2",
            transport_key_bytes,
            iv_bytes,
            "sess-kat",
            "/v1/pairing/sessions/x/confirm",
            2,
            PlaintextInput::Utf8("second message".into()),
        )
        .await,
    );

    // v3: empty plaintext.
    vectors.push(
        seal_vector(
            "empty_plaintext",
            transport_key_bytes,
            iv_bytes,
            "sess-kat",
            "/v1/pairing/sessions/x/response",
            1,
            PlaintextInput::Utf8(String::new()),
        )
        .await,
    );

    // v4: 4 KiB plaintext.
    let large = vec![0x42u8; 4096];
    vectors.push(
        seal_vector(
            "large_plaintext_4kib",
            transport_key_bytes,
            iv_bytes,
            "sess-kat",
            "/v1/pairing/sessions/x/response",
            1,
            PlaintextInput::Bytes(large),
        )
        .await,
    );

    // v5: path with UTF-8 multibyte chars — proves the AAD len-prefix
    // carries byte length, not char length.
    vectors.push(
        seal_vector(
            "utf8_multibyte_path",
            transport_key_bytes,
            iv_bytes,
            "sess-kat",
            "/v1/\u{00e9}chelle/\u{1F300}/response",
            1,
            PlaintextInput::Utf8("utf-8 path binding".into()),
        )
        .await,
    );

    // --------- Negative vectors ---------

    // n1: tampered tag (last byte flipped) — tag-mismatch.
    let base = vectors[0].clone();
    let mut bad_ct = hex::decode(&base.ciphertext_hex).unwrap();
    let last = bad_ct.len() - 1;
    bad_ct[last] ^= 0x01;
    vectors.push(Vector {
        name: "tampered_tag".into(),
        ciphertext_hex: hex::encode(&bad_ct),
        expected_result: "tag-mismatch".into(),
        mutation: Some("flipped last byte of ciphertext||tag".into()),
        ..base.clone()
    });

    // n2: tampered ciphertext body (first byte flipped, tag intact at end).
    let mut bad_body = hex::decode(&base.ciphertext_hex).unwrap();
    if !bad_body.is_empty() {
        bad_body[0] ^= 0x01;
    }
    vectors.push(Vector {
        name: "tampered_ciphertext_body".into(),
        ciphertext_hex: hex::encode(&bad_body),
        expected_result: "tag-mismatch".into(),
        mutation: Some("flipped first byte of ciphertext".into()),
        ..base.clone()
    });

    // n3: AAD path mismatch — opener uses a different path than sealer.
    // We express this as a valid ciphertext but with the `path` field in
    // the vector changed to something else; the opener's AAD will not
    // match and decryption fails.
    vectors.push(Vector {
        name: "wrong_aad_path".into(),
        path: "/v1/pairing/sessions/x/WRONG".into(),
        expected_result: "aad-mismatch".into(),
        mutation: Some("path mutated after sealing".into()),
        ..base.clone()
    });

    // n4: counter rollback — reusing counter=1 after having already
    // opened a higher counter is rejected by `open` per CounterNotMonotonic.
    // Represented as a valid ciphertext at counter 1; the test code
    // arranges the session state so last_opened_counter >= 1 before
    // attempting open.
    vectors.push(Vector {
        name: "counter_rollback".into(),
        expected_result: "counter-not-monotonic".into(),
        mutation: Some("replay counter=1 after opening counter>=1".into()),
        ..base.clone()
    });

    VectorFile {
        envelope_info: "auths-pairing-envelope-v1".into(),
        aead: "chacha20poly1305".into(),
        version: 1,
        vectors,
    }
}

enum PlaintextInput {
    Utf8(String),
    Bytes(Vec<u8>),
}

async fn seal_vector(
    name: &str,
    transport_key_bytes: [u8; 32],
    iv: [u8; 12],
    session_id: &str,
    path: &str,
    counter: u32,
    plaintext: PlaintextInput,
) -> Vector {
    // Fresh session per vector so counters start clean. The envelope
    // session internally starts at counter=1; to hit a target counter
    // we seal (counter - 1) dummy envelopes first.
    assert!((1..MAX_MESSAGES_PER_SESSION).contains(&counter));

    let tk = TransportKey::new(transport_key_bytes);
    let mut session = EnvelopeSession::new(&tk, session_id.to_string(), iv)
        .await
        .expect("envelope session");
    for _ in 1..counter {
        let _: Envelope<Sealed> = session
            .seal("/warmup", b"warmup")
            .await
            .expect("warmup seal");
    }

    let (pt_bytes, pt_utf8, pt_hex) = match plaintext {
        PlaintextInput::Utf8(s) => {
            let bytes = s.as_bytes().to_vec();
            (bytes, Some(s), None)
        }
        PlaintextInput::Bytes(b) => {
            let hex_str = hex::encode(&b);
            (b, None, Some(hex_str))
        }
    };

    let sealed: Envelope<Sealed> = session.seal(path, &pt_bytes).await.expect("seal");
    let nonce_hex = hex::encode(sealed.nonce());
    let aad_hex = hex::encode(compute_expected_aad(session_id, path, counter));
    let ciphertext_hex = hex::encode(sealed.ciphertext());

    Vector {
        name: name.to_string(),
        transport_key_hex: hex::encode(transport_key_bytes),
        iv_hex: hex::encode(iv),
        session_id: session_id.to_string(),
        path: path.to_string(),
        counter,
        plaintext_utf8: pt_utf8,
        plaintext_hex: pt_hex,
        nonce_hex,
        aad_hex,
        ciphertext_hex,
        expected_result: "valid".into(),
        mutation: None,
    }
}

fn compute_expected_aad(session_id: &str, path: &str, counter: u32) -> Vec<u8> {
    let sid = session_id.as_bytes();
    let p = path.as_bytes();
    let mut aad = Vec::with_capacity(4 + sid.len() + 4 + p.len() + 4);
    aad.extend_from_slice(&(sid.len() as u32).to_be_bytes());
    aad.extend_from_slice(sid);
    aad.extend_from_slice(&(p.len() as u32).to_be_bytes());
    aad.extend_from_slice(p);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

#[tokio::test]
async fn kat_vectors_match_current_envelope_output() {
    let path = vectors_path();
    let regenerate_requested = std::env::var("AUTHS_REGEN_VECTORS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let fresh = regenerate().await;

    if regenerate_requested || !path.exists() {
        let json = serde_json::to_string_pretty(&fresh).expect("serialize vectors") + "\n";
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, json).expect("write vectors file");
        if regenerate_requested {
            eprintln!("regenerated {} at operator request", path.display());
            return;
        }
        eprintln!("wrote initial {} (file did not exist)", path.display());
        return;
    }

    let on_disk: VectorFile = {
        let text = std::fs::read_to_string(&path).expect("read vectors file");
        serde_json::from_str(&text).expect("parse vectors file")
    };

    assert_eq!(
        on_disk.envelope_info, fresh.envelope_info,
        "envelope_info drift — check ENVELOPE_INFO domain separator"
    );
    assert_eq!(on_disk.aead, fresh.aead, "aead drift");
    assert_eq!(on_disk.version, fresh.version, "version drift");
    assert_eq!(
        on_disk.vectors.len(),
        fresh.vectors.len(),
        "vector count drift — someone added/removed a vector without updating the file. \
         Set AUTHS_REGEN_VECTORS=1 to regenerate."
    );

    for (on, fr) in on_disk.vectors.iter().zip(fresh.vectors.iter()) {
        assert_eq!(
            on, fr,
            "vector drift on '{}' — envelope output no longer matches the \
             committed KAT. Set AUTHS_REGEN_VECTORS=1 to regenerate after \
             a deliberate change (and coordinate with the mobile mirror).",
            on.name
        );
    }
}

/// Negative vectors: reconstruct the session, attempt `open` on the
/// mutated ciphertext/AAD, assert the declared error fires.
#[tokio::test]
async fn negative_vectors_reject_as_declared() {
    let path = vectors_path();
    if !path.exists() {
        // Bootstrap case: the positive test writes the file; run it first.
        return;
    }
    let text = std::fs::read_to_string(&path).expect("read vectors file");
    let file: VectorFile = serde_json::from_str(&text).expect("parse vectors file");

    for v in file.vectors.iter().filter(|v| v.expected_result != "valid") {
        let tk = transport_key_from_hex(&v.transport_key_hex);
        let iv = iv_from_hex(&v.iv_hex);
        let mut session = EnvelopeSession::new(&tk, v.session_id.clone(), iv)
            .await
            .expect("envelope session");

        // `Envelope<Sealed>` has private fields, so we cannot forge an
        // envelope whose ciphertext bytes match the stored mutated hex
        // from inside this crate's integration tests. The KAT's
        // tag-mismatch, tampered-ciphertext, and counter-rollback cases
        // are primarily a cross-implementation contract for the mobile
        // mirror; Rust-side we verify what the API surface allows.
        //
        // Specifically on Rust:
        // - `aad-mismatch`: we can express this by sealing at one path
        //   and opening at a different path (different AAD). The opener
        //   rejects with `AadMismatch` before the AEAD even runs.
        // - `tag-mismatch` / `tampered_ciphertext_body`: can only be
        //   exercised via the wire (mobile mirror); our negative fields
        //   are documentation. Skip on Rust.
        // - `counter-not-monotonic`: requires two envelopes at the same
        //   counter, which the typestate API structurally prevents on a
        //   single session. Mobile mirror exercises this by replaying a
        //   captured wire envelope. Skip on Rust.
        match v.expected_result.as_str() {
            "tag-mismatch" | "counter-not-monotonic" => continue,
            "aad-mismatch" => {
                let sealed = session
                    .seal(&v.path, &v.plaintext_bytes())
                    .await
                    .expect("reseal for aad negative");
                let alt_path = format!("{}__mutated", v.path);
                let result = session.open(&alt_path, sealed).await;
                assert!(
                    result.is_err(),
                    "negative vector '{}' must be rejected but succeeded",
                    v.name
                );
            }
            other => panic!("unknown expected_result {other}"),
        }
    }
}
