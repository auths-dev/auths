//! KEL-rooted X.509 leaf certificates — composing a KERI identity with TLS.
//!
//! TLS already authenticates endpoints through the WebPKI/CA system. This module
//! lets a KERI AID compose *with* that pipe instead of replacing it: an X.509
//! leaf certificate whose **trust roots in the AID's key event log**, not in a
//! certificate authority. A stock TLS stack (rustls, OpenSSL, BoringSSL, Go
//! `crypto/tls`) completes a handshake with the cert exactly as it would with any
//! self-signed leaf; an *AID-aware* verifier additionally re-derives the trust by
//! replaying the KEL — so deployment rides every load balancer, mesh, and client
//! that already speaks TLS, while the identity stays self-certifying.
//!
//! ## How the cert chains to the KEL
//!
//! The leaf is *bound* to the AID, not signed by a CA. Two things tie them:
//!
//! 1. **A `did:keri:<aid>` URI in `subjectAltName`** — the SPIFFE X.509-SVID
//!    pattern (identity-in-SAN). It parses cleanly in any stock X.509 verifier
//!    (graceful degradation: a legacy verifier sees an ordinary URI SAN), and an
//!    AID-aware verifier reads the AID out of it.
//! 2. **An `AuthsKeriBinding` certificate extension** carrying the AID's resolved
//!    key-state — the AID prefix, every current signing key (CESR), and the KEL
//!    tip SAID. This is the projection of a KEL replay into the cert, so the
//!    verifier checks the cert against the *log*, never against a CA.
//!
//! The verifier (`verify_binds_to_key_state`, available with the `tls-cert`
//! feature) replays the supplied KEL into a [`KeyState`] and asserts the cert's
//! embedded binding equals that state. Trust is rooted in the log: change a
//! current key in the cert and replay no longer agrees, so the cert is rejected.
//!
//! ## What this module is *not*
//!
//! The leaf carries its own ephemeral TLS keypair (so the long-term AID signing
//! key never goes on the wire). This module establishes the *binding to the KEL
//! key-state* and the *handshake interop*; it does **not** by itself make the
//! binding unforgeable against an attacker who fabricates a key-state — proving
//! the AID *authorized* this TLS key (a KERI signature over the leaf SPKI) and
//! rejecting revoked / KEL-invalid certs is the adversarial verifier's job and
//! lives elsewhere. Here the contract is: produce a KEL-rooted leaf stock stacks
//! accept, and verify a leaf binds to a given KEL's replayed state — both
//! directions, deterministically.
//!
//! ## Parse, don't validate
//!
//! [`AuthsKeriBinding`] is a parsed type: [`AuthsKeriBinding::from_key_state`]
//! builds it only from a resolved key-state, and
//! [`AuthsKeriBinding::from_canonical_json`] is total over its serialized form —
//! an ill-formed extension cannot be represented as a binding, it is an error at
//! the boundary.

use serde::{Deserialize, Serialize};

use crate::keys::{KeriDecodeError, KeriPublicKey};
use crate::state::KeyState;

/// OID of the `AuthsKeriBinding` certificate extension, under the
/// Private Enterprise arc `1.3.6.1.4.1.59999` (`auths`), extension `.1.1`.
///
/// The content is the DER encoding of an OCTET STRING wrapping the canonical
/// JSON of an [`AuthsKeriBinding`]. The extension is **non-critical**: a legacy
/// X.509 verifier that does not understand it ignores it (graceful degradation),
/// while an AID-aware verifier reads it to re-root trust in the KEL.
pub const AUTHS_KERI_BINDING_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 59999, 1, 1];

/// The `did:keri` DID method scheme prefix used in the certificate SAN URI.
pub const DID_KERI_SCHEME: &str = "did:keri:";

/// Errors building or verifying a KEL-rooted certificate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsCertError {
    /// A current signing key in the key-state could not be decoded.
    #[error("decode AID key-state key: {0}")]
    Key(#[from] KeriDecodeError),

    /// X.509 certificate generation failed in the backend.
    #[error("generate certificate: {0}")]
    Generate(String),

    /// The supplied TLS key material could not be loaded as a keypair.
    #[error("load TLS keypair: {0}")]
    KeyPair(String),

    /// The certificate PEM/DER could not be parsed.
    #[error("parse certificate: {0}")]
    ParseCert(String),

    /// The certificate carries no `AuthsKeriBinding` extension — it is not a
    /// KEL-rooted auths certificate.
    #[error("certificate carries no auths KEL binding extension")]
    MissingBinding,

    /// The `AuthsKeriBinding` extension content was not well-formed.
    #[error("malformed auths KEL binding extension: {0}")]
    MalformedBinding(String),

    /// The certificate's binding does not match the replayed KEL key-state.
    #[error("certificate binding does not match the replayed KEL: {0}")]
    BindingMismatch(String),

    /// The certificate's `did:keri` SAN is absent or does not match the binding.
    #[error("certificate did:keri SAN mismatch: {0}")]
    SanMismatch(String),
}

/// The AID key-state a KEL-rooted certificate embeds — the projection of a KEL
/// replay into the cert, so a verifier checks the leaf against the *log*.
///
/// Field order and labels are stable (`serde_json` with `preserve_order`), so the
/// JSON inside the extension is canonical across producers and the bytes a
/// verifier re-derives from a fresh replay equal the bytes in the cert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthsKeriBinding {
    /// The AID this certificate is bound to (the KEL prefix). Also the subject
    /// of the `did:keri:<aid>` SAN.
    pub aid: String,
    /// Every current signing key of the AID, CESR-qualified, in KEL order.
    pub current_keys: Vec<String>,
    /// The SAID of the KEL tip the binding was projected from — the exact log
    /// position whose replay must reproduce `current_keys`.
    pub kel_tip: String,
}

impl AuthsKeriBinding {
    /// Project a resolved [`KeyState`] into a certificate binding.
    ///
    /// Every current key is decoded first (parse, don't validate), so a binding
    /// is only ever built from keys that are valid for their curve — an
    /// undecodable key is [`TlsCertError::Key`] at the boundary, never serialized
    /// into a cert.
    pub fn from_key_state(state: &KeyState) -> Result<Self, TlsCertError> {
        let mut current_keys = Vec::with_capacity(state.current_keys.len());
        for key in &state.current_keys {
            // Decode to reject a malformed key before it reaches the cert.
            KeriPublicKey::parse(key.as_str())?;
            current_keys.push(key.as_str().to_string());
        }
        Ok(Self {
            aid: state.prefix.as_str().to_string(),
            current_keys,
            kel_tip: state.last_event_said.as_str().to_string(),
        })
    }

    /// The `did:keri:<aid>` URI this binding's AID resolves to.
    pub fn did_keri(&self) -> String {
        format!("{DID_KERI_SCHEME}{}", self.aid)
    }

    /// Serialize to the canonical JSON bytes carried (DER-wrapped) in the cert.
    pub fn to_canonical_json(&self) -> Vec<u8> {
        // `serde_json` here is configured (workspace-wide) with preserve_order,
        // and the struct field order is fixed, so this is deterministic.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse a binding from the canonical JSON bytes. Total over its input:
    /// malformed JSON is [`TlsCertError::MalformedBinding`], not a panic.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, TlsCertError> {
        serde_json::from_slice(bytes).map_err(|e| TlsCertError::MalformedBinding(e.to_string()))
    }
}

#[cfg(feature = "tls-cert")]
mod backend {
    use super::*;

    use rcgen::string::Ia5String;
    use rcgen::{
        CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, SanType,
    };

    /// A freshly issued KEL-rooted leaf certificate plus its private key.
    ///
    /// The cert's subject public key is a fresh ephemeral TLS keypair (the AID's
    /// long-term key is never put on the wire); the AID binding rides in the SAN
    /// and the [`AUTHS_KERI_BINDING_OID`] extension.
    pub struct IssuedCert {
        /// The certificate, PEM-encoded.
        pub cert_pem: String,
        /// The ephemeral TLS private key, PKCS#8 PEM. Hand to the TLS acceptor.
        pub key_pem: zeroize::Zeroizing<String>,
        /// The binding the cert embeds (for the caller to echo / log).
        pub binding: AuthsKeriBinding,
    }

    /// Issue a KEL-rooted leaf certificate for a resolved AID key-state.
    ///
    /// Generates a fresh P-256 TLS keypair, sets the subject CN and a
    /// `did:keri:<aid>` URI SAN, embeds the [`AuthsKeriBinding`] extension, and
    /// self-signs with the ephemeral key so a stock TLS stack completes a
    /// handshake. `extra_sans` carries the transport host names/IPs the cert must
    /// also be valid for (e.g. `localhost`, `127.0.0.1`) — without them a
    /// hostname-checking client would reject the leaf even though the binding is
    /// sound.
    pub fn issue_kel_rooted_cert(
        state: &KeyState,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let binding = AuthsKeriBinding::from_key_state(state)?;
        let key_pair =
            KeyPair::generate().map_err(|e| TlsCertError::KeyPair(format!("generate: {e}")))?;
        issue_with_keypair(&binding, &key_pair, extra_sans)
    }

    /// Issue a KEL-rooted leaf from an existing PKCS#8-PEM TLS keypair.
    ///
    /// The deterministic path used by tests and by callers that already hold a
    /// TLS key. The key is the cert's subject key and self-signs the leaf.
    pub fn issue_kel_rooted_cert_with_key(
        state: &KeyState,
        tls_key_pkcs8_pem: &str,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let binding = AuthsKeriBinding::from_key_state(state)?;
        let key_pair = KeyPair::from_pem(tls_key_pkcs8_pem)
            .map_err(|e| TlsCertError::KeyPair(format!("from pem: {e}")))?;
        issue_with_keypair(&binding, &key_pair, extra_sans)
    }

    fn issue_with_keypair(
        binding: &AuthsKeriBinding,
        key_pair: &KeyPair,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| TlsCertError::Generate(format!("params: {e}")))?;

        // Subject CN = the did:keri DID, so the identity is visible even in tools
        // that only print the subject.
        params
            .distinguished_name
            .push(DnType::CommonName, binding.did_keri());

        // SAN: the did:keri URI (the SPIFFE X.509-SVID identity-in-SAN pattern)
        // plus any transport hostnames/IPs the leaf must serve.
        let did_uri = Ia5String::try_from(binding.did_keri())
            .map_err(|e| TlsCertError::Generate(format!("did:keri SAN: {e}")))?;
        params.subject_alt_names.push(SanType::URI(did_uri));
        for san in extra_sans {
            params.subject_alt_names.push(san_for(san)?);
        }

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // The KEL binding: a non-critical extension carrying the replayed
        // key-state, DER-wrapped as an OCTET STRING (the standard envelope for an
        // opaque extension value).
        let content = yasna_octet_string(&binding.to_canonical_json());
        let mut ext = CustomExtension::from_oid_content(AUTHS_KERI_BINDING_OID, content);
        ext.set_criticality(false);
        params.custom_extensions.push(ext);

        let cert = params
            .self_signed(key_pair)
            .map_err(|e| TlsCertError::Generate(format!("self-sign: {e}")))?;

        Ok(IssuedCert {
            cert_pem: cert.pem(),
            key_pem: zeroize::Zeroizing::new(key_pair.serialize_pem()),
            binding: binding.clone(),
        })
    }

    /// Build a SAN entry from a host string: an IP literal becomes an IP SAN,
    /// anything else a DNS SAN (matching how `rcgen`/stock stacks treat hosts).
    fn san_for(host: &str) -> Result<SanType, TlsCertError> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            Ok(SanType::IpAddress(ip))
        } else {
            let dns = Ia5String::try_from(host.to_string())
                .map_err(|e| TlsCertError::Generate(format!("DNS SAN {host:?}: {e}")))?;
            Ok(SanType::DnsName(dns))
        }
    }

    /// DER-encode `bytes` as an OCTET STRING (the extension value envelope).
    fn yasna_octet_string(bytes: &[u8]) -> Vec<u8> {
        yasna::construct_der(|w| w.write_bytes(bytes))
    }

    /// Extract the [`AuthsKeriBinding`] embedded in a PEM certificate.
    ///
    /// Reads the `AUTHS_KERI_BINDING_OID` extension, unwraps the OCTET STRING, and
    /// parses the canonical JSON. Errors classify the failure precisely:
    /// [`TlsCertError::MissingBinding`] when there is no such extension (a plain
    /// cert), [`TlsCertError::MalformedBinding`] when its content is not the
    /// expected envelope.
    pub fn extract_binding(cert_pem: &str) -> Result<AuthsKeriBinding, TlsCertError> {
        use x509_parser::prelude::*;

        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| TlsCertError::ParseCert(format!("PEM: {e}")))?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| TlsCertError::ParseCert(format!("DER: {e}")))?;

        let oid_str = oid_string(AUTHS_KERI_BINDING_OID);
        for ext in cert.extensions() {
            if ext.oid.to_id_string() == oid_str {
                let inner = unwrap_octet_string(ext.value)?;
                return AuthsKeriBinding::from_canonical_json(&inner);
            }
        }
        Err(TlsCertError::MissingBinding)
    }

    /// Read the `did:keri` URI SAN out of a PEM certificate, if present.
    pub fn extract_did_keri_san(cert_pem: &str) -> Result<Option<String>, TlsCertError> {
        use x509_parser::prelude::*;

        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| TlsCertError::ParseCert(format!("PEM: {e}")))?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| TlsCertError::ParseCert(format!("DER: {e}")))?;

        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let GeneralName::URI(uri) = name
                    && uri.starts_with(DID_KERI_SCHEME)
                {
                    return Ok(Some((*uri).to_string()));
                }
            }
        }
        Ok(None)
    }

    /// Verify a KEL-rooted certificate against an AID's KEL key-state.
    ///
    /// The peer→auths direction: parse the cert, read its embedded binding *and*
    /// its `did:keri` SAN, then assert both agree with `state` — the freshly
    /// replayed key-state of the KEL the verifier holds. Trust is rooted in the
    /// log: a cert whose embedded key-state diverges from a real replay is
    /// rejected ([`TlsCertError::BindingMismatch`]).
    pub fn verify_binds_to_key_state(
        cert_pem: &str,
        state: &KeyState,
    ) -> Result<AuthsKeriBinding, TlsCertError> {
        let expected = AuthsKeriBinding::from_key_state(state)?;
        let embedded = extract_binding(cert_pem)?;

        if embedded.aid != expected.aid {
            return Err(TlsCertError::BindingMismatch(format!(
                "AID {} in cert != {} from KEL replay",
                embedded.aid, expected.aid
            )));
        }
        if embedded.current_keys != expected.current_keys {
            return Err(TlsCertError::BindingMismatch(
                "current signing keys in cert do not match the KEL replay".to_string(),
            ));
        }
        if embedded.kel_tip != expected.kel_tip {
            return Err(TlsCertError::BindingMismatch(format!(
                "KEL tip {} in cert != {} from replay",
                embedded.kel_tip, expected.kel_tip
            )));
        }

        // The SAN must carry the same AID — the legacy-compat identity surface
        // must agree with the binding, or a tool reading only the SAN would trust
        // a different AID than the one the binding (and the KEL) attest.
        match extract_did_keri_san(cert_pem)? {
            Some(san) if san == expected.did_keri() => Ok(embedded),
            Some(san) => Err(TlsCertError::SanMismatch(format!(
                "SAN {san} != {}",
                expected.did_keri()
            ))),
            None => Err(TlsCertError::SanMismatch(
                "certificate carries no did:keri SAN".to_string(),
            )),
        }
    }

    /// Render an OID arc as the dotted string `x509-parser` exposes.
    fn oid_string(arc: &[u64]) -> String {
        arc.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Unwrap a DER OCTET STRING to its content bytes.
    fn unwrap_octet_string(der: &[u8]) -> Result<Vec<u8>, TlsCertError> {
        yasna::parse_der(der, |r| r.read_bytes())
            .map_err(|e| TlsCertError::MalformedBinding(format!("OCTET STRING: {e}")))
    }
}

#[cfg(feature = "tls-cert")]
pub use backend::{
    IssuedCert, extract_binding, extract_did_keri_san, issue_kel_rooted_cert,
    issue_kel_rooted_cert_with_key, verify_binds_to_key_state,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{CesrKey, Prefix, Said, Threshold};

    /// A single-key Ed25519 key-state at the given AID/key/tip.
    fn state(aid: &str, keys: &[&str], tip: &str) -> KeyState {
        KeyState::from_inception(
            Prefix::new_unchecked(aid.to_string()),
            keys.iter()
                .map(|k| CesrKey::new_unchecked(k.to_string()))
                .collect(),
            vec![Said::new_unchecked("ENext0".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked(tip.to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        )
    }

    fn ed25519_key(raw: &[u8; 32]) -> String {
        KeriPublicKey::ed25519(raw).unwrap().to_qb64().unwrap()
    }

    #[test]
    fn binding_projects_key_state() {
        let k = ed25519_key(&[7u8; 32]);
        let st = state("EAidAAA", &[&k], "ETip000");
        let b = AuthsKeriBinding::from_key_state(&st).unwrap();
        assert_eq!(b.aid, "EAidAAA");
        assert_eq!(b.current_keys, vec![k]);
        assert_eq!(b.kel_tip, "ETip000");
        assert_eq!(b.did_keri(), "did:keri:EAidAAA");
    }

    #[test]
    fn binding_rejects_undecodable_key_at_boundary() {
        let st = state("EAidAAA", &["Xnot-a-verkey"], "ETip000");
        assert!(matches!(
            AuthsKeriBinding::from_key_state(&st),
            Err(TlsCertError::Key(_))
        ));
    }

    #[test]
    fn binding_canonical_json_round_trips() {
        let k = ed25519_key(&[3u8; 32]);
        let st = state("EAidAAA", &[&k], "ETip000");
        let b = AuthsKeriBinding::from_key_state(&st).unwrap();
        let json = b.to_canonical_json();
        let back = AuthsKeriBinding::from_canonical_json(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn binding_json_field_order_is_canonical() {
        let k = ed25519_key(&[1u8; 32]);
        let st = state("EAidAAA", &[&k], "ETip000");
        let b = AuthsKeriBinding::from_key_state(&st).unwrap();
        let s = String::from_utf8(b.to_canonical_json()).unwrap();
        // aid, current_keys, kel_tip — struct order, preserve_order serde.
        let i_aid = s.find("\"aid\"").unwrap();
        let i_keys = s.find("\"current_keys\"").unwrap();
        let i_tip = s.find("\"kel_tip\"").unwrap();
        assert!(i_aid < i_keys && i_keys < i_tip, "field order: {s}");
    }

    #[test]
    fn malformed_binding_json_is_an_error_not_a_panic() {
        assert!(matches!(
            AuthsKeriBinding::from_canonical_json(b"not json"),
            Err(TlsCertError::MalformedBinding(_))
        ));
    }

    #[cfg(feature = "tls-cert")]
    mod backend_tests {
        use super::*;

        fn multi_state() -> (KeyState, Vec<String>) {
            let k1 = ed25519_key(&[1u8; 32]);
            let k2 = ed25519_key(&[2u8; 32]);
            let st = state(
                "EAidMultiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &[&k1, &k2],
                "ETipMultiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            (st, vec![k1, k2])
        }

        #[test]
        fn issued_cert_carries_binding_and_san() {
            let (st, keys) = multi_state();
            let issued =
                issue_kel_rooted_cert(&st, &["localhost".to_string(), "127.0.0.1".to_string()])
                    .unwrap();
            assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
            assert!(!issued.key_pem.is_empty());

            let binding = extract_binding(&issued.cert_pem).unwrap();
            assert_eq!(binding.aid, st.prefix.as_str());
            assert_eq!(binding.current_keys, keys);

            let san = extract_did_keri_san(&issued.cert_pem).unwrap();
            assert_eq!(san, Some(format!("did:keri:{}", st.prefix.as_str())));
        }

        #[test]
        fn issued_cert_verifies_against_the_same_key_state() {
            let (st, _) = multi_state();
            let issued = issue_kel_rooted_cert(&st, &["localhost".to_string()]).unwrap();
            let binding = verify_binds_to_key_state(&issued.cert_pem, &st).unwrap();
            assert_eq!(binding.aid, st.prefix.as_str());
        }

        #[test]
        fn cert_is_rejected_against_a_different_key_state() {
            let (st, _) = multi_state();
            let issued = issue_kel_rooted_cert(&st, &["localhost".to_string()]).unwrap();

            // A KEL replay that yields a different current key must not verify.
            let other_key = ed25519_key(&[9u8; 32]);
            let other = state(
                st.prefix.as_str(),
                &[&other_key],
                st.last_event_said.as_str(),
            );
            assert!(matches!(
                verify_binds_to_key_state(&issued.cert_pem, &other),
                Err(TlsCertError::BindingMismatch(_))
            ));
        }

        #[test]
        fn cert_is_rejected_against_a_different_aid() {
            let (st, _) = multi_state();
            let issued = issue_kel_rooted_cert(&st, &["localhost".to_string()]).unwrap();
            let k = ed25519_key(&[1u8; 32]);
            let other = state(
                "EAidOTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &[&k],
                "ETip",
            );
            assert!(matches!(
                verify_binds_to_key_state(&issued.cert_pem, &other),
                Err(TlsCertError::BindingMismatch(_))
            ));
        }

        #[test]
        fn plain_cert_has_no_binding() {
            // A cert minted without the extension reports MissingBinding, not a
            // false match — so a stock self-signed cert can't masquerade as
            // KEL-rooted.
            let kp = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            assert!(matches!(
                extract_binding(&cert.pem()),
                Err(TlsCertError::MissingBinding)
            ));
        }

        #[test]
        fn issue_with_supplied_key_is_deterministic_in_binding() {
            // Same KEL + same TLS key → identical embedded binding (the cert
            // serial/validity may differ, but the KEL projection is stable).
            let (st, _) = multi_state();
            let kp = rcgen::KeyPair::generate().unwrap();
            let pem = kp.serialize_pem();
            let a = issue_kel_rooted_cert_with_key(&st, &pem, &["localhost".to_string()]).unwrap();
            let b = issue_kel_rooted_cert_with_key(&st, &pem, &["localhost".to_string()]).unwrap();
            assert_eq!(
                extract_binding(&a.cert_pem).unwrap(),
                extract_binding(&b.cert_pem).unwrap()
            );
        }
    }
}
