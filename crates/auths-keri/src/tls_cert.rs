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
//! ## Unforgeability: the AID authorizes the TLS key
//!
//! The leaf carries its own ephemeral TLS keypair (so the long-term AID signing
//! key never goes on the wire). The binding to the key-state alone is *not*
//! unforgeable: a stock self-signed leaf only proves possession of the *TLS* key,
//! and anyone replaying a public KEL could project the same key-state into a leaf
//! minted over *their own* TLS key. So a KEL-rooted leaf additionally carries a
//! [`TlsKeyAuthorization`] — a KERI signature, by one of the AID's *current*
//! signing keys, over the leaf's `SubjectPublicKeyInfo` DER. That signature is the
//! proof the AID authorized *this* TLS key: an attacker who never held the AID's
//! signing key cannot produce it, even with the full public KEL in hand.
//!
//! The adversarial verifier ([`verify_authorized_against_key_state`]) re-roots
//! trust in the log and rejects every forgery class:
//!
//! * **forged binding** — a leaf whose embedded key-state matches the replay but
//!   whose TLS key the AID never signed → [`TlsCertError::Unauthorized`];
//! * **stripped binding / authorization** — a plain leaf, or one missing the
//!   authorization → [`TlsCertError::MissingBinding`] / [`TlsCertError::MissingAuthorization`];
//! * **revoked / rotated AID** — a leaf whose embedded key-state diverges from a
//!   fresh replay of the *current* KEL → [`TlsCertError::BindingMismatch`];
//! * **SAN spoof** — a `did:keri` SAN that disagrees with the binding →
//!   [`TlsCertError::SanMismatch`].
//!
//! Relay/MITM (a proof lifted off one TLS channel and replayed on another) is
//! rejected one layer up, by the session's channel binding to the TLS exporter;
//! the cert proves *who*, the channel binding proves *which connection*.
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

    /// The certificate carries no `did:keri` URI in its `subjectAltName` — there
    /// is no auths identity to read out of it (the X.509-SVID identity surface).
    #[error("certificate carries no did:keri subjectAltName")]
    NoSanIdentity,

    /// The `did:keri` SAN was present but its AID is not a valid KERI prefix.
    #[error("did:keri SAN carries an invalid AID: {0}")]
    InvalidSanAid(#[from] crate::types::KeriTypeError),

    /// The certificate binds to a key-state but carries no [`TlsKeyAuthorization`]
    /// — there is no proof the AID authorized this TLS key, so it is unforgeable
    /// only if rejected (the adversarial verifier requires the authorization).
    #[error("certificate carries no AID authorization over its TLS key")]
    MissingAuthorization,

    /// The authorization names a current-key index outside the replayed key-state.
    #[error("authorization key index {index} is out of range (key-state has {len} current keys)")]
    AuthorizationIndexOutOfRange {
        /// The out-of-range index the authorization claimed.
        index: usize,
        /// The number of current keys the replayed key-state actually has.
        len: usize,
    },

    /// A current signing key named by the key-state could not be decoded when
    /// checking the authorization (a malformed verkey reached the verifier).
    #[error("decode authorizing key: {0}")]
    AuthorizationKey(String),

    /// The authorization signature does not verify: the AID's current key did not
    /// sign this leaf's TLS public key, so the AID never authorized it (a forged
    /// binding, or a relayed/substituted leaf).
    #[error("AID did not authorize this TLS key: {0}")]
    Unauthorized(String),
}

/// A KERI signature, by one of the AID's *current* signing keys, over the leaf's
/// `SubjectPublicKeyInfo` DER — the proof the AID **authorized** this TLS key.
///
/// Without it, a KEL-rooted leaf only proves possession of the *TLS* key; with
/// it, the leaf proves the AID's controller (the holder of a current signing key)
/// bound *that specific* TLS key to the AID. Parse, don't validate: the signature
/// is held as raw bytes (hex on the wire) and `key_index` is the position in the
/// key-state's `current_keys` whose signature this is; an out-of-range index is an
/// error at verification, never a silent skip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsKeyAuthorization {
    /// The index, in the key-state's `current_keys`, of the signing key that
    /// produced `signature`. (Single-sig today; the index makes multi-sig
    /// authorization a forward-compatible extension, not a reshape.)
    pub key_index: usize,
    /// The detached signature over the leaf's `SubjectPublicKeyInfo` DER, raw
    /// bytes (serialized as hex inside the canonical JSON).
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
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
    /// The AID's authorization over the leaf's TLS key, when present. `None` for a
    /// binding that names only the key-state (the discovery / identity surface);
    /// the adversarial verifier ([`verify_authorized_against_key_state`]) requires
    /// it, so an unauthorized leaf cannot pass the security check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_authorization: Option<TlsKeyAuthorization>,
}

impl AuthsKeriBinding {
    /// Project a resolved [`KeyState`] into a certificate binding (no
    /// authorization yet — the key-state projection only).
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
            tls_key_authorization: None,
        })
    }

    /// The same projection, carrying the AID's authorization over the leaf's TLS
    /// key. This is the binding a KEL-rooted leaf embeds once the AID has signed
    /// its `SubjectPublicKeyInfo` DER.
    pub fn with_authorization(mut self, authorization: TlsKeyAuthorization) -> Self {
        self.tls_key_authorization = Some(authorization);
        self
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

/// A port: signs the leaf's `SubjectPublicKeyInfo` DER with one of the AID's
/// *current* signing keys, producing the authorization that proves the AID bound
/// this TLS key. The core never imports a concrete key store — an adapter (a
/// keychain-backed signer, a held seed) supplies the signature.
///
/// The contract: [`sign_tls_key`](TlsKeyAuthorizer::sign_tls_key) returns the
/// detached signature over `spki_der`, and [`current_key_index`] is the position
/// in the key-state's `current_keys` of the public key that signature verifies
/// against. The verifier checks the signature against exactly that key, so an
/// adapter that lies about either is caught at [`verify_authorized_against_key_state`].
pub trait TlsKeyAuthorizer {
    /// The index, in the key-state's `current_keys`, of the signing key used.
    fn current_key_index(&self) -> usize;
    /// Sign the leaf's `SubjectPublicKeyInfo` DER, returning the raw signature.
    fn sign_tls_key(&self, spki_der: &[u8]) -> Result<Vec<u8>, TlsCertError>;
}

/// Verify a [`TlsKeyAuthorization`] against a binding's `current_keys` and the
/// leaf's `SubjectPublicKeyInfo` DER — the unforgeability check.
///
/// The authorization must (1) name an in-range current-key index, (2) reference a
/// decodable verkey, and (3) carry a signature that verifies, under that key, over
/// the leaf's SPKI DER. Any failure is a rejection: the AID did not authorize this
/// TLS key. Shared by every verify direction so there is one source of truth for
/// "the AID signed this leaf." Only the cert backend (the `tls-cert` feature)
/// extracts an SPKI to check, so it is gated alongside it.
#[cfg(feature = "tls-cert")]
fn check_tls_key_authorization(
    authorization: &TlsKeyAuthorization,
    current_keys: &[String],
    spki_der: &[u8],
) -> Result<(), TlsCertError> {
    let key_str = current_keys.get(authorization.key_index).ok_or(
        TlsCertError::AuthorizationIndexOutOfRange {
            index: authorization.key_index,
            len: current_keys.len(),
        },
    )?;
    let key =
        KeriPublicKey::parse(key_str).map_err(|e| TlsCertError::AuthorizationKey(e.to_string()))?;
    key.verify_signature(spki_der, &authorization.signature)
        .map_err(TlsCertError::Unauthorized)
}

#[cfg(feature = "tls-cert")]
mod backend {
    use super::*;

    use rcgen::string::Ia5String;
    use rcgen::{
        CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, PublicKeyData, SanType,
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

    /// Issue a KEL-rooted leaf whose TLS key the AID has **authorized**.
    ///
    /// Generates a fresh ephemeral TLS keypair, has `authorizer` sign that key's
    /// `SubjectPublicKeyInfo` DER with one of the AID's current signing keys, and
    /// embeds the resulting [`TlsKeyAuthorization`] in the binding. The leaf is
    /// then unforgeable: only the AID's controller can produce the authorization,
    /// so an attacker replaying the public KEL cannot mint a leaf over a TLS key of
    /// their own choosing.
    pub fn issue_authorized_kel_rooted_cert(
        state: &KeyState,
        authorizer: &dyn TlsKeyAuthorizer,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let key_pair =
            KeyPair::generate().map_err(|e| TlsCertError::KeyPair(format!("generate: {e}")))?;
        issue_authorized_with_keypair(state, authorizer, &key_pair, extra_sans)
    }

    /// The deterministic-key counterpart of [`issue_authorized_kel_rooted_cert`]:
    /// authorize and issue over an existing PKCS#8-PEM TLS keypair.
    pub fn issue_authorized_kel_rooted_cert_with_key(
        state: &KeyState,
        authorizer: &dyn TlsKeyAuthorizer,
        tls_key_pkcs8_pem: &str,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let key_pair = KeyPair::from_pem(tls_key_pkcs8_pem)
            .map_err(|e| TlsCertError::KeyPair(format!("from pem: {e}")))?;
        issue_authorized_with_keypair(state, authorizer, &key_pair, extra_sans)
    }

    fn issue_authorized_with_keypair(
        state: &KeyState,
        authorizer: &dyn TlsKeyAuthorizer,
        key_pair: &KeyPair,
        extra_sans: &[String],
    ) -> Result<IssuedCert, TlsCertError> {
        let base = AuthsKeriBinding::from_key_state(state)?;

        // The leaf's SubjectPublicKeyInfo DER — the exact bytes the verifier reads
        // back out of the parsed certificate. Signing these binds the AID to *this*
        // TLS key (one source of truth for "what the AID signed").
        let spki_der = key_pair.subject_public_key_info();
        let key_index = authorizer.current_key_index();
        if base.current_keys.get(key_index).is_none() {
            return Err(TlsCertError::AuthorizationIndexOutOfRange {
                index: key_index,
                len: base.current_keys.len(),
            });
        }
        let signature = authorizer.sign_tls_key(&spki_der)?;
        let authorization = TlsKeyAuthorization {
            key_index,
            signature,
        };
        // Reject an authorizer that signed with a key that doesn't match its
        // claimed current key before the leaf ever leaves the issuer.
        check_tls_key_authorization(&authorization, &base.current_keys, &spki_der)?;

        let binding = base.with_authorization(authorization);
        issue_with_keypair(&binding, key_pair, extra_sans)
    }

    /// Mint a leaf embedding `binding` over `key_pair`. `pub(crate)` so the
    /// crate's adversarial tests can craft a leaf with a hand-built (e.g. forged)
    /// binding; production callers go through the `issue_*` entry points which
    /// build the binding from a replayed key-state.
    pub(crate) fn issue_with_keypair(
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

    /// Read the AID a certificate claims out of its `did:keri` SAN — the
    /// X.509-SVID identity surface.
    ///
    /// This is the identity-discovery direction (the SPIFFE X.509-SVID precedent):
    /// the AID rides in the `subjectAltName` URI every stock X.509 parser already
    /// exposes, so a verifier learns *which* auths identity a peer claims directly
    /// from the cert — **before** it holds that AID's KEL. The returned [`Prefix`]
    /// is then the lookup key to fetch and replay the KEL (via an OOBI / a held
    /// log), at which point [`verify_binds_to_key_state`] re-roots trust in the
    /// log. Parse, don't validate: the scheme is stripped and the AID is parsed
    /// into a validated [`Prefix`], so a present-but-malformed identifier is
    /// [`TlsCertError::InvalidSanAid`] at the boundary, never a raw string the
    /// caller has to re-check. A cert with no `did:keri` URI SAN is
    /// [`TlsCertError::NoSanIdentity`] (a plain leaf carries no auths identity).
    pub fn extract_aid_from_san(cert_pem: &str) -> Result<crate::types::Prefix, TlsCertError> {
        match extract_did_keri_san(cert_pem)? {
            Some(uri) => {
                let aid = uri.strip_prefix(DID_KERI_SCHEME).ok_or_else(|| {
                    TlsCertError::SanMismatch(format!("SAN {uri} is not a {DID_KERI_SCHEME} URI"))
                })?;
                Ok(crate::types::Prefix::new(aid.to_string())?)
            }
            None => Err(TlsCertError::NoSanIdentity),
        }
    }

    /// Read the leaf's `SubjectPublicKeyInfo` DER — the exact bytes the AID's
    /// authorization signature covers. Re-derived from the parsed certificate, so
    /// the verifier signs/checks over the canonical encoding (not a re-serialized
    /// approximation).
    pub fn extract_spki_der(cert_pem: &str) -> Result<Vec<u8>, TlsCertError> {
        use x509_parser::prelude::*;

        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| TlsCertError::ParseCert(format!("PEM: {e}")))?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| TlsCertError::ParseCert(format!("DER: {e}")))?;
        Ok(cert.public_key().raw.to_vec())
    }

    /// Assert a parsed binding and the cert's SAN both agree with the replayed
    /// key-state. The shared "the leaf chains to the log" check, with no
    /// authorization — used directly by [`verify_binds_to_key_state`] and as the
    /// first half of [`verify_authorized_against_key_state`].
    fn check_binds_to_key_state(
        cert_pem: &str,
        embedded: &AuthsKeriBinding,
        expected: &AuthsKeriBinding,
    ) -> Result<(), TlsCertError> {
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
            Some(san) if san == expected.did_keri() => Ok(()),
            Some(san) => Err(TlsCertError::SanMismatch(format!(
                "SAN {san} != {}",
                expected.did_keri()
            ))),
            None => Err(TlsCertError::SanMismatch(
                "certificate carries no did:keri SAN".to_string(),
            )),
        }
    }

    /// Verify a KEL-rooted certificate against an AID's KEL key-state.
    ///
    /// The peer→auths direction: parse the cert, read its embedded binding *and*
    /// its `did:keri` SAN, then assert both agree with `state` — the freshly
    /// replayed key-state of the KEL the verifier holds. Trust is rooted in the
    /// log: a cert whose embedded key-state diverges from a real replay is
    /// rejected ([`TlsCertError::BindingMismatch`]).
    ///
    /// This checks the leaf *chains to* the log; it does **not** check the AID
    /// authorized the leaf's TLS key. For the adversarial guarantee (rejecting a
    /// forged binding minted over an attacker's TLS key) use
    /// [`verify_authorized_against_key_state`].
    pub fn verify_binds_to_key_state(
        cert_pem: &str,
        state: &KeyState,
    ) -> Result<AuthsKeriBinding, TlsCertError> {
        let expected = AuthsKeriBinding::from_key_state(state)?;
        let embedded = extract_binding(cert_pem)?;
        check_binds_to_key_state(cert_pem, &embedded, &expected)?;
        Ok(embedded)
    }

    /// The adversarial verifier (T3): a leaf passes only if it chains to the log
    /// **and** the AID authorized its TLS key.
    ///
    /// On top of [`verify_binds_to_key_state`], this requires the embedded
    /// [`TlsKeyAuthorization`] and checks it against the leaf's
    /// `SubjectPublicKeyInfo` DER and the *replayed* current keys. The rejection
    /// classes, each a distinct error:
    ///
    /// * a plain leaf (no extension) → [`TlsCertError::MissingBinding`];
    /// * a leaf whose key-state diverges from the replay (revoked / rotated AID) →
    ///   [`TlsCertError::BindingMismatch`];
    /// * a leaf whose SAN disagrees with the binding → [`TlsCertError::SanMismatch`];
    /// * a leaf with no authorization (stripped) → [`TlsCertError::MissingAuthorization`];
    /// * a leaf whose authorization does not verify under a current key — a forged
    ///   binding minted over a TLS key the AID never signed →
    ///   [`TlsCertError::Unauthorized`].
    pub fn verify_authorized_against_key_state(
        cert_pem: &str,
        state: &KeyState,
    ) -> Result<AuthsKeriBinding, TlsCertError> {
        let expected = AuthsKeriBinding::from_key_state(state)?;
        let embedded = extract_binding(cert_pem)?;
        check_binds_to_key_state(cert_pem, &embedded, &expected)?;

        let authorization = embedded
            .tls_key_authorization
            .as_ref()
            .ok_or(TlsCertError::MissingAuthorization)?;
        let spki_der = extract_spki_der(cert_pem)?;
        // Check against the *replayed* current keys, not the embedded ones: the
        // binding's keys were already asserted equal to the replay, but rooting the
        // authorization check in the replay keeps the log the single source of truth.
        check_tls_key_authorization(authorization, &expected.current_keys, &spki_der)?;
        Ok(embedded)
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
    IssuedCert, extract_aid_from_san, extract_binding, extract_did_keri_san, extract_spki_der,
    issue_authorized_kel_rooted_cert, issue_authorized_kel_rooted_cert_with_key,
    issue_kel_rooted_cert, issue_kel_rooted_cert_with_key, verify_authorized_against_key_state,
    verify_binds_to_key_state,
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
        // The crate-internal mint-with-binding entry point, for crafting leaves
        // with hand-built (forged / out-of-range) bindings in the adversarial tests.
        use crate::tls_cert::backend::issue_with_keypair;
        use rcgen::PublicKeyData;

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

        /// A test [`TlsKeyAuthorizer`] backed by a ring Ed25519 keypair. Signs the
        /// SPKI directly (no `native` feature needed for the crate's own tests).
        struct Ed25519Authorizer {
            keypair: ring::signature::Ed25519KeyPair,
            key_index: usize,
        }

        impl Ed25519Authorizer {
            fn from_seed(seed: &[u8; 32], key_index: usize) -> Self {
                let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
                Self { keypair, key_index }
            }
            /// The CESR-qualified current key string this authorizer's key occupies.
            fn cesr_key(&self) -> String {
                use ring::signature::KeyPair;
                let raw: [u8; 32] = self.keypair.public_key().as_ref().try_into().unwrap();
                ed25519_key(&raw)
            }
        }

        impl TlsKeyAuthorizer for Ed25519Authorizer {
            fn current_key_index(&self) -> usize {
                self.key_index
            }
            fn sign_tls_key(&self, spki_der: &[u8]) -> Result<Vec<u8>, TlsCertError> {
                Ok(self.keypair.sign(spki_der).as_ref().to_vec())
            }
        }

        /// A single-key key-state whose current key is `auth`'s public key, plus a
        /// matching authorizer at index 0. The standard authorized-cert fixture.
        fn authorized_state(seed: &[u8; 32]) -> (KeyState, Ed25519Authorizer) {
            let auth = Ed25519Authorizer::from_seed(seed, 0);
            let key = auth.cesr_key();
            let st = state(
                "EAidAuthAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &[&key],
                "ETipAuthAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            (st, auth)
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
        fn aid_reads_out_of_the_san_without_the_kel() {
            // The X.509-SVID identity surface: a verifier learns *which* AID a
            // cert claims from the SAN alone, before it holds the KEL.
            let (st, _) = multi_state();
            let issued = issue_kel_rooted_cert(&st, &["localhost".to_string()]).unwrap();
            let aid = extract_aid_from_san(&issued.cert_pem).unwrap();
            assert_eq!(aid.as_str(), st.prefix.as_str());
        }

        #[test]
        fn plain_cert_has_no_san_identity() {
            // A stock self-signed leaf carries no did:keri SAN, so there is no
            // auths identity to read out of it — NoSanIdentity, not a panic.
            let kp = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            assert!(matches!(
                extract_aid_from_san(&cert.pem()),
                Err(TlsCertError::NoSanIdentity)
            ));
        }

        #[test]
        fn malformed_san_aid_is_rejected_at_the_boundary() {
            // A did:keri SAN whose AID is not a valid KERI prefix is an error at
            // the parse boundary, never returned as a trusted identity.
            let kp = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            let bad = rcgen::string::Ia5String::try_from("did:keri:".to_string()).unwrap();
            params.subject_alt_names.push(rcgen::SanType::URI(bad));
            let cert = params.self_signed(&kp).unwrap();
            assert!(matches!(
                extract_aid_from_san(&cert.pem()),
                Err(TlsCertError::InvalidSanAid(_))
            ));
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

        // --- T3 adversarial verifier: the AID authorizes the TLS key ---

        #[test]
        fn authorized_cert_carries_authorization_and_verifies() {
            // The happy path: an AID-authorized leaf carries the authorization and
            // passes the adversarial verifier against its own replayed key-state.
            let (st, auth) = authorized_state(&[7u8; 32]);
            let issued =
                issue_authorized_kel_rooted_cert(&st, &auth, &["localhost".to_string()]).unwrap();

            let embedded = extract_binding(&issued.cert_pem).unwrap();
            assert!(
                embedded.tls_key_authorization.is_some(),
                "an authorized leaf must embed the authorization"
            );

            let binding = verify_authorized_against_key_state(&issued.cert_pem, &st).unwrap();
            assert_eq!(binding.aid, st.prefix.as_str());
        }

        #[test]
        fn forged_binding_over_attackers_tls_key_is_rejected() {
            // The core forgery: an attacker replays the victim's *public* KEL, so
            // the binding's key-state matches a real replay — but mints the leaf
            // over their own TLS key with no valid authorization. The adversarial
            // verifier rejects it (the AID never signed this TLS key), even though
            // the key-state binding alone would "match".
            let (st, _auth) = authorized_state(&[7u8; 32]);

            // Attacker forges a binding that names the correct key-state but signs
            // the SPKI with a key they DO hold — which is not the AID's key.
            let attacker = Ed25519Authorizer::from_seed(&[99u8; 32], 0);
            let forged_kp = rcgen::KeyPair::generate().unwrap();
            let spki = forged_kp.subject_public_key_info();
            let forged_sig = attacker.sign_tls_key(&spki).unwrap();
            // Build the cert by hand: correct key-state binding (matches replay),
            // but the embedded authorization is the attacker's signature.
            let binding = AuthsKeriBinding::from_key_state(&st)
                .unwrap()
                .with_authorization(TlsKeyAuthorization {
                    key_index: 0,
                    signature: forged_sig,
                });
            let issued =
                issue_with_keypair(&binding, &forged_kp, &["localhost".to_string()]).unwrap();

            // The key-state binding "matches" the replay (forged from the public KEL)...
            assert!(verify_binds_to_key_state(&issued.cert_pem, &st).is_ok());
            // ...but the AID's current key did not sign this TLS SPKI → Unauthorized.
            assert!(matches!(
                verify_authorized_against_key_state(&issued.cert_pem, &st),
                Err(TlsCertError::Unauthorized(_))
            ));
        }

        #[test]
        fn stripped_authorization_is_rejected() {
            // A leaf that chains to the key-state but carries NO authorization (the
            // discovery-only binding) is rejected by the adversarial verifier — a
            // KEL-rooted leaf must prove the AID authorized its TLS key.
            let (st, _auth) = authorized_state(&[7u8; 32]);
            let unauthorized = issue_kel_rooted_cert(&st, &["localhost".to_string()]).unwrap();
            assert!(matches!(
                verify_authorized_against_key_state(&unauthorized.cert_pem, &st),
                Err(TlsCertError::MissingAuthorization)
            ));
        }

        #[test]
        fn stripped_binding_plain_cert_is_rejected() {
            // A plain self-signed leaf (no binding extension at all) is rejected —
            // MissingBinding, before any authorization check.
            let (st, _auth) = authorized_state(&[7u8; 32]);
            let kp = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            let plain = params.self_signed(&kp).unwrap();
            assert!(matches!(
                verify_authorized_against_key_state(&plain.pem(), &st),
                Err(TlsCertError::MissingBinding)
            ));
        }

        #[test]
        fn revoked_or_rotated_aid_is_rejected() {
            // A leaf authorized under the AID's *old* key-state is rejected once the
            // verifier replays the *current* KEL (rotated/revoked): the binding's
            // key-state no longer matches the replay → BindingMismatch, before the
            // authorization is even checked.
            let (old_state, auth) = authorized_state(&[7u8; 32]);
            let issued =
                issue_authorized_kel_rooted_cert(&old_state, &auth, &["localhost".to_string()])
                    .unwrap();

            // The current key-state after a rotation: a different current key.
            let rotated_key = ed25519_key(&[8u8; 32]);
            let current_state = state(
                old_state.prefix.as_str(),
                &[&rotated_key],
                "ETipRotatedAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            assert!(matches!(
                verify_authorized_against_key_state(&issued.cert_pem, &current_state),
                Err(TlsCertError::BindingMismatch(_))
            ));
        }

        #[test]
        fn authorization_with_out_of_range_index_is_rejected() {
            // An authorization that names a current-key index the key-state does
            // not have is rejected, not silently skipped.
            let (st, auth) = authorized_state(&[7u8; 32]);
            let kp = rcgen::KeyPair::generate().unwrap();
            let spki = kp.subject_public_key_info();
            let sig = auth.sign_tls_key(&spki).unwrap();
            let binding = AuthsKeriBinding::from_key_state(&st)
                .unwrap()
                .with_authorization(TlsKeyAuthorization {
                    key_index: 5, // out of range: single-key state
                    signature: sig,
                });
            let issued = issue_with_keypair(&binding, &kp, &["localhost".to_string()]).unwrap();
            assert!(matches!(
                verify_authorized_against_key_state(&issued.cert_pem, &st),
                Err(TlsCertError::AuthorizationIndexOutOfRange { index: 5, len: 1 })
            ));
        }

        #[test]
        fn issuer_rejects_authorizer_signing_with_wrong_key() {
            // Defense at issuance: an authorizer whose signing key does not match
            // the current key it claims is caught before the leaf is emitted, so a
            // miswired adapter can't mint a leaf that will only fail at the verifier.
            let (st, _auth) = authorized_state(&[7u8; 32]);
            // An authorizer at index 0 but holding a key that is NOT the state's key.
            let wrong = Ed25519Authorizer::from_seed(&[42u8; 32], 0);
            assert!(matches!(
                issue_authorized_kel_rooted_cert(&st, &wrong, &["localhost".to_string()]),
                Err(TlsCertError::Unauthorized(_))
            ));
        }

        #[test]
        fn issuer_rejects_out_of_range_authorizer_index() {
            // An authorizer claiming a key index the state lacks is rejected at
            // issuance, before signing.
            let (st, _auth) = authorized_state(&[7u8; 32]);
            let bad_index = Ed25519Authorizer::from_seed(&[7u8; 32], 9);
            assert!(matches!(
                issue_authorized_kel_rooted_cert(&st, &bad_index, &["localhost".to_string()]),
                Err(TlsCertError::AuthorizationIndexOutOfRange { index: 9, len: 1 })
            ));
        }

        #[test]
        fn authorization_round_trips_through_binding_json() {
            // The authorization survives canonical-JSON round-trip (the wire form
            // inside the cert extension), so a verifier reads back exactly what the
            // issuer embedded.
            let (st, auth) = authorized_state(&[7u8; 32]);
            let issued =
                issue_authorized_kel_rooted_cert(&st, &auth, &["localhost".to_string()]).unwrap();
            let embedded = extract_binding(&issued.cert_pem).unwrap();
            let json = embedded.to_canonical_json();
            let back = AuthsKeriBinding::from_canonical_json(&json).unwrap();
            assert_eq!(back, embedded);
            assert!(back.tls_key_authorization.is_some());
        }
    }
}
