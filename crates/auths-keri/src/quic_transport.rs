//! HTTP/3-grade QUIC transport for the KEL-rooted TLS composition.
//!
//! The KEL-rooted X.509 leaf ([`crate::tls_cert`]) and the per-connection
//! channel binding it carries are not specific to TLS-over-TCP: QUIC runs the
//! **same TLS 1.3 handshake** inside its CRYPTO frames (RFC 9001), so an auths
//! identity composes with QUIC — and therefore HTTP/3 — through exactly the same
//! two mechanisms it composes with TLS:
//!
//! * **the leaf certificate** — a QUIC server presents the KEL-rooted leaf in its
//!   TLS 1.3 handshake just as a TLS-over-TCP server would; an auths-aware peer
//!   re-roots trust by replaying the KEL ([`crate::verify_binds_to_key_state`] /
//!   [`crate::verify_authorized_against_key_state`]). Trust lives in the log, not
//!   in a CA — over QUIC exactly as over TCP.
//! * **the channel binding** — both endpoints of one QUIC connection export the
//!   same keying material from the connection's TLS 1.3 secrets ([RFC 5705]
//!   exporter), so a possession proof folded against that material opens only on
//!   the connection that minted it. A proof captured on one QUIC connection and
//!   relayed onto another is rejected, the same anti-relay property the TCP path
//!   already has.
//!
//! This module is the QUIC **adapter** for those mechanisms. It builds a
//! [`quinn`] server config from a KEL-rooted leaf + key and a client config that
//! completes the handshake, and it exposes [`quic_channel_binding`] —
//! the [`quinn::Connection`] side of the keying-material exporter, the QUIC
//! counterpart of the rustls-over-TCP exporter the pairing daemon already uses.
//!
//! # Channel-binding parameters over QUIC (NORMATIVE)
//!
//! RFC 9266 `tls-exporter` specifies an *absent* exporter context, but the QUIC
//! public exporter API ([`quinn::Connection::export_keying_material`]) always
//! passes a context (it has no "absent" form). Both endpoints of an auths QUIC
//! connection are auths-aware, so they agree on a fixed label + context for their
//! binding; the per-connection, anti-relay property holds regardless of the
//! context value (it derives from the connection's own TLS 1.3 secrets). The
//! constants are:
//!
//! * **Label** [`QUIC_EXPORTER_LABEL`] = `EXPORTER-Channel-Binding` — the same
//!   registered RFC 9266 label the TCP path uses, so the two transports name the
//!   binding identically.
//! * **Context** [`QUIC_EXPORTER_CONTEXT`] = `auths-quic-channel-binding-v1` — the
//!   explicit context the QUIC API requires (an auths-internal domain separator,
//!   distinct from the TCP path's absent context, so a TCP and a QUIC binding for
//!   the same secrets can never collide).
//! * **Length** [`QUIC_EXPORTER_LEN`] = 32 bytes.
//!
//! [RFC 5705]: https://www.rfc-editor.org/rfc/rfc5705

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::pem::PemObject;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, ServerConfig as RustlsServerConfig,
    SignatureScheme,
};
use quinn::{ClientConfig, ServerConfig};
use subtle::ConstantTimeEq;

use crate::KeyState;

/// RFC 9266 exporter label, shared with the TCP channel-binding path so both
/// transports name the binding identically.
pub const QUIC_EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The exporter context the QUIC keying-material API requires (it has no
/// "absent" form). An auths-internal domain separator; both auths QUIC endpoints
/// pass exactly these bytes so they derive the same binding from one connection.
pub const QUIC_EXPORTER_CONTEXT: &[u8] = b"auths-quic-channel-binding-v1";

/// Length, in bytes, of the channel binding exported from a QUIC connection.
pub const QUIC_EXPORTER_LEN: usize = 32;

/// Errors building a QUIC transport from a KEL-rooted leaf, or extracting a
/// channel binding from a QUIC connection.
#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    /// A certificate or key PEM could not be parsed into the rustls types QUIC's
    /// TLS 1.3 stack needs.
    #[error("parse PEM material: {0}")]
    Pem(String),

    /// rustls / quinn refused to build the server or client TLS config (e.g. the
    /// key does not match the leaf, or the cipher suite is unavailable).
    #[error("build QUIC TLS config: {0}")]
    Config(String),

    /// The QUIC connection refused to export keying material — the handshake is
    /// not complete, or the connection is not TLS 1.3-capable. A connection that
    /// cannot produce a binding MUST NOT fall back to an unbound proof; this is
    /// surfaced so the caller fails closed.
    #[error("QUIC channel binding unavailable: {0}")]
    ExporterUnavailable(String),
}

/// Parse a certificate-chain PEM into the DER chain QUIC's TLS stack serves.
fn parse_cert_chain(cert_pem: &str) -> Result<Vec<CertificateDer<'static>>, QuicTransportError> {
    CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QuicTransportError::Pem(format!("certificate chain: {e}")))
}

/// Parse a PKCS#8 private-key PEM into the DER key QUIC's TLS stack signs with.
fn parse_private_key(key_pem: &str) -> Result<PrivateKeyDer<'static>, QuicTransportError> {
    PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| QuicTransportError::Pem(format!("private key: {e}")))
}

/// Build a [`quinn::ServerConfig`] that presents a KEL-rooted leaf over QUIC.
///
/// `cert_pem` is the leaf (the one [`crate::issue_kel_rooted_cert`] mints, with
/// the `did:keri` SAN + KEL binding extension); `key_pem` is its PKCS#8 private
/// key. The resulting config drives the TLS 1.3 handshake inside QUIC, so the
/// leaf — and the KEL binding it carries — is presented over HTTP/3 exactly as
/// over TLS-over-TCP. The peer re-roots trust by replaying the KEL.
pub fn quic_server_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<ServerConfig, QuicTransportError> {
    let certs = parse_cert_chain(cert_pem)?;
    let key = parse_private_key(key_pem)?;

    let mut tls = RustlsServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| QuicTransportError::Config(format!("TLS1.3 server: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| QuicTransportError::Config(format!("server cert: {e}")))?;
    // QUIC requires ALPN; advertise HTTP/3 ("h3") so the transport is HTTP/3-ready.
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = QuicServerConfig::try_from(tls)
        .map_err(|e| QuicTransportError::Config(format!("quic server tls: {e}")))?;
    Ok(ServerConfig::with_crypto(Arc::new(quic_tls)))
}

/// Build a [`quinn::ClientConfig`] that completes a QUIC handshake to a
/// KEL-rooted server.
///
/// Like [`crate::tls_cert`]'s verify model, certificate trust is re-rooted in the
/// **KEL**, not the WebPKI/CA chain: the client accepts the served leaf at the
/// TLS layer and the auths-aware caller then verifies the leaf binds to the AID's
/// replayed key-state out of band ([`crate::verify_binds_to_key_state`]). This is
/// the same separation the TCP path uses — TLS carries the pipe, the log carries
/// the trust.
pub fn quic_client_config() -> Result<ClientConfig, QuicTransportError> {
    let mut tls = RustlsClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| QuicTransportError::Config(format!("TLS1.3 client: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(KelRootedVerifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = QuicClientConfig::try_from(tls)
        .map_err(|e| QuicTransportError::Config(format!("quic client tls: {e}")))?;
    Ok(ClientConfig::new(Arc::new(quic_tls)))
}

/// Extract the per-connection channel binding from a live [`quinn::Connection`].
///
/// This is the QUIC adapter of the keying-material exporter the TCP path uses
/// over rustls. Both endpoints of one QUIC connection derive the **same** value
/// (it is a function of the connection's TLS 1.3 secrets); two independent
/// connections derive **different** values. Folding it into a proof scopes the
/// proof to the connection that minted it (anti-relay), over QUIC exactly as over
/// TCP.
///
/// The handshake MUST be complete; before it is, quinn returns an error and this
/// surfaces [`QuicTransportError::ExporterUnavailable`] so the caller fails closed
/// rather than minting an unbound, relay-able proof.
pub fn quic_channel_binding(
    conn: &quinn::Connection,
) -> Result<[u8; QUIC_EXPORTER_LEN], QuicTransportError> {
    let mut material = [0u8; QUIC_EXPORTER_LEN];
    conn.export_keying_material(&mut material, QUIC_EXPORTER_LABEL, QUIC_EXPORTER_CONTEXT)
        .map_err(|e| QuicTransportError::ExporterUnavailable(format!("{e:?}")))?;
    Ok(material)
}

/// The AWS-LC-rs crypto provider QUIC's TLS 1.3 stack uses — the same provider
/// the rest of auths's rustls usage runs on, so the cipher suites match.
fn crypto_provider() -> Arc<quinn::rustls::crypto::CryptoProvider> {
    Arc::new(quinn::rustls::crypto::aws_lc_rs::default_provider())
}

/// Certificate verifier that accepts the leaf at the TLS layer so the KEL replay
/// can re-root trust out of band.
///
/// The KEL-rooted leaf is self-signed (its trust is in the log, not a CA chain),
/// so a WebPKI verifier would reject it. The auths model is to accept it here and
/// verify the binding against the replayed key-state afterwards — trust is rooted
/// in the KEL, never in this TLS-layer acceptance. This mirrors the TCP path,
/// where the SPKI is pinned out-of-band and the binding is checked by replay.
#[derive(Debug)]
struct KelRootedVerifier;

impl ServerCertVerifier for KelRootedVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        // QUIC mandates TLS 1.3; a 1.2 signature path is unreachable here.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// The result of carrying the KEL-rooted composition over a QUIC loopback: the
/// identity that was served, whether both endpoints agreed on the channel
/// binding (the anti-relay property), and the binding itself (hex, for display).
#[derive(Debug, Clone)]
pub struct QuicLoopbackOutcome {
    /// The `did:keri:<aid>` the served leaf binds to (re-rooted in the replayed KEL).
    pub did_keri: String,
    /// Whether the two endpoints of the QUIC connection derived the **same**
    /// channel binding. True is the expected outcome — a proof folded against it
    /// opens only on this connection (anti-relay).
    pub binding_agrees: bool,
    /// The per-connection channel binding, hex-encoded, for display/logging.
    pub channel_binding_hex: String,
    /// The binding length in bytes ([`QUIC_EXPORTER_LEN`]).
    pub channel_binding_len: usize,
}

/// Carry the KEL-rooted composition over a real QUIC loopback connection.
///
/// Stands up a QUIC server on loopback serving the leaf (`cert_pem`/`key_pem`),
/// connects a client, completes the TLS 1.3 handshake inside QUIC, then proves
/// both composition mechanisms over QUIC:
///
/// * the **leaf** the client receives re-roots in the KEL — it is verified to bind
///   to `state`, the replayed key-state ([`crate::verify_binds_to_key_state`]);
/// * the **channel binding** both endpoints export from the connection is the same
///   ([`quic_channel_binding`]) — the per-connection value an anti-relay proof
///   folds against.
///
/// Returns the [`QuicLoopbackOutcome`]. A handshake or binding failure is a
/// [`QuicTransportError`] (the composition could not be carried over QUIC), and a
/// served leaf that does not bind to the KEL is a [`TlsCertError`] surfaced
/// through [`QuicTransportError::Config`].
pub async fn quic_loopback_compose(
    cert_pem: &str,
    key_pem: &str,
    state: &KeyState,
) -> Result<QuicLoopbackOutcome, QuicTransportError> {
    let server_cfg = quic_server_config(cert_pem, key_pem)?;
    let loopback = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let server = quinn::Endpoint::server(server_cfg, loopback)
        .map_err(|e| QuicTransportError::Config(format!("bind QUIC server: {e}")))?;
    let server_addr = server
        .local_addr()
        .map_err(|e| QuicTransportError::Config(format!("server local addr: {e}")))?;

    let mut client = quinn::Endpoint::client(loopback)
        .map_err(|e| QuicTransportError::Config(format!("bind QUIC client: {e}")))?;
    client.set_default_client_config(quic_client_config()?);

    // Accept on the server while the client connects — both ends of one handshake.
    let accept = async {
        let incoming = server
            .accept()
            .await
            .ok_or_else(|| QuicTransportError::Config("no inbound QUIC connection".to_string()))?;
        incoming
            .await
            .map_err(|e| QuicTransportError::Config(format!("server handshake: {e}")))
    };
    let connect = async {
        client
            .connect(server_addr, "localhost")
            .map_err(|e| QuicTransportError::Config(format!("client connect: {e}")))?
            .await
            .map_err(|e| QuicTransportError::Config(format!("client handshake: {e}")))
    };
    let (server_conn, client_conn) = tokio::try_join!(accept, connect)?;

    // Both ends export their channel binding; they must agree (per-connection).
    let client_cb = quic_channel_binding(&client_conn)?;
    let server_cb = quic_channel_binding(&server_conn)?;
    let binding_agrees = bool::from(client_cb.ct_eq(&server_cb));

    // The leaf the client received must re-root in the replayed KEL.
    let chain = client_conn
        .peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or_else(|| {
            QuicTransportError::Config("server presented no certificate over QUIC".to_string())
        })?;
    let leaf_der = chain
        .first()
        .ok_or_else(|| QuicTransportError::Config("empty certificate chain".to_string()))?;
    let observed_pem = pem_from_der(leaf_der);
    let binding = crate::verify_binds_to_key_state(&observed_pem, state).map_err(|e| {
        QuicTransportError::Config(format!("served leaf does not bind to KEL: {e}"))
    })?;

    // Close the endpoints so their UDP sockets are released promptly.
    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");

    Ok(QuicLoopbackOutcome {
        did_keri: binding.did_keri(),
        binding_agrees,
        channel_binding_hex: hex::encode(client_cb),
        channel_binding_len: QUIC_EXPORTER_LEN,
    })
}

/// Re-encode a DER certificate as PEM so the PEM-based KEL verifier can read the
/// leaf a QUIC peer presented.
fn pem_from_der(der: &CertificateDer<'_>) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};

    use quinn::{Endpoint, Incoming};

    use crate::tls_cert::{issue_kel_rooted_cert, verify_binds_to_key_state};
    use crate::types::{CesrKey, Prefix, Said, Threshold};
    use crate::{IssuedCert, KeriPublicKey, KeyState};

    /// A single-key Ed25519 key-state for a KEL-rooted leaf.
    fn sample_state() -> KeyState {
        let key = KeriPublicKey::ed25519(&[9u8; 32])
            .unwrap()
            .to_qb64()
            .unwrap();
        KeyState::from_inception(
            Prefix::new_unchecked("EQuicAidAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            vec![CesrKey::new_unchecked(key)],
            vec![Said::new_unchecked("ENext0".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ETipQuic000000000000000000000000000000000000".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        )
    }

    fn kel_rooted_leaf() -> IssuedCert {
        // localhost SANs so the leaf is valid for the loopback transport.
        issue_kel_rooted_cert(
            &sample_state(),
            &["localhost".to_string(), "::1".to_string()],
        )
        .expect("mint KEL-rooted leaf")
    }

    /// Stand up a QUIC server endpoint on loopback serving `leaf`, returning the
    /// endpoint and its bound address.
    fn server_endpoint(leaf: &IssuedCert) -> (Endpoint, SocketAddr) {
        let cfg = quic_server_config(&leaf.cert_pem, &leaf.key_pem).expect("server cfg");
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let ep = Endpoint::server(cfg, addr).expect("server endpoint");
        let bound = ep.local_addr().expect("local addr");
        (ep, bound)
    }

    /// Drive one full QUIC handshake to `server_addr` and return both endpoints'
    /// channel bindings plus the leaf the client observed.
    async fn handshake(
        client: &Endpoint,
        server: &Endpoint,
        server_addr: SocketAddr,
    ) -> (
        [u8; QUIC_EXPORTER_LEN],
        [u8; QUIC_EXPORTER_LEN],
        Vec<CertificateDer<'static>>,
    ) {
        let accept = async {
            let incoming: Incoming = server.accept().await.expect("incoming");
            incoming.await.expect("server connection")
        };
        let connect = async {
            client
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("client connection")
        };
        let (server_conn, client_conn) = tokio::join!(accept, connect);

        let client_cb = quic_channel_binding(&client_conn).expect("client binding");
        let server_cb = quic_channel_binding(&server_conn).expect("server binding");
        let peer_chain = client_conn
            .peer_identity()
            .expect("peer identity")
            .downcast::<Vec<CertificateDer<'static>>>()
            .expect("cert chain");
        (client_cb, server_cb, *peer_chain)
    }

    fn client_endpoint() -> Endpoint {
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let mut ep = Endpoint::client(addr).expect("client endpoint");
        ep.set_default_client_config(quic_client_config().expect("client cfg"));
        ep
    }

    #[tokio::test]
    async fn server_serves_kel_rooted_leaf_over_quic() {
        // The KEL-rooted leaf the client observes over the QUIC TLS 1.3 handshake
        // must be exactly the one the server holds, and it must bind to the KEL.
        let leaf = kel_rooted_leaf();
        let (server, addr) = server_endpoint(&leaf);
        let client = client_endpoint();

        let (_c, _s, chain) = handshake(&client, &server, addr).await;
        assert!(
            !chain.is_empty(),
            "server presented no certificate over QUIC"
        );

        // The served leaf re-roots in the KEL: replay the key-state and confirm the
        // leaf the client received binds to it — trust in the log, over QUIC.
        let observed_pem = pem_from_der(&chain[0]);
        let binding = verify_binds_to_key_state(&observed_pem, &sample_state())
            .expect("served leaf must bind to the KEL");
        assert_eq!(
            binding.did_keri(),
            "did:keri:EQuicAidAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[tokio::test]
    async fn both_endpoints_derive_the_same_binding() {
        // RFC 5705 over QUIC: both ends of one connection export the SAME keying
        // material — the agreement that lets a proof be scoped to the channel.
        let leaf = kel_rooted_leaf();
        let (server, addr) = server_endpoint(&leaf);
        let client = client_endpoint();

        let (client_cb, server_cb, _chain) = handshake(&client, &server, addr).await;
        assert_eq!(
            client_cb, server_cb,
            "both ends of one QUIC connection must derive the same channel binding"
        );
    }

    #[tokio::test]
    async fn independent_connections_derive_distinct_bindings() {
        // Two independent QUIC connections export DIFFERENT keying material — the
        // per-connection property the anti-relay guarantee rests on. A proof bound
        // to connection 1 cannot be replayed on connection 2.
        let leaf = kel_rooted_leaf();
        let (server, addr) = server_endpoint(&leaf);
        let client = client_endpoint();

        let (cb1, _s1, _c1) = handshake(&client, &server, addr).await;
        let (cb2, _s2, _c2) = handshake(&client, &server, addr).await;
        assert_ne!(
            cb1, cb2,
            "two independent QUIC connections must derive distinct bindings"
        );
    }

    /// Re-encode a DER certificate as PEM so the existing PEM-based KEL verifier
    /// can read the leaf the QUIC peer presented.
    fn pem_from_der(der: &CertificateDer<'_>) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}
