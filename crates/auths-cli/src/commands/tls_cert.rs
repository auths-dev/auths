//! `auths tls-cert` — KEL-rooted X.509 leaf certificates for TLS composition.
//!
//! TLS already authenticates endpoints through the WebPKI/CA system. This command
//! lets a KERI AID compose *with* that pipe rather than replace it: it issues an
//! X.509 leaf whose trust roots in the AID's key event log (a `did:keri:<aid>`
//! SAN plus a binding extension carrying the replayed key-state), so a stock TLS
//! stack — rustls, OpenSSL, BoringSSL, Go `crypto/tls` — completes a handshake
//! with it, while an AID-aware peer re-derives the trust by replaying the KEL.
//! That is how an auths identity deploys through every load balancer, mesh, and
//! client that already speaks TLS.
//!
//! Two directions, both offline/hermetic (the KEL handed in is a local artifact):
//!
//! * `auths tls-cert issue --from-kel kel.json --sign-key aid.key.pem` — us →
//!   peer: replay the KEL, project its current key-state into a KEL-rooted leaf,
//!   have the AID's current signing key authorize the leaf's TLS key (a KERI
//!   signature over the leaf SPKI), and emit the cert PEM plus the ephemeral TLS
//!   private key PEM the acceptor serves.
//! * `auths tls-cert verify --cert cert.pem --from-kel kel.json` — peer → us: the
//!   adversarial verifier. Parse a peer's leaf, replay the KEL we hold for its
//!   AID, and confirm the cert binds to that exact replayed key-state (AID,
//!   current keys, KEL tip, the `did:keri` SAN) **and** that the AID authorized
//!   the leaf's TLS key. Rejects a forged binding (matching key-state over an
//!   attacker's TLS key), a revoked/rotated AID, a stripped binding/authorization,
//!   and a SAN spoof. Trust is rooted in the log, never in a CA.
//!
//! The wire/crypto definition lives in `auths-keri::tls_cert`; this is a thin CLI
//! adapter over it. The cert's subject key is a fresh ephemeral TLS keypair, so
//! the AID's long-term signing key never goes on the wire — only its detached
//! authorization signature over the public TLS key does.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_crypto::TypedSignerKey;
use auths_keri::{
    IssuedCert, KeyState, QuicLoopbackOutcome, TlsCertError, TlsKeyAuthorizer, TrustedKel,
    extract_aid_from_san, issue_authorized_kel_rooted_cert,
    issue_authorized_kel_rooted_cert_with_key, issue_kel_rooted_cert,
    issue_kel_rooted_cert_with_key, parse_kel_json, quic_loopback_compose,
    verify_authorized_against_key_state,
};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use crate::config::CliConfig;

/// Adapter: a [`TlsKeyAuthorizer`] backed by the AID's current signing key.
///
/// The CLI holds the AID's signing key as a local PKCS#8 artifact (the same
/// hermetic boundary `--from-kel` / `--tls-key` already use); this adapter signs
/// the leaf's `SubjectPublicKeyInfo` DER with it so the issued leaf carries the
/// AID's authorization. The core `auths-keri` never imports a key store — it only
/// sees the port.
struct SignerKeyAuthorizer {
    signer: TypedSignerKey,
    key_index: usize,
}

impl TlsKeyAuthorizer for SignerKeyAuthorizer {
    fn current_key_index(&self) -> usize {
        self.key_index
    }

    fn sign_tls_key(&self, spki_der: &[u8]) -> Result<Vec<u8>, TlsCertError> {
        self.signer
            .sign(spki_der)
            .map_err(|e| TlsCertError::Generate(format!("authorize TLS key: {e}")))
    }
}

/// Load the AID's current signing key from a PKCS#8 PEM file into a typed signer.
fn load_signer(key_path: &Path) -> Result<TypedSignerKey> {
    let path = expand_tilde(key_path)?;
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("read signing key {}: {e}", path.display()))?;
    let (_, der) = pkcs8::SecretDocument::from_pem(&pem)
        .map_err(|e| anyhow!("parse signing key PEM {}: {e}", path.display()))?;
    TypedSignerKey::from_pkcs8(der.as_bytes())
        .map_err(|e| anyhow!("load signing key {}: {e}", path.display()))
}

/// Issue or verify a KEL-rooted X.509 certificate (TLS composition).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Issue/verify a KEL-rooted X.509 cert, read its did:keri subjectAltName, and carry it over TLS or QUIC/HTTP3 — an auths identity that stock TLS stacks (rustls/openssl/go) handshake with",
    after_help = "Examples:
  auths tls-cert issue --from-kel kel.json --sign-key aid.key.pem --san localhost   # AID-authorized leaf
  auths tls-cert issue --from-kel kel.json --sign-key aid.key.pem --out leaf         # writes leaf.cert.pem + leaf.key.pem
  auths tls-cert identity --cert leaf.cert.pem                                       # read the did:keri AID out of the SAN
  auths tls-cert verify --cert leaf.cert.pem --from-kel kel.json                     # adversarial: rejects forged/revoked/stripped
  auths tls-cert quic --from-kel kel.json                                            # carry the leaf + channel binding over QUIC/HTTP3"
)]
pub struct TlsCertCommand {
    /// The direction to run: issue our leaf, or verify a peer's.
    #[command(subcommand)]
    pub action: TlsCertAction,
}

/// The directions of KEL-rooted mTLS composition.
#[derive(Subcommand, Debug, Clone)]
pub enum TlsCertAction {
    /// Issue a KEL-rooted leaf certificate for an AID (us → peer).
    Issue(IssueArgs),
    /// Read the did:keri AID out of a leaf's subjectAltName (X.509-SVID identity).
    Identity(IdentityArgs),
    /// Verify a peer's leaf binds to the KEL we hold (peer → us).
    Verify(VerifyArgs),
    /// Carry the KEL-rooted leaf + channel binding over a QUIC/HTTP3 transport.
    Quic(QuicArgs),
}

/// `auths tls-cert issue` — mint a KEL-rooted leaf for one of our AIDs.
#[derive(Parser, Debug, Clone)]
pub struct IssueArgs {
    /// Replay this KEL file and project its current key-state into the leaf's
    /// `did:keri` SAN + binding extension. The KEL is the root of trust.
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: PathBuf,

    /// Extra Subject-Alternative-Name host the leaf must serve (DNS name or IP
    /// literal). Repeatable. Typically `localhost`, `127.0.0.1`, the LAN host.
    #[clap(long = "san", value_name = "HOST")]
    pub sans: Vec<String>,

    /// Use this PKCS#8-PEM TLS keypair as the leaf's subject key instead of a
    /// fresh ephemeral one (e.g. to reuse a key the acceptor already holds).
    #[clap(long, value_name = "KEY.pem")]
    pub tls_key: Option<PathBuf>,

    /// The AID's current signing key (PKCS#8 PEM). When given, the leaf carries an
    /// AID authorization over its TLS key (a KERI signature over the leaf SPKI), so
    /// `verify` can reject a forged binding minted over an attacker's TLS key.
    /// Without it the leaf only chains to the key-state (the discovery surface) and
    /// is rejected by the adversarial verifier.
    #[clap(long, value_name = "AID-KEY.pem")]
    pub sign_key: Option<PathBuf>,

    /// Which current key (index into the KEL's current key-state) `--sign-key`
    /// corresponds to. Defaults to 0 (single-sig AIDs).
    #[clap(long, default_value_t = 0, value_name = "N")]
    pub sign_key_index: usize,

    /// Write `<PREFIX>.cert.pem` + `<PREFIX>.key.pem` instead of printing to
    /// stdout. Without it, the cert PEM is printed (the key never is, to avoid
    /// leaking it into logs).
    #[clap(long, value_name = "PREFIX")]
    pub out: Option<PathBuf>,
}

/// `auths tls-cert identity` — read the did:keri AID out of a leaf's SAN.
#[derive(Parser, Debug, Clone)]
pub struct IdentityArgs {
    /// The leaf certificate, PEM-encoded. Its `did:keri` subjectAltName names the
    /// auths identity — the AID a verifier looks up before replaying its KEL.
    #[clap(long, value_name = "CERT.pem")]
    pub cert: PathBuf,
}

/// `auths tls-cert verify` — confirm a peer's leaf is rooted in a KEL we hold.
#[derive(Parser, Debug, Clone)]
pub struct VerifyArgs {
    /// The peer's leaf certificate, PEM-encoded.
    #[clap(long, value_name = "CERT.pem")]
    pub cert: PathBuf,

    /// Replay this KEL (the one we hold for the cert's AID) and require the cert
    /// to bind to its replayed key-state.
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: PathBuf,
}

/// `auths tls-cert quic` — carry the same composition over QUIC/HTTP3.
///
/// QUIC runs the same TLS 1.3 handshake inside its CRYPTO frames, so a KERI
/// identity composes with QUIC — and therefore HTTP/3 — through exactly the same
/// two mechanisms it composes with TLS-over-TCP: the KEL-rooted leaf the server
/// presents, and the per-connection channel binding both endpoints export from
/// the connection's TLS 1.3 secrets. This stands up a real loopback QUIC
/// connection, serves the leaf over it, and proves both — the client re-roots the
/// served leaf in the replayed KEL, and both endpoints derive the same channel
/// binding (a proof bound to it cannot be relayed onto a different connection).
#[derive(Parser, Debug, Clone)]
pub struct QuicArgs {
    /// Replay this KEL and serve its KEL-rooted leaf over the QUIC handshake. The
    /// KEL is the root of trust the client re-derives by replay — over QUIC
    /// exactly as over TCP.
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: PathBuf,
}

impl TlsCertCommand {
    /// Run the requested direction.
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.action {
            TlsCertAction::Issue(args) => args.run(),
            TlsCertAction::Identity(args) => args.run(),
            TlsCertAction::Verify(args) => args.run(),
            TlsCertAction::Quic(args) => args.run(),
        }
    }
}

/// Replay a KEL file into its resolved current key-state. A KEL file the operator
/// hands us is a local, self-owned artifact — the reviewable trust assertion that
/// structural replay requires (the same boundary `did-webs`/`oobi` use).
fn replay_kel(kel_path: &Path) -> Result<auths_keri::KeyState> {
    let path = expand_tilde(kel_path)?;
    let json =
        std::fs::read_to_string(&path).map_err(|e| anyhow!("read KEL {}: {e}", path.display()))?;
    let events = parse_kel_json(&json).map_err(|e| anyhow!("parse KEL: {e}"))?;
    TrustedKel::from_trusted_source(&events)
        .replay()
        .map_err(|e| anyhow!("replay KEL: {e}"))
}

impl IssueArgs {
    fn run(&self) -> Result<()> {
        let state = replay_kel(&self.from_kel)?;
        let issued = self.issue(&state)?;

        match &self.out {
            Some(prefix) => {
                let cert_path = with_suffix(prefix, "cert.pem");
                let key_path = with_suffix(prefix, "key.pem");
                std::fs::write(&cert_path, issued.cert_pem.as_bytes())
                    .map_err(|e| anyhow!("write {}: {e}", cert_path.display()))?;
                write_private_key(&key_path, &issued.key_pem)?;
                println!(
                    "issued KEL-rooted leaf for {}\n  cert: {}\n  key:  {}",
                    issued.binding.did_keri(),
                    cert_path.display(),
                    key_path.display()
                );
            }
            None => {
                // Cert only on stdout; the private key is never printed, so a
                // captured transcript can't leak it.
                print!("{}", issued.cert_pem);
            }
        }
        Ok(())
    }

    /// Mint the leaf, dispatching on whether the AID's signing key (authorized,
    /// the secure path) and/or a supplied TLS key are provided. One source of
    /// truth for the four issue paths.
    fn issue(&self, state: &KeyState) -> Result<auths_keri::IssuedCert> {
        let tls_key_pem = match &self.tls_key {
            Some(key_path) => {
                let path = expand_tilde(key_path)?;
                Some(
                    std::fs::read_to_string(&path)
                        .map_err(|e| anyhow!("read TLS key {}: {e}", path.display()))?,
                )
            }
            None => None,
        };

        match (&self.sign_key, tls_key_pem) {
            (Some(sign_key_path), Some(tls_pem)) => {
                let signer = load_signer(sign_key_path)?;
                let authorizer = SignerKeyAuthorizer {
                    signer,
                    key_index: self.sign_key_index,
                };
                issue_authorized_kel_rooted_cert_with_key(state, &authorizer, &tls_pem, &self.sans)
                    .map_err(|e| anyhow!("issue authorized KEL-rooted cert: {e}"))
            }
            (Some(sign_key_path), None) => {
                let signer = load_signer(sign_key_path)?;
                let authorizer = SignerKeyAuthorizer {
                    signer,
                    key_index: self.sign_key_index,
                };
                issue_authorized_kel_rooted_cert(state, &authorizer, &self.sans)
                    .map_err(|e| anyhow!("issue authorized KEL-rooted cert: {e}"))
            }
            (None, Some(tls_pem)) => issue_kel_rooted_cert_with_key(state, &tls_pem, &self.sans)
                .map_err(|e| anyhow!("issue KEL-rooted cert: {e}")),
            (None, None) => issue_kel_rooted_cert(state, &self.sans)
                .map_err(|e| anyhow!("issue KEL-rooted cert: {e}")),
        }
    }
}

impl IdentityArgs {
    fn run(&self) -> Result<()> {
        let cert_path = expand_tilde(&self.cert)?;
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| anyhow!("read cert {}: {e}", cert_path.display()))?;

        // The X.509-SVID identity read: the did:keri AID rides in the SAN every
        // stock X.509 parser already exposes, so we learn which identity the cert
        // claims before holding its KEL. The AID is parsed (not just extracted),
        // so what we print is a valid KERI prefix, not a raw string.
        let aid = extract_aid_from_san(&cert_pem)
            .map_err(|e| anyhow!("read did:keri identity from cert SAN: {e}"))?;

        println!(
            "did:keri:{aid}\n  AID: {aid}\n  (the SAN names the identity; replay its KEL to root trust in the log)"
        );
        Ok(())
    }
}

impl VerifyArgs {
    fn run(&self) -> Result<()> {
        let state = replay_kel(&self.from_kel)?;
        let cert_path = expand_tilde(&self.cert)?;
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| anyhow!("read cert {}: {e}", cert_path.display()))?;

        // The adversarial verifier: the leaf must chain to the replayed log AND
        // carry the AID's authorization over its TLS key. This rejects a forged
        // binding (matching key-state, attacker's TLS key), a revoked/rotated AID
        // (key-state diverges from the replay), a stripped binding/authorization,
        // and a SAN spoof — the T3 rejection classes.
        let binding = verify_authorized_against_key_state(&cert_pem, &state)
            .map_err(|e| anyhow!("certificate rejected: {e}"))?;

        let authorized_by = binding
            .tls_key_authorization
            .as_ref()
            .map(|a| a.key_index)
            .unwrap_or_default();
        println!(
            "verified: certificate is rooted in the KEL and the AID authorized its TLS key\n  did:keri: {}\n  current keys: {}\n  KEL tip: {}\n  TLS key authorized by current key #{}",
            binding.did_keri(),
            binding.current_keys.join(", "),
            binding.kel_tip,
            authorized_by,
        );
        Ok(())
    }
}

impl QuicArgs {
    fn run(&self) -> Result<()> {
        let state = replay_kel(&self.from_kel)?;
        // Mint the KEL-rooted leaf the QUIC server presents (localhost SANs so the
        // loopback handshake is valid for the transport host).
        let leaf = issue_kel_rooted_cert(&state, &["localhost".to_string(), "::1".to_string()])
            .map_err(|e| anyhow!("issue KEL-rooted leaf for QUIC: {e}"))?;

        // The loopback driver is a single Tokio runtime turn: stand up a QUIC
        // endpoint, serve the leaf, connect a client, complete the TLS 1.3
        // handshake inside QUIC, and prove the composition (leaf re-roots in the
        // KEL, both ends agree on the channel binding). The transport plumbing
        // lives in auths-keri; this command is the adapter.
        let outcome = run_quic_loopback(&leaf, &state)?;

        println!(
            "QUIC/HTTP3 composition verified — the KEL-rooted leaf and channel binding carry over QUIC\n  did:keri: {}\n  ALPN: h3 (HTTP/3)\n  served leaf re-rooted in the replayed KEL: yes\n  both endpoints derive the same channel binding (anti-relay): {}\n  channel binding: {} ({} bytes, per-connection)",
            outcome.did_keri,
            if outcome.binding_agrees { "yes" } else { "no" },
            outcome.channel_binding_hex,
            outcome.channel_binding_len,
        );
        Ok(())
    }
}

/// Drive the QUIC loopback composition on a fresh Tokio runtime.
///
/// `auths tls-cert` is otherwise synchronous; QUIC needs an async reactor, so we
/// spin a current-thread runtime for this one command rather than make the whole
/// CLI async. The transport itself lives behind [`quic_loopback_compose`] in
/// `auths-keri` — this is just the runtime adapter.
fn run_quic_loopback(leaf: &IssuedCert, state: &KeyState) -> Result<QuicLoopbackOutcome> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("build QUIC runtime: {e}"))?;
    rt.block_on(quic_loopback_compose(&leaf.cert_pem, &leaf.key_pem, state))
        .map_err(|e| anyhow!("QUIC composition failed: {e}"))
}

/// `prefix` + `.suffix`, preserving any directory in `prefix`.
fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let name = prefix
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    prefix.with_file_name(format!("{name}.{suffix}"))
}

/// Write the private key with owner-only permissions where the OS supports it,
/// so an issued key isn't left world-readable.
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem.as_bytes()).map_err(|e| anyhow!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| anyhow!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}
