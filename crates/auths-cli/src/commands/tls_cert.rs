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
//! * `auths tls-cert issue --from-kel kel.json` — us → peer: replay the KEL,
//!   project its current key-state into a KEL-rooted leaf, and emit the cert PEM
//!   plus the ephemeral TLS private key PEM the acceptor serves.
//! * `auths tls-cert verify --cert cert.pem --from-kel kel.json` — peer → us:
//!   parse a peer's leaf, replay the KEL we hold for its AID, and confirm the
//!   cert binds to that exact replayed key-state (AID, current keys, KEL tip, and
//!   the `did:keri` SAN). Trust is rooted in the log, never in a CA.
//!
//! The wire/crypto definition lives in `auths-keri::tls_cert`; this is a thin CLI
//! adapter over it. The cert's subject key is a fresh ephemeral TLS keypair, so
//! the AID's long-term signing key never goes on the wire.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_keri::{
    TrustedKel, extract_aid_from_san, issue_kel_rooted_cert, issue_kel_rooted_cert_with_key,
    parse_kel_json, verify_binds_to_key_state,
};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use crate::config::CliConfig;

/// Issue or verify a KEL-rooted X.509 certificate (TLS composition).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Issue/verify a KEL-rooted X.509 cert and read its did:keri subjectAltName — an auths identity that stock TLS stacks (rustls/openssl/go) handshake with",
    after_help = "Examples:
  auths tls-cert issue --from-kel kel.json --san localhost --san 127.0.0.1
  auths tls-cert issue --from-kel kel.json --out leaf            # writes leaf.cert.pem + leaf.key.pem
  auths tls-cert identity --cert leaf.cert.pem                   # read the did:keri AID out of the SAN
  auths tls-cert verify --cert leaf.cert.pem --from-kel kel.json"
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

impl TlsCertCommand {
    /// Run the requested direction.
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.action {
            TlsCertAction::Issue(args) => args.run(),
            TlsCertAction::Identity(args) => args.run(),
            TlsCertAction::Verify(args) => args.run(),
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

        let issued = match &self.tls_key {
            Some(key_path) => {
                let path = expand_tilde(key_path)?;
                let key_pem = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow!("read TLS key {}: {e}", path.display()))?;
                issue_kel_rooted_cert_with_key(&state, &key_pem, &self.sans)
                    .map_err(|e| anyhow!("issue KEL-rooted cert: {e}"))?
            }
            None => issue_kel_rooted_cert(&state, &self.sans)
                .map_err(|e| anyhow!("issue KEL-rooted cert: {e}"))?,
        };

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

        let binding = verify_binds_to_key_state(&cert_pem, &state)
            .map_err(|e| anyhow!("certificate does not chain to the KEL: {e}"))?;

        println!(
            "verified: certificate is rooted in the KEL\n  did:keri: {}\n  current keys: {}\n  KEL tip: {}",
            binding.did_keri(),
            binding.current_keys.join(", "),
            binding.kel_tip
        );
        Ok(())
    }
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
