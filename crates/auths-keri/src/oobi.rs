//! Out-Of-Band Introduction (OOBI) — KERI discovery.
//!
//! An OOBI is how one KERI controller tells another *"here is my AID, and here
//! is a URL at which you can fetch its key event log and service endpoints."* It
//! is the bootstrap of every live exchange: before a peer can request a receipt,
//! present a credential, or resolve a key-state, it must first discover *where*
//! the controlling AID's KEL and endpoints live. OOBIs carry that location
//! out-of-band (hence the name); the KEL fetched through one is still verified
//! cryptographically, so the URL is only a hint, never a root of trust.
//!
//! Two halves, mirroring the two directions of discovery:
//!
//! * **Resolve** (peer → us): parse a peer's OOBI URL into a typed [`Oobi`],
//!   fetch the bytes it points at, and [`ingest_oobi_stream`] them — replaying
//!   the embedded KEL into a verified [`KeyState`] and collecting the endpoint
//!   reply records the peer published alongside it.
//! * **Serve** (us → peer): from one of our own KELs and the URL we host it at,
//!   [`OobiEndpoint::for_controller`] derives the OOBI URL to publish and the
//!   `rpy` reply stream (`/loc/scheme` + `/end/role/add`) a peer fetches when it
//!   resolves us.
//!
//! The wire records are byte-exact with keripy 1.3.4: a `/loc/scheme` reply is
//! `{v, t:"rpy", d, dt, r:"/loc/scheme", a:{eid, scheme, url}}` and an
//! `/end/role/add` reply is `{v, t:"rpy", d, dt, r:"/end/role/add",
//! a:{cid, role, eid}}`, each SAID-ified and version-sized exactly as
//! `keri.app.habbing.Hab.reply`. The URL grammar is keripy's `OOBI_RE`
//! (`/oobi/{cid}/{role}[/{eid}]`).
//!
//! This module is I/O-free: it parses URLs, serializes/parses wire records, and
//! replays KELs. The HTTP fetch lives behind a port in the caller (the CLI's
//! OOBI adapter), so the discovery logic never imports a transport.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::error::KeriTranslationError;
use crate::events::KERI_VERSION_PREFIX;
use crate::said::{Protocol, compute_said_with_protocol};
use crate::state::KeyState;
use crate::types::{Prefix, Said};
use crate::validate::{TrustedKel, ValidationError, parse_kel_json};

/// Placeholder version string filled in during saidify (17 chars, like every
/// KERI record's `v`).
const KERI_VERSION_PLACEHOLDER: &str = "KERI10JSON000000_";

/// Sizes the version string `KERI10JSON{size:06x}_` to a serialized record — the
/// same single-pass machinery the TEL records use (the field width is constant,
/// so re-serializing with the placeholder gives the final byte length).
fn recompute_version_string<T: Serialize>(event: &T) -> Result<String, OobiError> {
    let bytes = serde_json::to_vec(event).map_err(KeriTranslationError::SerializationFailed)?;
    Ok(format!("{KERI_VERSION_PREFIX}{:06x}_", bytes.len()))
}

/// An authorized endpoint role in a KERI introduction.
///
/// Mirrors keripy's `kering.Roles` — the fixed vocabulary of what an endpoint
/// identifier (`eid`) is authorized to *do* for a controller (`cid`). Parsing is
/// total: an unknown role is rejected at the boundary, so an `Role` value is
/// always one keripy would accept in a `/end/role` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The controller itself (its own endpoint).
    Controller,
    /// A witness that receipts the controller's KEL.
    Witness,
    /// A watcher that observes the controller's KEL for duplicity.
    Watcher,
    /// A registrar of the controller's credential registries.
    Registrar,
    /// A judge in a multi-sig group.
    Judge,
    /// A juror in a multi-sig group.
    Juror,
    /// A peer in a direct-mode exchange.
    Peer,
    /// A mailbox that buffers messages for the controller.
    Mailbox,
    /// An agent acting on behalf of the controller (e.g. a KERIA agent).
    Agent,
    /// A gateway endpoint.
    Gateway,
}

impl Role {
    /// The keripy `kering.Roles` wire token for this role.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Controller => "controller",
            Role::Witness => "witness",
            Role::Watcher => "watcher",
            Role::Registrar => "registrar",
            Role::Judge => "judge",
            Role::Juror => "juror",
            Role::Peer => "peer",
            Role::Mailbox => "mailbox",
            Role::Agent => "agent",
            Role::Gateway => "gateway",
        }
    }

    /// Parses a keripy role token into a typed [`Role`].
    ///
    /// Total at the boundary: an unrecognized token is an [`OobiError::Role`],
    /// never a silently-accepted string.
    pub fn parse(s: &str) -> Result<Self, OobiError> {
        Ok(match s {
            "controller" => Role::Controller,
            "witness" => Role::Witness,
            "watcher" => Role::Watcher,
            "registrar" => Role::Registrar,
            "judge" => Role::Judge,
            "juror" => Role::Juror,
            "peer" => Role::Peer,
            "mailbox" => Role::Mailbox,
            "agent" => Role::Agent,
            "gateway" => Role::Gateway,
            other => return Err(OobiError::Role(other.to_string())),
        })
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed Out-Of-Band Introduction URL.
///
/// The canonical keripy OOBI form is
/// `<scheme>://<authority>/oobi/<cid>/<role>[/<eid>]` (keripy's `OOBI_RE`). A
/// parsed `Oobi` guarantees: a recognized scheme, a present authority, a
/// CESR-valid controller prefix (`cid`), a known [`Role`], and — when present —
/// a CESR-valid endpoint prefix (`eid`). Invalid URLs never become an `Oobi`;
/// they are rejected by [`Oobi::parse`] at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oobi {
    /// URL scheme — `http`, `https`, or `tcp` (keripy `kering.Schemes`).
    pub scheme: String,
    /// Network authority (`host[:port]`) hosting the introduction endpoint.
    pub authority: String,
    /// Controller AID being introduced (the `cid` path segment).
    pub cid: Prefix,
    /// Authorized role of the endpoint for that controller.
    pub role: Role,
    /// Optional endpoint provider AID (`eid`) when the OOBI scopes one endpoint.
    pub eid: Option<Prefix>,
}

impl Oobi {
    /// Parses a peer's OOBI URL into a typed [`Oobi`].
    ///
    /// Accepts the keripy `OOBI_RE` shape
    /// `<scheme>://<authority>/oobi/<cid>/<role>[/<eid>]`. Every component is
    /// validated at the boundary: the scheme must be one keripy speaks, the
    /// `cid`/`eid` must be CESR-valid prefixes, and the role must be a known
    /// [`Role`].
    pub fn parse(url: &str) -> Result<Self, OobiError> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| OobiError::Url(format!("missing scheme separator in {url:?}")))?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "tcp") {
            return Err(OobiError::Scheme(scheme));
        }

        // Split authority from the path; an absent path is not a valid OOBI.
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, path),
            None => return Err(OobiError::Url(format!("missing /oobi path in {url:?}"))),
        };
        if authority.is_empty() {
            return Err(OobiError::Url(format!("empty authority in {url:?}")));
        }

        // Drop any query string / fragment (keripy treats them as alias hints
        // only) and split the path into its segments.
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let mut segs = path.split('/').filter(|s| !s.is_empty());
        match segs.next() {
            Some("oobi") => {}
            _ => return Err(OobiError::Url(format!("path is not /oobi/... in {url:?}"))),
        }

        let cid_str = segs
            .next()
            .ok_or_else(|| OobiError::Url(format!("missing cid segment in {url:?}")))?;
        let cid = Prefix::new(cid_str.to_string()).map_err(|e| OobiError::Prefix {
            segment: "cid",
            source: e,
        })?;

        let role_str = segs
            .next()
            .ok_or_else(|| OobiError::Url(format!("missing role segment in {url:?}")))?;
        let role = Role::parse(role_str)?;

        let eid = match segs.next() {
            Some(eid_str) => {
                Some(
                    Prefix::new(eid_str.to_string()).map_err(|e| OobiError::Prefix {
                        segment: "eid",
                        source: e,
                    })?,
                )
            }
            None => None,
        };

        // A trailing segment past the eid is not a keripy OOBI.
        if segs.next().is_some() {
            return Err(OobiError::Url(format!("trailing path segment in {url:?}")));
        }

        Ok(Oobi {
            scheme,
            authority: authority.to_string(),
            cid,
            role,
            eid,
        })
    }

    /// The canonical OOBI URL for this introduction.
    ///
    /// Round-trips [`Oobi::parse`]: `Oobi::parse(&o.url()) == Ok(o)`.
    pub fn url(&self) -> String {
        let base = format!(
            "{}://{}/oobi/{}/{}",
            self.scheme, self.authority, self.cid, self.role
        );
        match &self.eid {
            Some(eid) => format!("{base}/{eid}"),
            None => base,
        }
    }
}

impl std::fmt::Display for Oobi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url())
    }
}

/// A `/loc/scheme` reply — *"endpoint `eid` is reachable via `scheme` at `url`."*
///
/// Byte-exact with keripy's `Hab.makeLocScheme`: serializes as
/// `{v, t:"rpy", d, dt, r:"/loc/scheme", a:{eid, scheme, url}}`, SAID-ified over
/// the whole record and version-sized to the serialized bytes. Build via
/// [`LocSchemeReply::new`] (which saidifies), then serialize for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocSchemeReply {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// SAID of this reply (Blake3-256 over the saidified record).
    pub d: Said,
    /// ISO-8601 datetime stamp (RFC-3339 profile, microsecond precision).
    pub dt: String,
    /// Endpoint provider AID this location describes.
    pub eid: Prefix,
    /// URL scheme of the endpoint (`http`/`https`/`tcp`).
    pub scheme: String,
    /// Endpoint URL.
    pub url: String,
}

impl LocSchemeReply {
    /// Builds a saidified `/loc/scheme` reply for an endpoint location.
    pub fn new(
        eid: Prefix,
        scheme: impl Into<String>,
        url: impl Into<String>,
        dt: impl Into<String>,
    ) -> Result<Self, OobiError> {
        let mut reply = Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            d: Said::default(),
            dt: dt.into(),
            eid,
            scheme: scheme.into(),
            url: url.into(),
        };
        reply.saidify()?;
        Ok(reply)
    }

    fn saidify(&mut self) -> Result<(), OobiError> {
        let body =
            serde_json::to_value(&*self).map_err(KeriTranslationError::SerializationFailed)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        self.v = recompute_version_string(&*self)?;
        Ok(())
    }
}

impl Serialize for LocSchemeReply {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "rpy")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", "/loc/scheme")?;
        let mut a = serde_json::Map::new();
        a.insert(
            "eid".into(),
            serde_json::Value::String(self.eid.to_string()),
        );
        a.insert(
            "scheme".into(),
            serde_json::Value::String(self.scheme.clone()),
        );
        a.insert("url".into(), serde_json::Value::String(self.url.clone()));
        map.serialize_entry("a", &serde_json::Value::Object(a))?;
        map.end()
    }
}

/// An `/end/role/add` reply — *"controller `cid` authorizes `eid` in `role`."*
///
/// Byte-exact with keripy's `Hab.makeEndRole`: serializes as
/// `{v, t:"rpy", d, dt, r:"/end/role/add", a:{cid, role, eid}}`, SAID-ified and
/// version-sized exactly as `Hab.reply`. Build via [`EndRoleReply::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndRoleReply {
    /// Version string `KERI10JSON{size:06x}_`.
    pub v: String,
    /// SAID of this reply.
    pub d: Said,
    /// ISO-8601 datetime stamp.
    pub dt: String,
    /// Controller AID authorizing the endpoint.
    pub cid: Prefix,
    /// Role the endpoint is authorized for.
    pub role: Role,
    /// Endpoint provider AID being authorized.
    pub eid: Prefix,
}

impl EndRoleReply {
    /// Builds a saidified `/end/role/add` reply authorizing an endpoint.
    pub fn new(
        cid: Prefix,
        role: Role,
        eid: Prefix,
        dt: impl Into<String>,
    ) -> Result<Self, OobiError> {
        let mut reply = Self {
            v: KERI_VERSION_PLACEHOLDER.to_string(),
            d: Said::default(),
            dt: dt.into(),
            cid,
            role,
            eid,
        };
        reply.saidify()?;
        Ok(reply)
    }

    fn saidify(&mut self) -> Result<(), OobiError> {
        let body =
            serde_json::to_value(&*self).map_err(KeriTranslationError::SerializationFailed)?;
        self.d = compute_said_with_protocol(&body, Protocol::Keri)?;
        self.v = recompute_version_string(&*self)?;
        Ok(())
    }
}

impl Serialize for EndRoleReply {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "rpy")?;
        map.serialize_entry("d", &self.d)?;
        map.serialize_entry("dt", &self.dt)?;
        map.serialize_entry("r", "/end/role/add")?;
        let mut a = serde_json::Map::new();
        a.insert(
            "cid".into(),
            serde_json::Value::String(self.cid.to_string()),
        );
        a.insert(
            "role".into(),
            serde_json::Value::String(self.role.to_string()),
        );
        a.insert(
            "eid".into(),
            serde_json::Value::String(self.eid.to_string()),
        );
        map.serialize_entry("a", &serde_json::Value::Object(a))?;
        map.end()
    }
}

/// The serve side: an AID's discoverable introduction.
///
/// From a controller's KEL and the URL its endpoint is hosted at, this derives
/// what a resolving peer needs: the OOBI URL to publish, and the `rpy` reply
/// stream (`/loc/scheme` + `/end/role/add`) the peer fetches. The endpoint
/// provider (`eid`) defaults to the controller itself (`cid`) — the
/// "controller" role — exactly as keripy's self-introduction does.
#[derive(Debug, Clone)]
pub struct OobiEndpoint {
    /// The OOBI URL a peer resolves to discover this controller.
    pub oobi: Oobi,
    /// The endpoint-location reply (`/loc/scheme`).
    pub loc_scheme: LocSchemeReply,
    /// The role-authorization reply (`/end/role/add`).
    pub end_role: EndRoleReply,
}

impl OobiEndpoint {
    /// Derives a controller's self-introduction from its replayed key-state.
    ///
    /// `scheme` + `authority` describe where the controller hosts its endpoint;
    /// `url` is the absolute endpoint URL embedded in the `/loc/scheme` reply
    /// (keripy includes the full URL, not just the authority). The introduction
    /// is for the `controller` role with the controller as its own endpoint.
    pub fn for_controller(
        state: &KeyState,
        scheme: impl Into<String>,
        authority: impl Into<String>,
        url: impl Into<String>,
        dt: impl Into<String>,
    ) -> Result<Self, OobiError> {
        let scheme = scheme.into();
        let authority = authority.into();
        let dt = dt.into();
        let cid = state.prefix.clone();
        let oobi = Oobi {
            scheme: scheme.clone(),
            authority,
            cid: cid.clone(),
            role: Role::Controller,
            eid: None,
        };
        let loc_scheme = LocSchemeReply::new(cid.clone(), scheme, url, dt.clone())?;
        let end_role = EndRoleReply::new(cid.clone(), Role::Controller, cid, dt)?;
        Ok(OobiEndpoint {
            oobi,
            loc_scheme,
            end_role,
        })
    }

    /// Serializes the `rpy` reply stream a resolving peer fetches (newline-joined
    /// JSON, the keripy `replyEndRole` wire shape minus the leading KEL replay,
    /// which the caller prepends from the KEL it serves).
    pub fn reply_stream(&self) -> Result<String, OobiError> {
        let loc = serde_json::to_string(&self.loc_scheme)
            .map_err(KeriTranslationError::SerializationFailed)?;
        let end = serde_json::to_string(&self.end_role)
            .map_err(KeriTranslationError::SerializationFailed)?;
        Ok(format!("{loc}\n{end}"))
    }
}

/// The result of resolving a peer's OOBI: a verified key-state plus the endpoint
/// reply records the peer published alongside its KEL.
#[derive(Debug, Clone)]
pub struct OobiResolution {
    /// The controller AID the OOBI introduced.
    pub cid: Prefix,
    /// The replayed, verified key-state of that controller's KEL.
    pub state: KeyState,
    /// Number of KEL events ingested.
    pub event_count: usize,
}

/// Ingests the bytes fetched from an OOBI URL: replays the embedded KEL into a
/// verified [`KeyState`].
///
/// The fetched body is a KERI message stream. We extract its key events (the
/// `icp`/`rot`/`ixn`/`dip`/`drt` records the peer replayed) as a JSON array and
/// replay them — so the KEL is verified cryptographically, not trusted because
/// it arrived over a particular URL. The OOBI URL only told us *where* to look;
/// trust comes from the replay.
///
/// `expected_cid` is the controller the OOBI claimed to introduce; ingest fails
/// if the replayed KEL's prefix does not match it (an OOBI that delivers a
/// *different* AID's KEL is a discovery failure, not a silent substitution).
pub fn ingest_oobi_stream(
    expected_cid: &Prefix,
    kel_json: &str,
) -> Result<OobiResolution, OobiError> {
    let events = parse_kel_json(kel_json)?;
    if events.is_empty() {
        return Err(OobiError::EmptyKel);
    }
    let event_count = events.len();
    // A KEL fetched through an OOBI is replayed (verified) before it is trusted.
    let state = TrustedKel::from_trusted_source(&events).replay()?;
    if state.prefix != *expected_cid {
        return Err(OobiError::CidMismatch {
            expected: expected_cid.to_string(),
            actual: state.prefix.to_string(),
        });
    }
    Ok(OobiResolution {
        cid: state.prefix.clone(),
        state,
        event_count,
    })
}

/// Errors raised while parsing, serving, or resolving an OOBI.
#[derive(Debug, thiserror::Error)]
pub enum OobiError {
    /// The OOBI URL did not match the `<scheme>://<authority>/oobi/...` grammar.
    #[error("invalid OOBI URL: {0}")]
    Url(String),
    /// The URL scheme is not one KERI speaks (`http`/`https`/`tcp`).
    #[error("unsupported OOBI scheme: {0:?}")]
    Scheme(String),
    /// A path segment was not a CESR-valid prefix.
    #[error("invalid {segment} prefix in OOBI URL: {source}")]
    Prefix {
        /// Which segment failed (`cid` or `eid`).
        segment: &'static str,
        /// The underlying CESR/derivation-code error.
        source: crate::types::KeriTypeError,
    },
    /// The role segment was not a known KERI role.
    #[error("unknown OOBI role: {0:?}")]
    Role(String),
    /// The OOBI stream carried no KEL events.
    #[error("OOBI stream carried no KEL events")]
    EmptyKel,
    /// The replayed KEL belonged to a different AID than the OOBI introduced.
    #[error("OOBI introduced {expected} but delivered a KEL for {actual}")]
    CidMismatch {
        /// The AID the OOBI URL claimed.
        expected: String,
        /// The AID the delivered KEL actually replayed to.
        actual: String,
    },
    /// The fetched KEL failed to parse or replay (cryptographic verification).
    #[error("KEL replay failed: {0}")]
    Replay(#[from] ValidationError),
    /// A wire record failed to saidify/serialize.
    #[error("KERI record build failed: {0}")]
    Record(#[from] KeriTranslationError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const CID: &str = "EOoC9Auw5kgKLi0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM";
    const EID: &str = "BADQWh0eolE5bVV6-9RYizxtmdvrly_tEKMlYuom3Nz6";

    #[test]
    fn parses_controller_oobi() {
        let url = format!("http://127.0.0.1:5642/oobi/{CID}/controller");
        let oobi = Oobi::parse(&url).unwrap();
        assert_eq!(oobi.scheme, "http");
        assert_eq!(oobi.authority, "127.0.0.1:5642");
        assert_eq!(oobi.cid.as_str(), CID);
        assert_eq!(oobi.role, Role::Controller);
        assert_eq!(oobi.eid, None);
    }

    #[test]
    fn parses_witness_oobi_with_eid() {
        let url = format!("https://witness.example:5631/oobi/{CID}/witness/{EID}");
        let oobi = Oobi::parse(&url).unwrap();
        assert_eq!(oobi.scheme, "https");
        assert_eq!(oobi.role, Role::Witness);
        assert_eq!(oobi.eid.as_ref().unwrap().as_str(), EID);
    }

    #[test]
    fn url_round_trips() {
        for url in [
            format!("http://127.0.0.1:5642/oobi/{CID}/controller"),
            format!("https://w.example:5631/oobi/{CID}/witness/{EID}"),
            format!("tcp://10.0.0.1:5621/oobi/{CID}/mailbox"),
        ] {
            let oobi = Oobi::parse(&url).unwrap();
            assert_eq!(oobi.url(), url);
            assert_eq!(Oobi::parse(&oobi.url()).unwrap(), oobi);
        }
    }

    #[test]
    fn drops_query_alias_hint() {
        let url = format!("http://127.0.0.1:5642/oobi/{CID}/controller?name=alice");
        let oobi = Oobi::parse(&url).unwrap();
        assert_eq!(oobi.cid.as_str(), CID);
        assert_eq!(oobi.role, Role::Controller);
    }

    #[test]
    fn rejects_bad_scheme() {
        let err = Oobi::parse(&format!("ftp://h/oobi/{CID}/controller")).unwrap_err();
        assert!(matches!(err, OobiError::Scheme(_)));
    }

    #[test]
    fn rejects_unknown_role() {
        let err = Oobi::parse(&format!("http://h:1/oobi/{CID}/overlord")).unwrap_err();
        assert!(matches!(err, OobiError::Role(_)));
    }

    #[test]
    fn rejects_missing_path() {
        assert!(matches!(
            Oobi::parse(&format!("http://h:1/oobi/{CID}")).unwrap_err(),
            OobiError::Url(_)
        ));
        assert!(matches!(
            Oobi::parse("http://h:1").unwrap_err(),
            OobiError::Url(_)
        ));
    }

    #[test]
    fn rejects_invalid_cid_prefix() {
        let err = Oobi::parse("http://h:1/oobi/not-a-prefix/controller").unwrap_err();
        assert!(matches!(err, OobiError::Prefix { segment: "cid", .. }));
    }

    #[test]
    fn role_parse_total() {
        for r in [
            Role::Controller,
            Role::Witness,
            Role::Watcher,
            Role::Registrar,
            Role::Judge,
            Role::Juror,
            Role::Peer,
            Role::Mailbox,
            Role::Agent,
            Role::Gateway,
        ] {
            assert_eq!(Role::parse(r.as_str()).unwrap(), r);
        }
        assert!(Role::parse("nope").is_err());
    }

    // The wire records must be byte-exact with keripy 1.3.4's `Hab.reply`. These
    // SAIDs/version strings were generated from keripy itself (the oracle):
    //   serdering.SerderKERI(sad={v, t:"rpy", d:"", dt, r, a}, makify=True)
    #[test]
    fn loc_scheme_reply_byte_exact_keripy() {
        let reply = LocSchemeReply::new(
            Prefix::new(EID.to_string()).unwrap(),
            "http",
            "http://127.0.0.1:5642/",
            "2024-01-01T00:00:00.000000+00:00",
        )
        .unwrap();
        let json = serde_json::to_string(&reply).unwrap();
        let expected = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EHrMc5EKCqJHrpCAAlgG6UPaupi-tmlDw8SvspQobfC1","dt":"2024-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"eid":"BADQWh0eolE5bVV6-9RYizxtmdvrly_tEKMlYuom3Nz6","scheme":"http","url":"http://127.0.0.1:5642/"}}"#;
        assert_eq!(json, expected);
    }

    #[test]
    fn end_role_add_reply_byte_exact_keripy() {
        let reply = EndRoleReply::new(
            Prefix::new(CID.to_string()).unwrap(),
            Role::Controller,
            Prefix::new(EID.to_string()).unwrap(),
            "2024-01-01T00:00:00.000000+00:00",
        )
        .unwrap();
        let json = serde_json::to_string(&reply).unwrap();
        let expected = r#"{"v":"KERI10JSON000116_","t":"rpy","d":"EBHnCvYya3Udo4SEGo82HeOPt7WkVDEC0KWfKYnZpupF","dt":"2024-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"cid":"EOoC9Auw5kgKLi0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","role":"controller","eid":"BADQWh0eolE5bVV6-9RYizxtmdvrly_tEKMlYuom3Nz6"}}"#;
        assert_eq!(json, expected);
    }
}
