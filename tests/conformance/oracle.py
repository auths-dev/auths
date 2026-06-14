"""keripy oracle — the canonical expected output for every conformance surface.

Every function here is a *pure keripy* computation. It never reads auths output
and never hand-copies a SAID: the expected value for each surface is produced by
calling the KERI reference implementation (keripy 1.3.4) with the SAME fixed,
deterministic inputs the auths CLI is fed. The conformance tests then assert that
`auths_cli_output == oracle_output`, which is the live byte-for-byte cross-check.

All key material is fixed (no randomness, no clock): the Ed25519 raw key is
`bytes(range(32))`, the P-256 scalar is `int(bytes(range(1, 33)))`, and every
timestamp is passed explicitly. This mirrors interop/harness/gen_vectors.py.

The keripy recipe each function uses is documented in the auths Rust sources:
  - key-state / ksn      ⇔ keri.core.eventing.state(...)._asdict()
  - did:webs             ⇔ did-webs-resolver gen_did_document (OKP/EC JWK)
  - oobi /loc /end       ⇔ keri.core.eventing.reply(route=..., data=..., stamp=...)
  - ipex grant / admit   ⇔ keri.peer.exchanging.exchange(route=..., ...)
"""

from __future__ import annotations

import base64
import json

from keri.core import coring, eventing
from keri.core.coring import MtrDex
from keri.peer import exchanging
from keri.vc import proving

# ── Fixed, deterministic key material ───────────────────────────────────────
ED_RAW = bytes(range(32))  # 0x00..0x1f — the spike's Ed25519 raw key.
# A second Ed25519 key for the IPEX recipient AID (deterministic offset).
ED2_RAW = bytes((b + 5) % 256 for b in range(32))
# The fixed registry/schema SAIDs used by the auths ipex.rs reference vector.
IPEX_REGISTRY = "EO0_SHla5Gnzc-T3jkTNAclpA1iv1L9k3lQZw5cFOe9o"
IPEX_SCHEMA = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
# Fixed timestamps. Epoch is the auths CLI default for --dt; the oobi/ipex
# surfaces stamp with microsecond precision (keripy/auths both use that form).
EPOCH_KSN = "1970-01-01T00:00:00+00:00"
EPOCH_US = "1970-01-01T00:00:00.000000+00:00"
ACDC_DT = "2024-01-01T00:00:00.000000+00:00"


def ed_verfer() -> coring.Verfer:
    """The deterministic Ed25519 verfer (controller key)."""
    return coring.Verfer(raw=ED_RAW, code=MtrDex.Ed25519)


def ed2_verfer() -> coring.Verfer:
    """The deterministic Ed25519 verfer for the IPEX recipient AID."""
    return coring.Verfer(raw=ED2_RAW, code=MtrDex.Ed25519)


def p256_verfer() -> coring.Verfer:
    """A deterministic, valid P-256 verfer (compressed SEC1 point)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    scalar = int.from_bytes(bytes(range(1, 33)), "big")
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    raw = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    return coring.Verfer(raw=raw, code=MtrDex.ECDSA_256r1)


# ── Inception / KEL fixtures (the inputs both sides consume) ─────────────────
def icp_ed() -> eventing.Serder:
    """Self-addressing Ed25519 inception (the auths AID model: i == d == SAID)."""
    return eventing.incept(keys=[ed_verfer().qb64], code=MtrDex.Blake3_256)


def icp_ed2() -> eventing.Serder:
    """Self-addressing inception for the IPEX recipient AID."""
    return eventing.incept(keys=[ed2_verfer().qb64], code=MtrDex.Blake3_256)


def icp_p256() -> eventing.Serder:
    """Self-addressing P-256 inception."""
    return eventing.incept(keys=[p256_verfer().qb64], code=MtrDex.Blake3_256)


def kel_json(icp: eventing.Serder) -> list[dict]:
    """A KEL file body: a JSON array of keripy event.raw objects (the spike form)."""
    return [json.loads(icp.raw.decode())]


# ── Surface 1: ksn emit ─────────────────────────────────────────────────────
def ksn_state(icp: eventing.Serder, *, stamp: str = EPOCH_KSN) -> dict:
    """keripy KeyStateRecord (`ksn` wire shape) for a single-icp KEL.

    Mirrors auths `key-state --from-kel`. keripy's `state(...)` defaults `dt` to
    `now()`; auths defaults `--dt` to the epoch, so we pin `stamp` to the epoch
    to keep the comparison deterministic (the only field that would otherwise
    diverge). Every other field (vn, i, s, p, d, f, et, kt, k, nt, n, bt, b, c,
    ee, di) is keripy's own output.
    """
    keys = [json.loads(icp.raw.decode())["k"][0]]
    ksr = eventing.state(
        pre=icp.pre,
        sn=0,
        pig="",
        dig=icp.said,
        fn=0,
        eilk="icp",
        keys=keys,
        eevt=eventing.StateEstEvent(s="0", d=icp.said, br=[], ba=[]),
        sith="1",
        ndigs=[],
        toad=0,
        wits=[],
        cnfg=[],
        stamp=stamp,
    )
    return ksr._asdict()


# ── Surface 2: ksn ingest ───────────────────────────────────────────────────
def ksn_ingest_input(icp: eventing.Serder) -> dict:
    """A keripy-produced ksn JSON record (the thing a peer publishes)."""
    return ksn_state(icp, stamp=EPOCH_KSN)


def ksn_ingest_expected(icp: eventing.Serder) -> dict:
    """The resolved key-state (i, k, s) a peer should recover from the ksn.

    auths `--ingest` prints a normalized internal view, not the wire ksn; the
    gate asserts the *resolved key-state* matches: prefix==i, current_keys==k,
    sequence==s. Those three are derived here straight from keripy.
    """
    rec = ksn_state(icp, stamp=EPOCH_KSN)
    return {"i": rec["i"], "k": rec["k"], "s": rec["s"]}


# ── Surface 3: did:webs ─────────────────────────────────────────────────────
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def did_webs(icp: eventing.Serder, verfer: coring.Verfer, domain: str) -> dict:
    """The did:webs DID document for an AID.

    Mirrors the did-webs-resolver `gen_did_document` / `generate_json_web_key_vm`:
    field order id, verificationMethod, service, alsoKnownAs; Ed25519 → OKP
    x-only JWK; P-256 → EC x/y JWK. The verkey qb64 is keripy's; the JWK
    coordinates are derived from the same raw public key keripy holds.
    """
    aid = icp.pre
    did = f"did:webs:{domain}:{aid}"
    vk = verfer.qb64

    if verfer.code == MtrDex.Ed25519:
        jwk = {"kty": "OKP", "kid": vk, "crv": "Ed25519", "x": _b64u(verfer.raw)}
    elif verfer.code == MtrDex.ECDSA_256r1:
        from cryptography.hazmat.primitives.asymmetric import ec

        # Decompress the SEC1 point keripy carries to recover x and y.
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), verfer.raw)
        nums = pub.public_numbers()
        jwk = {
            "kty": "EC",
            "kid": vk,
            "crv": "P-256",
            "x": _b64u(nums.x.to_bytes(32, "big")),
            "y": _b64u(nums.y.to_bytes(32, "big")),
        }
    else:
        raise ValueError(f"unsupported verkey code {verfer.code}")

    return {
        "id": did,
        "verificationMethod": [
            {
                "id": f"#{vk}",
                "type": "JsonWebKey",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "service": [],
        "alsoKnownAs": [f"did:keri:{aid}"],
    }


# ── Surface 4: oobi endpoint ────────────────────────────────────────────────
def oobi_url(icp: eventing.Serder, authority: str, scheme: str = "http") -> str:
    """The OOBI URL auths emits for the controller role (keripy OOBI_RE shape)."""
    return f"{scheme}://{authority}/oobi/{icp.pre}/controller"


def oobi_loc_scheme(icp: eventing.Serder, url: str, *, stamp: str = EPOCH_US) -> dict:
    """The `/loc/scheme` rpy reply, via keripy `eventing.reply` (SAID included)."""
    rpy = eventing.reply(
        route="/loc/scheme",
        data={"eid": icp.pre, "scheme": "http", "url": url},
        stamp=stamp,
    )
    return json.loads(rpy.raw.decode())


def oobi_end_role(icp: eventing.Serder, *, stamp: str = EPOCH_US) -> dict:
    """The `/end/role/add` rpy reply (controller authorizes itself), via keripy."""
    rpy = eventing.reply(
        route="/end/role/add",
        data={"cid": icp.pre, "role": "controller", "eid": icp.pre},
        stamp=stamp,
    )
    return json.loads(rpy.raw.decode())


# ── Surfaces 5 & 6: ipex grant / admit ──────────────────────────────────────
def ipex_acdc(sender: str, recipient: str, *, dt: str = ACDC_DT) -> dict:
    """A deterministic ACDC `{v,d,i,ri,s,a:{d,i,dt}}` matching the auths shape.

    keripy `proving.credential` saidifies the `a` block (nested `a.d`) exactly as
    auths does. Passing `data={"dt": dt}` makes `a.dt` deterministic (keripy
    otherwise stamps it with now()). Empty attributes otherwise.
    """
    acdc = proving.credential(
        schema=IPEX_SCHEMA,
        issuer=sender,
        data={"dt": dt},
        recipient=recipient,
        status=IPEX_REGISTRY,
    )
    return json.loads(acdc.raw.decode())


def _acdc_serder(sender: str, recipient: str, *, dt: str = ACDC_DT):
    return proving.credential(
        schema=IPEX_SCHEMA,
        issuer=sender,
        data={"dt": dt},
        recipient=recipient,
        status=IPEX_REGISTRY,
    )


def ipex_grant(sender: str, recipient: str, *, dt: str = ACDC_DT) -> dict:
    """keripy IPEX grant `exn` (route /ipex/grant), via `exchanging.exchange`.

    Recipe (from auths ipex.rs): exchange(route="/ipex/grant",
    payload={m:"", i:recipient}, sender=sender, embeds={acdc:<ACDC raw>}, date=dt).
    The top-level `d` SAID and the embeds section SAID `e.d` are keripy's own.
    """
    acdc = _acdc_serder(sender, recipient, dt=dt)
    exn, _ = exchanging.exchange(
        route="/ipex/grant",
        payload={"m": "", "i": recipient},
        sender=sender,
        embeds={"acdc": acdc.raw},
        date=dt,
    )
    return json.loads(exn.raw.decode())


def ipex_admit(sender: str, recipient: str, *, dt: str = ACDC_DT) -> dict:
    """keripy IPEX admit `exn` (route /ipex/admit), via `exchanging.exchange`.

    Recipe (from auths ipex.rs): exchange(route="/ipex/admit", payload={m:""},
    sender=recipient, dig=<grant SAID>, date=dt). Prior `p` = the grant SAID.
    """
    acdc = _acdc_serder(sender, recipient, dt=dt)
    grant, _ = exchanging.exchange(
        route="/ipex/grant",
        payload={"m": "", "i": recipient},
        sender=sender,
        embeds={"acdc": acdc.raw},
        date=dt,
    )
    admit, _ = exchanging.exchange(
        route="/ipex/admit",
        payload={"m": ""},
        sender=recipient,
        dig=grant.said,
        date=dt,
    )
    return json.loads(admit.raw.decode())
