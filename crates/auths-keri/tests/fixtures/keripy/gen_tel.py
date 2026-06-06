"""Generate keripy 1.3.4 backerless TEL fixtures for auths-keri Epic F.2.

Emits deterministic backerless (`NB`) TEL events — `vcp` (registry inception),
`iss` (credential issuance), `rev` (credential revocation) — for BOTH curves:
P-256 (the auths default) and Ed25519. These are the byte-interop oracles asserted
in `tests/cases/tel.rs`.

Pinned revision: keripy 1.3.4 (`keri.vdr.eventing.{incept,issue,revoke}`).

Field order produced by keripy 1.3.4:
  vcp: {v, t, d, i, ii, s, c, bt, b, n}   (i == d, self-addressing registry SAID)
  iss: {v, t, d, i, s, ri, dt}            (i == credential SAID; s == "0")
  rev: {v, t, d, i, s, ri, p, dt}         (s == "1"; p == prior iss SAID)

The TEL→KEL anchor seal keripy builds is a SealEvent {i, s, d} (NOT {s, d}).

Deterministic (fixed salts, fixed nonce, fixed `dt`). NOT run in CI — provenance
only; regenerate with `python3 gen_tel.py` (needs keripy 1.3.4 installed).
"""

import json
import pathlib

from keri.core import coring, eventing, signing
from keri.vdr import eventing as veventing

HERE = pathlib.Path(__file__).parent

FIXED_DT = "2025-01-01T00:00:00.000000+00:00"
FIXED_NONCE = signing.Salter(raw=bytes([0x07]) * 16).qb64


def aid_for(seed_byte, code):
    """Self-addressing issuer AID (E-prefix) whose key carries curve `code`."""
    signer = signing.Salter(raw=bytes([seed_byte]) * 16).signers(
        count=1, transferable=True, temp=True, code=code
    )[0]
    icp = eventing.incept(
        keys=[signer.verfer.qb64],
        isith="1",
        ndigs=[coring.Diger(ser=signer.verfer.qb64b).qb64],
        code=coring.MtrDex.Blake3_256,
    )
    return icp.pre, signer.verfer.qb64


def credential_said(tag):
    """Deterministic credential SAID stand-in (`i` of iss/rev) for a fixed tag."""
    return coring.Saider(sad={"d": "", "credential": tag}, label=coring.Saids.d).qb64


def emit_tel(name, seed_iss, seed_code):
    issuer_aid, issuer_vk = aid_for(seed_iss, seed_code)

    vcp = veventing.incept(
        pre=issuer_aid,
        baks=[],
        toad=0,
        nonce=FIXED_NONCE,
        cnfg=[veventing.TraitDex.NoBackers],
    )
    regk = vcp.pre

    vcdig = credential_said(name)
    iss = veventing.issue(vcdig=vcdig, regk=regk, dt=FIXED_DT)
    rev = veventing.revoke(vcdig=vcdig, regk=regk, dig=iss.said, dt=FIXED_DT)

    anchor = veventing.SealEvent(i=regk, s=iss.sn, d=iss.said)

    (HERE / f"tel.{name}.vcp.json").write_bytes(vcp.raw)
    (HERE / f"tel.{name}.iss.json").write_bytes(iss.raw)
    (HERE / f"tel.{name}.rev.json").write_bytes(rev.raw)
    (HERE / f"tel.{name}.meta.json").write_text(
        json.dumps(
            {
                "curve_code": seed_code,
                "issuer_aid": issuer_aid,
                "issuer_verkey": issuer_vk,
                "nonce": FIXED_NONCE,
                "dt": FIXED_DT,
                "registry_said": regk,
                "credential_said": vcdig,
                "vcp_said": vcp.said,
                "iss_said": iss.said,
                "rev_said": rev.said,
                "anchor_seal": {"i": anchor.i, "s": anchor.s, "d": anchor.d},
            },
            indent=2,
        )
    )
    return vcp, iss, rev


def main():
    p256 = emit_tel("p256", 0x02, coring.MtrDex.ECDSA_256r1_Seed)
    print("p256  vcp/iss/rev:", p256[0].said, p256[1].said, p256[2].said)

    ed = emit_tel("ed25519", 0x00, coring.MtrDex.Ed25519_Seed)
    print("ed25519 vcp/iss/rev:", ed[0].said, ed[1].said, ed[2].said)
    print("wrote TEL fixtures to", HERE)


if __name__ == "__main__":
    main()
