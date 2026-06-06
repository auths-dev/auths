"""Generate keripy 1.3.4 ACDC credential fixtures for auths-keri Epic F.1.

Emits deterministic ACDCs (`{v,d,i,ri,s,a}`) for BOTH curves — P-256 (default)
and Ed25519 — plus the pinned v1 capability JSON-Schema-2020-12 document with its
immutable schema SAID. These are the byte-interop oracles asserted in
`tests/cases/acdc.rs`.

Pinned revision: keripy 1.3.4 (`keri.vc.proving.credential` builds the SAD and
SAID-ifies it via `coring.Saider`; `keri.vdr` emits the `ri` registry SAID field).

Deterministic (fixed salts, fixed `dt`). NOT run in CI — provenance only;
regenerate with `python3 gen_credential.py` (needs keripy 1.3.4 installed).

Field order produced by keripy `credential()`: v, d, i, ri, s, a — where the `a`
(attributes) block is `{d, i, dt, <data...>}` with its own nested SAID `a.d` and a
subject `a.i` that is a holder AID. A top-level `e` (edges) block is also emitted
for the additive-layout fixture: adding `e` re-runs the SAID over the larger body
(it does not preserve the no-`e` top-level SAID), while `a.d` is unchanged because
`a` is unchanged.
"""

import json
import pathlib

from keri.core import coring, eventing, signing
from keri.vc import proving

HERE = pathlib.Path(__file__).parent

FIXED_DT = "2025-01-01T00:00:00.000000+00:00"

# ── Pinned v1 capability schema (JSON-Schema-2020-12) ────────────────────────
# The schema SAID is immutable: it SAID-ifies the *schema document* (label `$id`),
# distinct from event/credential SAID-ification (label `d`).
SCHEMA_DOC = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AuthsCapability",
    "description": "Auths v1 holder-bindable capability credential.",
    "type": "object",
    "properties": {
        "v": {"type": "string"},
        "d": {"type": "string"},
        "i": {"type": "string"},
        "ri": {"type": "string"},
        "s": {"type": "string"},
        "a": {
            "type": "object",
            "properties": {
                "d": {"type": "string"},
                "i": {"type": "string"},
                "dt": {"type": "string", "format": "date-time"},
                "capability": {"type": "string"},
            },
            "required": ["d", "i", "capability"],
        },
    },
    "required": ["v", "d", "i", "ri", "s", "a"],
}


def aid_for(seed_byte, code):
    """Self-addressing AID (E-prefix) whose underlying key carries curve `code`."""
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


def registry_said(tag):
    """Deterministic registry SAID stand-in (`ri`) for a fixed tag."""
    return coring.Saider(sad={"d": "", "registry": tag}, label=coring.Saids.d).qb64


def emit_credential(name, seed_iss, seed_rcp, seed_code, schema_said):
    issuer_aid, issuer_vk = aid_for(seed_iss, seed_code)
    subject_aid, subject_vk = aid_for(seed_rcp, seed_code)
    ri = registry_said(name)

    cred = proving.credential(
        schema=schema_said,
        issuer=issuer_aid,
        data={"dt": FIXED_DT, "capability": "sign"},
        recipient=subject_aid,
        status=ri,
    )

    edged = proving.credential(
        schema=schema_said,
        issuer=issuer_aid,
        data={"dt": FIXED_DT, "capability": "sign"},
        recipient=subject_aid,
        status=ri,
        source={
            "d": "",
            "parent": {
                "n": "EParentCredentialSaid00000000000000000000000",
                "s": schema_said,
            },
        },
    )

    (HERE / f"credential.{name}.json").write_bytes(cred.raw)
    (HERE / f"credential.{name}.edged.json").write_bytes(edged.raw)
    (HERE / f"credential.{name}.meta.json").write_text(
        json.dumps(
            {
                "curve_code": seed_code,
                "issuer_aid": issuer_aid,
                "issuer_verkey": issuer_vk,
                "subject_aid": subject_aid,
                "subject_verkey": subject_vk,
                "registry_said": ri,
                "schema_said": schema_said,
                "dt": FIXED_DT,
                "said": cred.said,
                "attr_said": cred.sad["a"]["d"],
                "edged_said": edged.said,
                "edged_attr_said": edged.sad["a"]["d"],
            },
            indent=2,
        )
    )
    return cred, edged


def main():
    schema_said = coring.Saider(sad=SCHEMA_DOC, label=coring.Saids.dollar).qb64
    saidified = dict(SCHEMA_DOC)
    saidified["$id"] = schema_said
    (HERE / "credential.schema.json").write_text(json.dumps(saidified, indent=2))
    (HERE / "credential.schema.meta.json").write_text(
        json.dumps({"schema_said": schema_said}, indent=2)
    )
    print("schema SAID:", schema_said)

    p256, p256_e = emit_credential(
        "p256", 0x02, 0x03, coring.MtrDex.ECDSA_256r1_Seed, schema_said
    )
    print("p256  said:", p256.said, "| edged said:", p256_e.said)

    ed, ed_e = emit_credential(
        "ed25519", 0x00, 0x01, coring.MtrDex.Ed25519_Seed, schema_said
    )
    print("ed25519 said:", ed.said, "| edged said:", ed_e.said)
    print("wrote credential fixtures to", HERE)


if __name__ == "__main__":
    main()
