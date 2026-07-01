"""keripy conformance — the live gate.

For each KERI surface, assert TWO things:
  1. live cross-check : auths CLI output == keripy oracle output (oracle.py)
  2. drift/provenance : auths CLI output == the frozen vector in vectors/

Both comparisons are CANONICAL JSON (sorted keys, normalized via `canon`). When
the comparison is byte-exact the raw stdout already matches; `canon` only
reorders keys so a JSON object-ordering difference never masks a real one. Any
field that must be *normalized away* (because the two sides legitimately differ)
is documented inline with the WHY.

The auths AID for the fixed Ed25519 key is
EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J (the spike's value).
"""

from __future__ import annotations

import json
from pathlib import Path

import oracle as o

HERE = Path(__file__).resolve().parent
VEC = HERE / "vectors"


def canon(obj) -> str:
    """Canonical JSON string: keys sorted recursively, compact separators.

    Numbers and strings keep their JSON forms; this only removes object-key
    ordering and whitespace as sources of spurious mismatch. Both the auths
    output and the keripy oracle output are real JSON, so this is a faithful
    structural-equality check that still catches any value/type difference.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def load_vector(name: str) -> dict:
    return json.loads((VEC / name).read_text())


# ── Surface 1: ksn emit ──────────────────────────────────────────────────────
def test_ksn_emit(run_auths, write_json):
    """keripy KEL → `auths key-state --from-kel` == keripy eventing.state(...).

    Byte-exact / structural: every field matches keripy's KeyStateRecord. The
    only field that would diverge is `dt` — keripy `state()` defaults it to
    now(); auths defaults --dt to the epoch. We pin BOTH to the epoch (oracle
    stamp=epoch, auths default --dt=epoch), so no field is normalized away here.
    """
    icp = o.icp_ed()
    kel = write_json("kel.json", o.kel_json(icp))

    out = run_auths(["key-state", "--from-kel", str(kel), "--json"]).json
    expected = o.ksn_state(icp)  # stamp defaults to epoch

    assert canon(out) == canon(expected)
    assert canon(out) == canon(load_vector("ksn-emit.json"))


# ── Surface 2: ksn ingest ────────────────────────────────────────────────────
def test_ksn_ingest(run_auths, write_json):
    """keripy ksn JSON → `auths key-state --ingest` resolves the same (i, k, s).

    auths `--ingest` prints a normalized internal view (prefix/current_keys/
    sequence/last_event_said), NOT the wire ksn shape, so we map those fields to
    the ksn (i, k, s) and compare. This is structural by design: the ingest
    surface is gated on the RESOLVED key-state, not on echoing the wire bytes.
    """
    icp = o.icp_ed()
    ksn = write_json("ksn.json", o.ksn_ingest_input(icp))

    out = run_auths(["key-state", "--ingest", str(ksn), "--json"]).json
    resolved = {
        "i": out["prefix"],
        "k": out["current_keys"],
        "s": str(out["sequence"]),
    }
    expected = o.ksn_ingest_expected(icp)

    assert canon(resolved) == canon(expected)
    assert canon(resolved) == canon(load_vector("ksn-ingest-resolved.json"))
    # And the resolved last-event SAID equals the ingested ksn's `d`.
    assert out["last_event_said"] == o.ksn_ingest_input(icp)["d"]


# ── Surface 3: did:webs (Ed25519) ────────────────────────────────────────────
def test_did_webs_ed25519(run_auths, write_json):
    """keripy Ed25519 KEL → `auths did-webs` == keripy gen_did_document (OKP JWK).

    Byte-exact: id, verificationMethod (OKP x-only JWK), service, alsoKnownAs all
    match. Nothing normalized away.
    """
    icp = o.icp_ed()
    kel = write_json("kel.json", o.kel_json(icp))

    out = run_auths(
        ["did-webs", "--from-kel", str(kel), "--domain", "example.com", "--json"]
    ).json
    expected = o.did_webs(icp, o.ed_verfer(), "example.com")

    assert canon(out) == canon(expected)
    assert canon(out) == canon(load_vector("did-webs-ed25519.json"))


# ── Surface 3b: did:webs (P-256) ─────────────────────────────────────────────
def test_did_webs_p256(run_auths, write_json):
    """keripy P-256 KEL → `auths did-webs` == keripy gen_did_document (EC JWK).

    Byte-exact: the EC JWK carries x and y derived from the same SEC1 compressed
    point keripy holds. Nothing normalized away.
    """
    icp = o.icp_p256()
    kel = write_json("kel-p256.json", o.kel_json(icp))

    out = run_auths(
        ["did-webs", "--from-kel", str(kel), "--domain", "example.com", "--json"]
    ).json
    expected = o.did_webs(icp, o.p256_verfer(), "example.com")

    assert canon(out) == canon(expected)
    assert canon(out) == canon(load_vector("did-webs-p256.json"))


# ── Surface 4: oobi endpoint ─────────────────────────────────────────────────
def test_oobi_endpoint(run_auths, write_json):
    """keripy KEL → `auths oobi endpoint` /loc/scheme + /end/role/add == keripy reply().

    Byte-exact including SAIDs. The auths `--json` stdout is the OOBI URL on the
    first line followed by the two `rpy` reply JSON lines; we parse all three.
    The dt is pinned to the epoch (microsecond form) on both sides.
    """
    icp = o.icp_ed()
    kel = write_json("kel.json", o.kel_json(icp))
    url = "http://127.0.0.1:5642/"

    res = run_auths(
        [
            "oobi", "endpoint",
            "--from-kel", str(kel),
            "--authority", "127.0.0.1:5642",
            "--url", url,
            "--json",
        ]
    )
    lines = res.stdout.splitlines()
    oobi_url_line = lines[0].strip()
    replies = [json.loads(line) for line in lines[1:] if line.strip()]
    loc = next(r for r in replies if r["r"] == "/loc/scheme")
    end = next(r for r in replies if r["r"] == "/end/role/add")

    assert oobi_url_line == o.oobi_url(icp, "127.0.0.1:5642")

    assert canon(loc) == canon(o.oobi_loc_scheme(icp, url))
    assert canon(loc) == canon(load_vector("oobi-loc-scheme.json"))

    assert canon(end) == canon(o.oobi_end_role(icp))
    assert canon(end) == canon(load_vector("oobi-end-role.json"))


# ── Surface 5: ipex grant ────────────────────────────────────────────────────
def test_ipex_grant(run_auths, write_json):
    """keripy ACDC → `auths ipex grant` == keripy ipexGrantExn/exchange.

    Byte-exact: the top-level `exn` SAID (`d`), the embedded ACDC (with its own
    saidified `a.d`), and the embeds-section SAID (`e.d`) all match keripy. dt is
    pinned (--dt on auths == date= on keripy).
    """
    icp, icp2 = o.icp_ed(), o.icp_ed2()
    sender, recipient = icp.pre, icp2.pre
    acdc = write_json("acdc.json", o.ipex_acdc(sender, recipient))

    out = run_auths(
        [
            "ipex", "grant",
            "--acdc", str(acdc),
            "--sender", sender,
            "--recipient", recipient,
            "--dt", o.ACDC_DT,
            "--json",
        ]
    ).json
    expected = o.ipex_grant(sender, recipient)

    assert canon(out) == canon(expected)
    assert canon(out) == canon(load_vector("ipex-grant.json"))
    # The embeds-section SAID specifically must match (the load-bearing detail).
    assert out["e"]["d"] == expected["e"]["d"]


# ── Surface 6: ipex admit ────────────────────────────────────────────────────
def test_ipex_admit(run_auths, write_json):
    """That grant → `auths ipex admit` == keripy ipexAdmitExn/exchange.

    Byte-exact: the admit `exn` SAID (`d`) and its prior (`p` = the grant SAID)
    match keripy. We first produce the grant via the CLI, then admit it.
    """
    icp, icp2 = o.icp_ed(), o.icp_ed2()
    sender, recipient = icp.pre, icp2.pre
    acdc = write_json("acdc.json", o.ipex_acdc(sender, recipient))

    grant_res = run_auths(
        [
            "ipex", "grant",
            "--acdc", str(acdc),
            "--sender", sender,
            "--recipient", recipient,
            "--dt", o.ACDC_DT,
            "--json",
        ]
    )
    grant_path = write_json("grant.json", json.loads(grant_res.stdout))

    out = run_auths(
        [
            "ipex", "admit",
            "--grant", str(grant_path),
            "--sender", recipient,
            "--dt", o.ACDC_DT,
            "--json",
        ]
    ).json
    expected = o.ipex_admit(sender, recipient)

    assert canon(out) == canon(expected)
    assert canon(out) == canon(load_vector("ipex-admit.json"))
    # The prior must thread the grant's SAID (the IPEX loop-closing detail).
    assert out["p"] == json.loads(grant_res.stdout)["d"]


# ── Surface 7: delegated inception (dip) — the Workstream A interop claim ─────
def test_dip_delegated_inception(run_auths):
    """auths `keri-emit dip` == keripy delegated inception (byte-for-byte AID).

    The interop claim for the device-delegation model: a delegate auths incepts as
    a delegated identifier must compute the SAME delegated AID (`d == i`) keripy
    would, or a keripy verifier would reject it. Delegate key = the deterministic
    ed2 key; delegator = the ed AID.
    """
    delegator = o.icp_ed().pre
    key = o.ed2_verfer().qb64

    out = run_auths(["keri-emit", "dip", "--key", key, "--delegator", delegator]).json
    expected = o.dip(delegator, key)

    assert canon(out) == canon(expected), (
        f"\n  auths : {canon(out)}\n  keripy: {canon(expected)}"
    )
    assert out["d"] == out["i"], "a delegated AID is self-addressing (d == i)"
    assert out["di"] == delegator, "di names the delegator"


# ── Surface 8: delegator-side revocation ixn ─────────────────────────────────
def test_revocation_ixn_is_keripy_parseable(run_auths):
    """auths `keri-emit ixn --seal-digest` == keripy interact with a digest seal.

    auths revokes a lost device delegator-side: a single-author root `ixn`
    anchoring the device's prefix as a digest seal. This asserts the EVENT is
    byte-identical to keripy's `interact(data=[{"d": ...}])` — i.e. a keripy
    verifier can parse/replay it. Whether keripy *interprets* that digest seal as a
    device revocation is a separate protocol-semantics question (see the interop
    findings write-up) — this surface only proves the wire event conforms.
    """
    icp = o.icp_ed()
    pre, prev = icp.pre, icp.said
    device_prefix = o.dip(pre, o.ed2_verfer().qb64)["i"]

    out = run_auths(
        [
            "keri-emit", "ixn",
            "--pre", pre,
            "--sn", "1",
            "--prev", prev,
            "--seal-digest", device_prefix,
        ]
    ).json
    expected = o.ixn_digest_seal(pre, 1, prev, device_prefix)

    assert canon(out) == canon(expected), (
        f"\n  auths : {canon(out)}\n  keripy: {canon(expected)}"
    )
    assert out["a"] == [{"d": device_prefix}], "the ixn anchors the device-prefix digest seal"


# ── Surface 7b: delegated inception WITH pre-rotation (auths's real dip shape) ─
def test_dip_with_pre_rotation(run_auths):
    """auths dip with a next-key commitment (`nt=1`, `n=[…]`) == keripy.

    auths's real delegated inception carries pre-rotation (a next-key digest), so
    this proves the *actual* shape — not just the bare form — computes the same
    delegated AID keripy would. Any valid CESR digest serves as the commitment
    (both sides embed it identically and SAID over it).
    """
    delegator = o.icp_ed().pre
    key = o.ed2_verfer().qb64
    nxt = o.icp_ed().said  # a valid CESR Blake3 digest used as the next-key commitment

    out = run_auths(
        ["keri-emit", "dip", "--key", key, "--delegator", delegator, "--next", nxt]
    ).json
    expected = o.dip(delegator, key, next_said=nxt)

    assert canon(out) == canon(expected), (
        f"\n  auths : {canon(out)}\n  keripy: {canon(expected)}"
    )
    assert out["nt"] == "1" and out["n"] == [nxt], "pre-rotation: nt=1, n=[commitment]"
