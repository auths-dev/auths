"""Provenance — the frozen vectors are provably keripy's.

Re-runs gen_vectors.py's generation logic IN PROCESS (via the keripy oracle) and
asserts the freshly computed bytes equal the checked-in fixtures/ and vectors/
files, byte-for-byte. If keripy changes a derivation (or someone hand-edits a
vector, or the version pin drifts), the sha256 changes and this fails — proving
the goldens were produced by keripy 1.3.4 and nothing else.

It also validates MANIFEST.yaml: every entry's recorded sha256 matches the file
on disk, and the recorded keripy version equals the installed one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

import oracle as o

HERE = Path(__file__).resolve().parent
KERI_VERSION = __import__("keri").__version__


def _canon_bytes(obj) -> bytes:
    """Must match gen_vectors._canon_bytes exactly."""
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _expected_files() -> dict[str, bytes]:
    """The full set of {relpath: bytes} gen_vectors.py would write, from keripy."""
    icp, icp2, icp_p = o.icp_ed(), o.icp_ed2(), o.icp_p256()
    sender, recipient = icp.pre, icp2.pre
    return {
        # fixtures (inputs)
        "fixtures/kel-ed25519.json": _canon_bytes(o.kel_json(icp)),
        "fixtures/kel-p256.json": _canon_bytes(o.kel_json(icp_p)),
        "fixtures/ksn-ingest.json": _canon_bytes(o.ksn_ingest_input(icp)),
        "fixtures/acdc.json": _canon_bytes(o.ipex_acdc(sender, recipient)),
        # vectors (outputs)
        "vectors/ksn-emit.json": _canon_bytes(o.ksn_state(icp)),
        "vectors/ksn-ingest-resolved.json": _canon_bytes(o.ksn_ingest_expected(icp)),
        "vectors/did-webs-ed25519.json": _canon_bytes(
            o.did_webs(icp, o.ed_verfer(), "example.com")
        ),
        "vectors/did-webs-p256.json": _canon_bytes(
            o.did_webs(icp_p, o.p256_verfer(), "example.com")
        ),
        "vectors/oobi-loc-scheme.json": _canon_bytes(
            o.oobi_loc_scheme(icp, "http://127.0.0.1:5642/")
        ),
        "vectors/oobi-end-role.json": _canon_bytes(o.oobi_end_role(icp)),
        "vectors/ipex-grant.json": _canon_bytes(o.ipex_grant(sender, recipient)),
        "vectors/ipex-admit.json": _canon_bytes(o.ipex_admit(sender, recipient)),
    }


@pytest.mark.parametrize("rel", list(_expected_files().keys()))
def test_vector_reproduces_byte_for_byte(rel):
    """Each checked-in fixture/vector == freshly regenerated keripy bytes."""
    expected = _expected_files()[rel]
    on_disk = (HERE / rel).read_bytes()
    assert on_disk == expected, (
        f"{rel} drifted from keripy {KERI_VERSION}; re-run `python3 gen_vectors.py` "
        "and review the diff (or a keripy version pin changed)"
    )


def test_manifest_matches_disk():
    """Every MANIFEST entry's sha256 matches the file, version matches keripy."""
    manifest = yaml.safe_load((HERE / "MANIFEST.yaml").read_text())
    entries = manifest["vectors"]
    assert entries, "MANIFEST.yaml has no entries"

    for e in entries:
        path = HERE / e["path"]
        assert path.exists(), f"MANIFEST references missing file {e['path']}"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == e["sha256"], (
            f"{e['path']} sha256 mismatch: manifest {e['sha256']}, disk {digest}"
        )
        assert e["source"] == "keripy"
        assert e["version"] == KERI_VERSION, (
            f"{e['path']} recorded keripy {e['version']} but {KERI_VERSION} is installed"
        )


def test_manifest_covers_all_vector_files():
    """No fixture/vector file is missing from the MANIFEST (provenance gap)."""
    manifest = yaml.safe_load((HERE / "MANIFEST.yaml").read_text())
    recorded = {e["path"] for e in manifest["vectors"]}
    on_disk = {
        f"{d}/{p.name}"
        for d in ("fixtures", "vectors")
        for p in (HERE / d).glob("*.json")
    }
    assert on_disk == recorded, (
        f"MANIFEST out of sync with disk; missing={on_disk - recorded} "
        f"extra={recorded - on_disk}"
    )
