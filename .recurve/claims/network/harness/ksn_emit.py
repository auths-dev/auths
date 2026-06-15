#!/usr/bin/env python3
"""Emit a KERI key-state notice the way the pinned keripy oracle publishes one.

Builds a `KeyStateRecord` with keripy 1.3.4 (`eventing.state(...)`) and prints it
as the canonical KERI ksn wire record on stdout. The node must be able to ingest
this — `auths key-state --ingest` consuming a record an implementation we do not
control produced is the oracle→node half of the conformance claim.

Deterministic (fixed key material) so the emitted record is stable across runs.
"""

import json
import sys

from keri.core import coring, eventing
from keri.core.coring import MtrDex


def main() -> int:
    # A deterministic, transferable Ed25519 controller verkey (fixed raw bytes).
    verkey = coring.Verfer(raw=bytes(range(32)), code=MtrDex.Ed25519).qb64

    # A self-addressing inception, then its key-state notice — exactly the shape a
    # keripy peer would publish for a thin client.
    icp = eventing.incept(keys=[verkey], code=coring.MtrDex.Blake3_256)
    ksr = eventing.state(
        pre=icp.pre,
        sn=0,
        pig="",
        dig=icp.said,
        fn=0,
        eilk="icp",
        keys=[verkey],
        eevt=eventing.StateEstEvent(s="0", d=icp.said, br=[], ba=[]),
        sith="1",
        ndigs=[],
        toad=0,
        wits=[],
        cnfg=[],
    )
    json.dump(ksr._asdict(), sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
