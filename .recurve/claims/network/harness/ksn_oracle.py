#!/usr/bin/env python3
"""Cross-verify a node-served key-state notice against the pinned keripy oracle.

Reads a KERI key-state record (the `{vn,i,s,p,d,f,dt,et,kt,k,nt,n,bt,b,c,ee,di}`
wire shape) on stdin and reconstructs the SAME key-state inside keripy 1.3.4 (the
canonical KERI reference implementation, pinned in harness/versions.lock — the
identical oracle the interop suite uses). If the node's record is a conformant
KERI ksn, keripy's `eventing.state(...)` builds its native KeyStateRecord from the
node's fields and the result round-trips field-for-field (ignoring `dt`, which is
the controller's own clock).

Exit 0 + "ORACLE-OK" when the node's notice IS what the oracle would publish for
the same key-state; non-zero with a located mismatch otherwise. This is the
node-serving half of IOP-L3c carried to the running witness: an implementation we
do not control agrees the node's KSN is a key-state notice.
"""

import json
import sys

from keri.core import eventing


def main() -> int:
    rec = json.load(sys.stdin)
    try:
        ee = rec["ee"]
        ksr = eventing.state(
            pre=rec["i"],
            sn=int(rec["s"], 16),
            pig=rec["p"],
            dig=rec["d"],
            fn=int(rec["f"], 16),
            eilk=rec["et"],
            keys=rec["k"],
            eevt=eventing.StateEstEvent(s=ee["s"], d=ee["d"], br=ee["br"], ba=ee["ba"]),
            sith=rec["kt"],
            ndigs=rec["n"],
            nsith=rec["nt"],
            toad=int(rec["bt"], 16),
            wits=rec["b"],
            cnfg=rec["c"],
            dpre=rec["di"] or None,
        )
    except Exception as exc:  # noqa: BLE001 — any failure means the oracle rejects it
        print(f"ORACLE-REJECT keripy could not build a key-state from the record: {exc}")
        return 1

    oracle = ksr._asdict()
    node = dict(rec)
    node.pop("dt", None)
    orc = dict(oracle)
    orc.pop("dt", None)

    if list(node.keys()) != list(orc.keys()):
        print(f"FIELD-MISMATCH node={list(node.keys())} oracle={list(orc.keys())}")
        return 1
    for k in node:
        if node[k] != orc[k]:
            print(f"VALUE-MISMATCH field={k} node={node[k]!r} oracle={orc[k]!r}")
            return 1
    print("ORACLE-OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
